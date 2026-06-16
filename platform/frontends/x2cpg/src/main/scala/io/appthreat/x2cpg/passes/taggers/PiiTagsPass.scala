package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Literal
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.util.matching.Regex

/** Tags literals, parameters and identifiers that resemble Personally Identifiable Information
  * (PII) or other sensitive/regulated data.
  *
  * The pass works in two complementary ways to keep false positives low:
  *   - Value based matching: string literals are matched against high-precision value regexes (for
  *     example a literal that looks like an email address, a credit-card number or an SSN).
  *   - Name based matching: parameters and identifiers are matched against name keyword regexes
  *     (for example a parameter named `ssn`, `creditCard` or `passwordHash`). The runtime value of
  *     a parameter is unknown at this stage, so the declared name is the best available signal.
  *
  * Every matching node receives:
  *   - a fine grained category tag (`pii-email`, `pci-card-number`, `phi-medical-record`, ...)
  *   - the umbrella tag [[SensitiveData]] (`sensitive-data`)
  *   - one or more compliance tags ([[Gdpr]], [[Pci]], [[Hipaa]], [[Ccpa]], [[Pii]], [[Secret]]) so
  *     downstream queries can pivot directly on a benchmark.
  *
  * @see
  *   https://www.strac.io/blog/sensitive-data-classification-for-hipaa-pci-dss-gdpr-iso-27001-ccpa-and-more
  */
class PiiTagsPass(atom: Cpg) extends CpgPass(atom):

  import PiiTagsPass.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    tagLiterals(dstGraph)
    tagNamedNodes(dstGraph)

  /** Tag string literals whose textual value resembles a sensitive datum. */
  private def tagLiterals(dstGraph: DiffGraphBuilder): Unit =
    // Pre-compute the literals once; most atoms contain a large number of them.
    val candidates = atom.literal
        .filter(l => isStringLiteral(l.code))
        .map(l => (l, unquote(l.code)))
        .filter { case (_, value) =>
            value.length >= MinValueLength && value.length <= MaxValueLength
        }
        .l

    Categories.foreach { category =>
        category.valueRegex.foreach { regex =>
            candidates.foreach { case (lit, value) =>
                if regex.matches(value) && category.valuePredicate(value) then
                  storeTags(Iterator.single(lit), category, dstGraph)
            }
        }
    }

  /** Tag parameters and identifiers whose declared name hints at a sensitive datum. */
  private def tagNamedNodes(dstGraph: DiffGraphBuilder): Unit =
      Categories.foreach { category =>
          category.nameRegex.foreach { regex =>
            val params = atom.parameter.filterNot(_.name == "this").filterNot(_.name == "self")
                .filter(p => regex.matches(normalizeName(p.name)))
            storeTags(params, category, dstGraph)

            val members = atom.member.filter(m => regex.matches(normalizeName(m.name)))
            storeTags(members, category, dstGraph)

            val idents = atom.identifier.filter(i => regex.matches(normalizeName(i.name)))
            storeTags(idents, category, dstGraph)
          }
      }
  end tagNamedNodes

  private def storeTags[A <: io.shiftleft.codepropertygraph.generated.nodes.StoredNode](
    nodes: Iterator[A],
    category: PiiCategory,
    dstGraph: DiffGraphBuilder
  ): Unit =
    val matched = nodes.l
    if matched.nonEmpty then
      matched.newTagNode(category.tag).store()(using dstGraph)
      matched.newTagNode(SensitiveData).store()(using dstGraph)
      category.compliance.foreach { c =>
          matched.newTagNode(c).store()(using dstGraph)
      }

end PiiTagsPass

object PiiTagsPass:

  // Umbrella and compliance tag names
  final val SensitiveData = "sensitive-data"
  final val Pii           = "pii"
  final val Gdpr          = "gdpr"
  final val Ccpa          = "ccpa"
  final val Pci           = "pci-dss"
  final val Hipaa         = "hipaa"
  final val Secret        = "secret"

  private final val MinValueLength = 4
  private final val MaxValueLength = 512

  /** A sensitive data category.
    *
    * @param tag
    *   fine grained tag name applied to matching nodes.
    * @param compliance
    *   compliance benchmark tags associated with the category.
    * @param valueRegex
    *   optional regex used to match a literal's textual value.
    * @param nameRegex
    *   optional regex used to match a parameter / identifier / member name (already normalized to
    *   lower case with separators removed).
    * @param valuePredicate
    *   optional additional check on a value-regex match to reduce false positives (for example a
    *   Luhn check for card numbers).
    */
  final case class PiiCategory(
    tag: String,
    compliance: Seq[String],
    valueRegex: Option[Regex] = None,
    nameRegex: Option[Regex] = None,
    valuePredicate: String => Boolean = _ => true
  )

  private def ci(pattern: String): Regex = ("(?i)" + pattern).r

  /** Names are normalized before matching: lower-cased with common separators removed so that
    * `first_name`, `firstName` and `FIRST-NAME` all collapse to `firstname`.
    */
  private def normalizeName(name: String): String =
      name.toLowerCase.replaceAll("[\\s_\\-.]", "")

  private def isStringLiteral(code: String): Boolean =
    val trimmed = code.trim
    (trimmed.startsWith("\"") && trimmed.endsWith("\"")) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
    (trimmed.startsWith("\"\"\"") && trimmed.endsWith("\"\"\""))

  private def unquote(code: String): String =
    var s = code.trim
    Seq("\"\"\"", "\"", "'").foreach { q =>
        if s.length >= 2 * q.length && s.startsWith(q) && s.endsWith(q) then
          s = s.substring(q.length, s.length - q.length)
    }
    s.trim

  /** Luhn checksum validation, used to filter random digit strings out of card-number matches. */
  private def luhnValid(value: String): Boolean =
    val digits = value.filter(_.isDigit)
    if digits.length < 13 || digits.length > 19 then false
    else
      var sum = 0
      var alt = false
      var i   = digits.length - 1
      while i >= 0 do
        var d = digits(i) - '0'
        if alt then
          d *= 2
          if d > 9 then d -= 9
        sum += d
        alt = !alt
        i -= 1
      sum % 10 == 0

  /** The PII / sensitive-data dictionary.
    *
    * Value regexes are intentionally anchored and specific; name regexes use word-ish boundaries
    * (the surrounding name is normalized first) to avoid matching unrelated identifiers.
    */
  val Categories: Seq[PiiCategory] = Seq(
    // ---- Contact / direct identifiers (GDPR, CCPA, PII) ----
    PiiCategory(
      tag = "pii-email",
      compliance = Seq(Pii, Gdpr, Ccpa),
      valueRegex = Some("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}".r),
      nameRegex = Some(ci(".*(email|emailaddress|mailaddress|useremail).*"))
    ),
    PiiCategory(
      tag = "pii-phone",
      compliance = Seq(Pii, Gdpr, Ccpa),
      // E.164 and common separated forms
      valueRegex = Some(
        "\\+?[0-9][0-9\\-().\\s]{6,18}[0-9]".r
      ),
      nameRegex = Some(ci(".*(phone|mobile|telephone|faxnumber|msisdn|contactnumber).*")),
      valuePredicate = v => v.count(_.isDigit) >= 7 && v.count(_.isDigit) <= 15
    ),
    PiiCategory(
      tag = "pii-full-name",
      compliance = Seq(Pii, Gdpr, Ccpa),
      nameRegex = Some(
        ci(".*(firstname|lastname|fullname|givenname|surname|familyname|middlename|maidenname).*")
      )
    ),
    PiiCategory(
      tag = "pii-postal-address",
      compliance = Seq(Pii, Gdpr, Ccpa),
      nameRegex = Some(ci(
        ".*(streetaddress|postaladdress|homeaddress|billingaddress|shippingaddress|zipcode|postalcode|postcode).*"
      ))
    ),
    PiiCategory(
      tag = "pii-date-of-birth",
      compliance = Seq(Pii, Gdpr, Ccpa, Hipaa),
      nameRegex = Some(ci(".*(dateofbirth|dob|birthdate|birthday).*"))
    ),
    PiiCategory(
      tag = "pii-ip-address",
      compliance = Seq(Pii, Gdpr),
      valueRegex = Some(
        ("(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])" +
            "|(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}").r
      ),
      nameRegex = Some(ci(".*(ipaddress|ipaddr|clientip|remoteaddr|ipv4|ipv6).*"))
    ),
    PiiCategory(
      tag = "pii-mac-address",
      compliance = Seq(Pii, Gdpr),
      valueRegex = Some("(?:[0-9A-Fa-f]{2}[:\\-]){5}[0-9A-Fa-f]{2}".r),
      nameRegex = Some(ci(".*(macaddress|macaddr).*"))
    ),
    PiiCategory(
      tag = "pii-geo-coordinates",
      compliance = Seq(Pii, Gdpr, Ccpa),
      nameRegex = Some(ci(".*(latitude|longitude|geolocation|gpscoord|geocoord).*"))
    ),

    // ---- National / government identifiers ----
    PiiCategory(
      tag = "pii-us-ssn",
      compliance = Seq(Pii, Gdpr, Ccpa, Hipaa),
      // Excludes obviously invalid SSNs (area 000/666/9xx, group 00, serial 0000)
      valueRegex = Some("(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}".r),
      nameRegex = Some(ci(".*(ssn|socialsecurity|socialsecuritynumber).*"))
    ),
    PiiCategory(
      tag = "pii-us-itin",
      compliance = Seq(Pii, Hipaa),
      valueRegex = Some("9\\d{2}-(?:5[0-9]|6[0-5]|7[0-9]|8[0-8]|9[0-2]|9[4-9])-\\d{4}".r),
      nameRegex = Some(ci(".*(itin|individualtaxpayer).*"))
    ),
    PiiCategory(
      tag = "pii-us-ein",
      compliance = Seq(Pii),
      valueRegex = Some("\\d{2}-\\d{7}".r),
      nameRegex = Some(ci(".*(einnumber|employeridentification).*"))
    ),
    PiiCategory(
      tag = "pii-passport",
      compliance = Seq(Pii, Gdpr, Ccpa),
      nameRegex = Some(ci(".*(passport|passportnumber|passportno).*"))
    ),
    PiiCategory(
      tag = "pii-drivers-license",
      compliance = Seq(Pii, Gdpr, Ccpa),
      nameRegex =
          Some(ci(".*(driverslicense|driverlicense|drivinglicence|licensenumber|dlnumber).*"))
    ),
    PiiCategory(
      tag = "pii-national-id",
      compliance = Seq(Pii, Gdpr, Ccpa),
      nameRegex = Some(ci(
        ".*(nationalid|aadhaar|aadhar|nationalinsurance|ninumber|nhsnumber|sinnumber|taxid|pannumber|curp|rfc).*"
      ))
    ),
    PiiCategory(
      tag = "pii-india-aadhaar",
      compliance = Seq(Pii, Gdpr),
      valueRegex = Some("[2-9]\\d{3}\\s?\\d{4}\\s?\\d{4}".r),
      valuePredicate = v => v.count(_.isDigit) == 12
    ),
    PiiCategory(
      tag = "pii-vehicle-vin",
      compliance = Seq(Pii),
      valueRegex = Some("[A-HJ-NPR-Z0-9]{17}".r),
      nameRegex = Some(ci(".*(vinnumber|vehicleidentification).*"))
    ),

    // ---- Financial / payment data (PCI-DSS) ----
    PiiCategory(
      tag = "pci-card-number",
      compliance = Seq(Pii, Pci),
      // Major card networks; Luhn validated below to avoid random digit strings.
      valueRegex = Some(
        ("4[0-9]{12}(?:[0-9]{3})?" + // Visa
            "|5[1-5][0-9]{14}" +     // Mastercard
            "|2(?:2[2-9][0-9]{12}|[3-6][0-9]{13}|7[01][0-9]{12}|720[0-9]{12})" + // Mastercard 2-series
            "|3[47][0-9]{13}" +                  // Amex
            "|6(?:011|5[0-9]{2})[0-9]{12}" +     // Discover
            "|3(?:0[0-5]|[68][0-9])[0-9]{11}").r // Diners
      ),
      nameRegex = Some(ci(".*(creditcard|cardnumber|cardno|ccnumber|pan|paymentcard).*")),
      valuePredicate = v => luhnValid(v)
    ),
    PiiCategory(
      tag = "pci-card-cvv",
      compliance = Seq(Pii, Pci),
      nameRegex = Some(ci(".*(cvv|cvv2|cvc|cardverification|securitycode).*"))
    ),
    PiiCategory(
      tag = "pci-card-expiry",
      compliance = Seq(Pci),
      nameRegex = Some(ci(".*(cardexpiry|expirydate|expirationdate|expmonth|expyear).*"))
    ),
    PiiCategory(
      tag = "finance-iban",
      compliance = Seq(Pii, Gdpr, Pci),
      valueRegex = Some("[A-Z]{2}\\d{2}[A-Z0-9]{11,30}".r),
      nameRegex = Some(ci(".*(iban|ibannumber).*"))
    ),
    PiiCategory(
      tag = "finance-bank-account",
      compliance = Seq(Pii, Pci),
      nameRegex = Some(ci(
        ".*(bankaccount|accountnumber|accountno|routingnumber|sortcode|swiftcode|bic|achnumber).*"
      ))
    ),
    PiiCategory(
      tag = "finance-crypto-wallet",
      compliance = Seq(Pii),
      valueRegex = Some(
        ("(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}" + // Bitcoin
            "|0x[a-fA-F0-9]{40}").r               // Ethereum
      ),
      nameRegex = Some(ci(".*(walletaddress|cryptoaddress|bitcoinaddress|ethaddress).*"))
    ),

    // ---- Protected Health Information (HIPAA) ----
    PiiCategory(
      tag = "phi-medical",
      compliance = Seq(Pii, Hipaa, Gdpr),
      nameRegex = Some(ci(
        ".*(medicalrecord|mrnnumber|healthrecord|patientid|patientname|diagnosis|icdcode|prescription|insuranceid|healthplan|npinumber|bloodtype|medication).*"
      ))
    ),

    // ---- Authentication secrets / credentials ----
    PiiCategory(
      tag = "secret-credential",
      compliance = Seq(Pii, Secret, Gdpr),
      nameRegex = Some(ci(
        ".*(password|passwd|pwd|passphrase|secretkey|privatekey|apikey|accesstoken|refreshtoken|authtoken|clientsecret|sessiontoken|bearertoken).*"
      ))
    ),
    PiiCategory(
      tag = "secret-jwt",
      compliance = Seq(Secret),
      valueRegex = Some("eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+".r)
    ),
    PiiCategory(
      tag = "secret-aws-access-key",
      compliance = Seq(Secret),
      valueRegex = Some("(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}".r)
    ),
    PiiCategory(
      tag = "secret-private-key-block",
      compliance = Seq(Secret),
      valueRegex = Some("-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\\s\\S]*".r)
    ),
    PiiCategory(
      tag = "secret-google-api-key",
      compliance = Seq(Secret),
      valueRegex = Some("AIza[0-9A-Za-z_\\-]{35}".r)
    ),
    PiiCategory(
      tag = "secret-slack-token",
      compliance = Seq(Secret),
      valueRegex = Some("xox[baprs]-[0-9A-Za-z\\-]{10,72}".r)
    ),
    PiiCategory(
      tag = "secret-github-token",
      compliance = Seq(Secret),
      valueRegex = Some("gh[pousr]_[0-9A-Za-z]{36,255}".r)
    ),

    // ---- Biometric / device identifiers ----
    PiiCategory(
      tag = "pii-biometric",
      compliance = Seq(Pii, Gdpr, Ccpa),
      nameRegex = Some(ci(".*(fingerprint|faceid|retinascan|irisscan|biometric|voiceprint).*"))
    ),
    PiiCategory(
      tag = "pii-device-id",
      compliance = Seq(Pii, Gdpr),
      nameRegex = Some(ci(".*(deviceid|imei|imsi|udid|advertisingid|androidid|serialnumber).*"))
    )
  )

end PiiTagsPass
