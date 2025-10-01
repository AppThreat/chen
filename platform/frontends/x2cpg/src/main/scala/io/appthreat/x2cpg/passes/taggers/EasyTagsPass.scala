package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{Languages, Operators}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.util.matching.Regex

/** Creates tags on nodes based on common patterns and language-specific conventions */
class EasyTagsPass(atom: Cpg) extends CpgPass(atom):

  private val RE_CHARS = "[](){}*+&|?.,\\$"

  // Language-specific patterns
  private val JS_REQUEST_PATTERNS = Array(
    "(?s)(?i).*(req|ctx|context)\\.(originalUrl|path|protocol|route|secure|signedCookies|stale|subdomains|xhr|app|pipe|file|files|baseUrl|fresh|hostname|ip|url|ips|method|body|param|params|query|cookies|request).*"
  )

  private val JS_RESPONSE_PATTERNS = Array(
    "(?s)(?i).*(res|ctx|context)\\.(append|attachment|body|cookie|download|end|format|json|jsonp|links|location|redirect|render|send|sendFile|sendStatus|set|vary).*",
    "(?s)(?i).*res\\.(set|writeHead|setHeader).*",
    "(?s)(?i).*(db|dao|mongo|mongoclient).*",
    "(?s)(?i).*(\\s|\\.)(list|create|upload|delete|execute|command|invoke|submit|send)"
  )

  private val PY_REQUEST_PATTERNS = Array(".*views.py:<module>.*")
  private val PY_RESPONSE_PATTERNS = Array(
    ".*views.py:.*HttpResponse.*",
    ".*views.py:.*render.*",
    ".*views.py:.*get_object_.*"
  )

  private def language: String = atom.metaData.language.headOption.getOrElse("")

  override def run(dstGraph: DiffGraphBuilder): Unit =
    tagCommonPatterns(dstGraph)
    tagByLanguage(dstGraph)

  private def tagCommonPatterns(dstGraph: DiffGraphBuilder): Unit =
    // Validation patterns
    atom.method.internal.name(".*(valid|check).*").newTagNode("validation").store()(using dstGraph)
    atom.method.internal.name("is[A-Z].*").newTagNode("validation").store()(using dstGraph)
    atom.method.internal.name("is_[a-z].*").newTagNode("validation").store()(using dstGraph)
    atom.method.internal.name("has_[a-z].*").newTagNode("validation").store()(using dstGraph)

    // Sanitization patterns
    atom.method.internal.name(".*(encode|escape|sanit).*").newTagNode("sanitization").store()(
      using dstGraph
    )

    // Authentication/Authorization patterns
    atom.method.internal.name(".*(login|authenti).*").newTagNode("authentication").store()(using
    dstGraph)
    atom.method.internal.name(".*(has_perm|get_perms).*").newTagNode("authentication").store()(
      using dstGraph
    )
    atom.method.internal.name(".*(authori).*").newTagNode("authorization").store()(using dstGraph)

  private def tagByLanguage(dstGraph: DiffGraphBuilder): Unit =
      language match
        case lang if lang == Languages.RUBYSRC =>
            tagRubyPatterns(dstGraph)
        case lang if lang == Languages.JSSRC || lang == Languages.JAVASCRIPT =>
            tagJavaScriptPatterns(dstGraph)
        case lang if lang == Languages.PYTHON || lang == Languages.PYTHONSRC =>
            tagPythonPatterns(dstGraph)
        case lang if lang == Languages.NEWC || lang == Languages.C =>
            tagCPatterns(dstGraph)
        case lang if lang == Languages.PHP =>
            tagPhpPatterns(dstGraph)
        case lang
            if Seq(Languages.JAVA, Languages.JAVASRC, "JAR", "JIMPLE", "ANDROID", "APK", "DEX")
                .contains(lang) =>
            tagJavaPatterns(dstGraph)
        case _ => // No specific patterns for this language
  private def tagRubyPatterns(dstGraph: DiffGraphBuilder): Unit =
    val httpLibraries =
        Seq("URI", "Net::HTTP", "HTTParty", "RestClient", "Faraday", "HTTP", "Excon")

    httpLibraries.foreach { httpLib =>
      val httpClientMethod = s".*$httpLib.*(new|get|post|parse).*"
      atom.call.code(httpClientMethod).newTagNode("http-client").store()(using dstGraph)

      atom.call.code(httpClientMethod)
          .argument
          .isLiteral
          .filterNot(l => l.code.length < 4)
          .filterNot(l => l.code.startsWith("'/#"))
          .filter(l => Seq("http", "api", "/").exists(l.code.contains))
          .newTagNode("http-endpoint")
          .store()(using dstGraph)
    }

  private def tagJavaScriptPatterns(dstGraph: DiffGraphBuilder): Unit =
    // Request/Response patterns
    JS_REQUEST_PATTERNS.foreach(p =>
        atom.call.code(p).newTagNode("framework-input").store()(using dstGraph)
    )
    JS_RESPONSE_PATTERNS.foreach(p =>
        atom.call.code(p).newTagNode("framework-output").store()(using dstGraph)
    )

    // Prototype risks
    atom.method.name("create")
        .external
        .callIn(using NoResolve)
        .argumentIndex(1)
        .codeExact("Object.create(null)")
        .newTagNode("no-proto")
        .store()(using dstGraph)

    val protoAssignmentMethods = Seq(
      "Object.assign",
      "Object.defineProperty",
      "Object.defineProperties",
      "Object.setPrototypeOf",
      "Reflect.defineProperty",
      "Reflect.setPrototypeOf",
      "Reflect.set"
    )

    protoAssignmentMethods.foreach { method =>
        atom.call
            .filter(_.dynamicTypeHintFullName.contains(method))
            .newTagNode("proto-assign")
            .store()(using dstGraph)
    }

    // HTTP client calls
    val httpClientPackages = Seq(
      "got",
      "axios",
      "undici",
      "ky",
      "node-fetch",
      "cross-fetch",
      "superagent",
      "needle",
      "isomorphic-fetch",
      "unfetch",
      "wretch",
      "request",
      "cacheable-lookup",
      "cacheable-request",
      "http2-wrapper",
      "responselike"
    )

    httpClientPackages.foreach { pkg =>
      val pkgTag = s"pkg:npm/$pkg@.*"

      atom.tag.name(pkgTag)
          .method
          .callIn(using NoResolve)
          .newTagNode("http-client")
          .store()(using dstGraph)

      atom.tag.name(pkgTag)
          .method
          .callIn(using NoResolve)
          .argument
          .isIdentifier
          .typeFullName(s"$pkg.*")
          .newTagNode("http-client")
          .store()(using dstGraph)

      atom.tag.name(pkgTag)
          .method
          .callIn(using NoResolve)
          .argument
          .isLiteral
          .newTagNode("http-endpoint")
          .store()(using dstGraph)

      atom.tag.name(pkgTag)
          .method
          .callIn(using NoResolve)
          .argument
          .isIdentifier
          .typeFullNameExact("__ecma.String")
          .filter(i => i.name == i.name.toUpperCase)
          .newTagNode("http-endpoint")
          .store()(using dstGraph)
    }

    // CLI source tagging
    atom.method.internal
        .fullName("(index|app).(js|jsx|ts|tsx)::program")
        .newTagNode("cli-source")
        .store()(using dstGraph)

    // Exported methods
    atom.call
        .where(_.methodFullName(Operators.assignment))
        .code("(module\\.)?exports.*")
        .argument
        .isCall
        .methodFullName
        .filterNot(_.startsWith("<"))
        .foreach { methodName =>
            atom.method.nameExact(methodName).newTagNode("exported").store()(using dstGraph)
        }

    // DOM-related events
    atom.method.external
        .name(
          "(addEventListener|fetch|createElement|createTextNode|importNode|appendChild|insertBefore)"
        )
        .parameter
        .newTagNode("dom")
        .store()(using dstGraph)

    atom.method.internal
        .name("(GET|POST|PUT|DELETE|HEAD|OPTIONS|request)")
        .parameter
        .newTagNode("http")
        .store()(using dstGraph)
  end tagJavaScriptPatterns

  private def tagPythonPatterns(dstGraph: DiffGraphBuilder): Unit =
    // Request/Response patterns
    PY_REQUEST_PATTERNS.foreach(p =>
        atom.method.fullName(p).parameter.newTagNode("framework-input").store()(using dstGraph)
    )

    PY_RESPONSE_PATTERNS.foreach { p =>
      atom.method.fullName(p).parameter.newTagNode("framework-output").store()(using dstGraph)
      atom.call.code(p).newTagNode("framework-output").store()(using dstGraph)
    }

    atom.call
        .where(_.file.name(".*views.py.*"))
        .code(".*(HttpResponse|render|get_object_).*")
        .newTagNode("framework-output")
        .store()(using dstGraph)

    atom.method.internal.name("is_[a-z].*").newTagNode("validation").store()(using dstGraph)

    // CLI source patterns
    atom.call
        .methodFullName(Operators.equals)
        .code("""__name__ == ["']__main__["']""")
        .controls
        .isCall
        .filterNot(_.name.startsWith("<operator"))
        .newTagNode("cli-source")
        .store()(using dstGraph)

    atom.tag.name("cli-source")
        .call
        .callee(using NoResolve)
        .newTagNode("cli-source")
        .store()(using dstGraph)

    atom.method.filename(".*(cli|main|command).*")
        .parameter
        .newTagNode("cli-source")
        .store()(using dstGraph)

    // Crypto patterns
    val cryptoLibs = "(cryptography|Crypto|ecdsa|nacl).*"

    atom.identifier.typeFullName(cryptoLibs).newTagNode("crypto").store()(using dstGraph)
    atom.call.methodFullName(cryptoLibs).newTagNode("crypto").store()(using dstGraph)

    atom.call.methodFullName(
      s"$cryptoLibs(generate|encrypt|decrypt|derive|sign|public_bytes|private_bytes|exchange|new|update|export_key|import_key|from_string|from_pem|to_pem).*"
    ).newTagNode("crypto-generate").store()(using dstGraph)

    atom.call.name("[A-Z0-9]+")
        .methodFullName(s"$cryptoLibs(primitives|serialization).*")
        .argument
        .inCall
        .newTagNode("crypto-algorithm")
        .store()(using dstGraph)
  end tagPythonPatterns

  private def tagCPatterns(dstGraph: DiffGraphBuilder): Unit =
    // CLI source patterns
    atom.method.internal.name("main").parameter.newTagNode("cli-source").store()(using dstGraph)
    atom.method.internal.name("wmain").parameter.newTagNode("cli-source").store()(using dstGraph)

    // Event patterns
    atom.method.internal.name(".*(ucm_|ucbuf_|event).*").parameter.newTagNode("event").store()(
      using dstGraph
    )
    atom.method.internal.name(".*(ucm_|ucbuf_|event).*").parameter.newTagNode("framework-input")
        .store()(using dstGraph)

    val eventVerbs   = Seq("call", "handle", "emit", "invoke", "store")
    val eventPattern = raw".*(?:${eventVerbs.mkString("|")})[_A-Z].*"

    atom.method.internal.name(eventPattern).parameter.newTagNode("event").store()(using dstGraph)
    atom.method.internal.name(eventPattern).callIn(using NoResolve).argument.newTagNode("event")
        .store()(
          using dstGraph
        )

    // Validation patterns
    val validationVerbs   = Seq("validate", "check", "verify")
    val validationPattern = raw".*(?:${validationVerbs.mkString("|")})[_A-Z].*"

    atom.method.internal.name(validationPattern).parameter.newTagNode("validation").store()(
      using dstGraph
    )
    atom.method.internal.name(validationPattern).callIn(using NoResolve).argument.newTagNode(
      "validation"
    )
        .store()(using dstGraph)

    atom.method.internal.name(".*(parse[_A-Z]).*").parameter.newTagNode("parse").store()(using
    dstGraph)

    // Library calls
    val libraryTags =
        Seq("json", "glibc", "regex", "decode", "wasm", "execution", "unicode", "utf8")
    libraryTags.foreach { tag =>
      atom.method.external.name(s".*$tag.*").callIn(using NoResolve).argument.newTagNode(tag).store()(
        using dstGraph
      )
      atom.method.external.name(s".*$tag.*").callIn(using NoResolve).argument.newTagNode(
        "library-call"
      )
          .store()(using dstGraph)
    }

    atom.method.external.name("(cuda|curl_|BIO_).*").parameter.newTagNode("library-call").store()(
      using dstGraph
    )

    // Driver patterns
    atom.method.external.name("DriverEntry").parameter.newTagNode("driver-source").store()(using
    dstGraph)
    atom.method.external.name("WdfDriverCreate").parameter.newTagNode("driver-source").store()(
      using dstGraph
    )
    atom.method.external.name("OnDeviceAdd").parameter.newTagNode("driver-source").store()(using
    dstGraph)

    // Cloud and system patterns
    atom.method.external.fullName("(Aws|Azure|google|cloud)(::|\\.).*").parameter.newTagNode(
      "cloud"
    ).store()(using dstGraph)
    atom.method.external.fullName("(CDevice|CDriver)(::|\\.).*").parameter.newTagNode(
      "device-driver"
    ).store()(using dstGraph)
    atom.method.external.fullName("(Windows|WEX|WDMAudio|winrt|wilEx)(::|\\.).*").parameter
        .newTagNode("windows").store()(using dstGraph)
    atom.method.external.fullName("(RpcServer)(::|\\.).*").parameter.newTagNode("rpc").store()(
      using dstGraph
    )
    atom.method.external.fullName(
      "(Pistache|Http|Rest|oatpp|HttpClient|HttpRequest|WebSocketClient|HttpResponse|drogon|chrono|httplib|web)(::|\\.).*"
    ).parameter.newTagNode("http").store()(using dstGraph)
    atom.method.external.name("(kore_|onion_|coro_).*").parameter.newTagNode("http").store()(
      using dstGraph
    )
  end tagCPatterns

  private def tagPhpPatterns(dstGraph: DiffGraphBuilder): Unit =
    // Request/Response patterns
    atom.parameter.name("request.*").newTagNode("framework-input").store()(using dstGraph)
    atom.parameter.name("response.*").newTagNode("framework-output").store()(using dstGraph)

    atom.ret
        .where(_.method.parameter.name("request.*"))
        .newTagNode("framework-output")
        .store()(using dstGraph)

    atom.call.code("\\$_(GET|POST|FILES|REQUEST|COOKIE|SESSION|ENV).*")
        .argument
        .newTagNode("framework-input")
        .store()(using dstGraph)

    // WordPress patterns
    atom.method.name("add_action").parameter.newTagNode("framework-input").store()(using dstGraph)
    atom.method.name("add_filter").parameter.newTagNode("framework-input").store()(using dstGraph)

    // Other PHP patterns
    atom.method.name("wp_cron").newTagNode("cron").store()(using dstGraph)
    atom.method.name("wp_mail").newTagNode("mail").store()(using dstGraph)
    atom.method.name("wp_signon").newTagNode("authentication").store()(using dstGraph)
    atom.method.name("wp_remote_.*").newTagNode("http").store()(using dstGraph)
  end tagPhpPatterns

  private def tagJdkStandardClasses(dstGraph: DiffGraphBuilder): Unit =
    // File I/O operations
    val fileIoPatterns = Seq(
      "java.io.*",
      "java.nio.*",
      "java.nio.file.*",
      "java.nio.channels.*"
    )
    fileIoPatterns.foreach { pattern =>
      atom.call.methodFullName(s"$pattern.*").newTagNode("io").store()(using dstGraph)
      atom.identifier.typeFullName(s"$pattern.*").newTagNode("io").store()(using dstGraph)
      atom.method.parameter.typeFullName(s"$pattern.*").newTagNode("io").store()(using dstGraph)
    }
    // Network operations
    val networkPatterns = Seq(
      "java.net.*",
      "java.net.http.*",
      "javax.net.*"
    )
    networkPatterns.foreach { pattern =>
      atom.call.methodFullName(s"$pattern.*").newTagNode("network").store()(using dstGraph)
      atom.identifier.typeFullName(s"$pattern.*").newTagNode("network").store()(using dstGraph)
      atom.method.parameter.typeFullName(s"$pattern.*").newTagNode("network").store()(using
      dstGraph)
    }
    // SQL operations
    val sqlPatterns = Seq(
      "java.sql.*",
      "javax.sql.*"
    )
    sqlPatterns.foreach { pattern =>
      atom.call.methodFullName(s"$pattern.*").newTagNode("sql").store()(using dstGraph)
      atom.identifier.typeFullName(s"$pattern.*").newTagNode("sql").store()(using dstGraph)
      atom.method.parameter.typeFullName(s"$pattern.*").newTagNode("sql").store()(using dstGraph)
    }
    // XML operations
    val xmlPatterns = Seq(
      "javax.xml.*",
      "org.w3c.dom.*",
      "org.xml.sax.*"
    )
    xmlPatterns.foreach { pattern =>
      atom.call.methodFullName(s"$pattern.*").newTagNode("xml").store()(using dstGraph)
      atom.identifier.typeFullName(s"$pattern.*").newTagNode("xml").store()(using dstGraph)
      atom.method.parameter.typeFullName(s"$pattern.*").newTagNode("xml").store()(using dstGraph)
    }
    // Concurrency operations
    val concurrentPatterns = Seq(
      "java.util.concurrent.*",
      "java.util.concurrent.atomic.*",
      "java.util.concurrent.locks.*"
    )
    concurrentPatterns.foreach { pattern =>
      atom.call.methodFullName(s"$pattern.*").newTagNode("concurrent").store()(using dstGraph)
      atom.identifier.typeFullName(s"$pattern.*").newTagNode("concurrent").store()(using dstGraph)
      atom.method.parameter.typeFullName(s"$pattern.*").newTagNode("concurrent").store()(using
      dstGraph)
    }
    // Process operations
    val processPatterns = Seq(
      "java.lang.Process.*",
      "java.lang.ProcessBuilder.*"
    )
    processPatterns.foreach { pattern =>
      atom.call.methodFullName(s"$pattern.*").newTagNode("process").store()(using dstGraph)
      atom.identifier.typeFullName(s"$pattern.*").newTagNode("process").store()(using dstGraph)
      atom.method.parameter.typeFullName(s"$pattern.*").newTagNode("process").store()(using
      dstGraph)
    }
    // Reflection operations
    val reflectionPatterns = Seq(
      "java.lang.reflect.*",
      "java.lang.Class.*"
    )
    reflectionPatterns.foreach { pattern =>
      atom.call.methodFullName(s"$pattern.*").newTagNode("reflection").store()(using dstGraph)
      atom.identifier.typeFullName(s"$pattern.*").newTagNode("reflection").store()(using dstGraph)
      atom.method.parameter.typeFullName(s"$pattern.*").newTagNode("reflection").store()(using
      dstGraph)
    }
    // System operations
    val systemPatterns = Seq(
      "java.lang.System.*",
      "java.lang.Runtime.*"
    )
    systemPatterns.foreach { pattern =>
      atom.call.methodFullName(s"$pattern.*").newTagNode("system").store()(using dstGraph)
      atom.identifier.typeFullName(s"$pattern.*").newTagNode("system").store()(using dstGraph)
      atom.method.parameter.typeFullName(s"$pattern.*").newTagNode("system").store()(using dstGraph)
    }
  end tagJdkStandardClasses

  private def tagJavaPatterns(dstGraph: DiffGraphBuilder): Unit =
    tagJdkStandardClasses(dstGraph)
    val cryptoPatterns = Seq(
      "java.security.*",
      "org.bouncycastle.*",
      "org.apache.xml.security.*",
      "javax.(security|crypto).*"
    )

    // Crypto tagging
    cryptoPatterns.foreach { pattern =>
      atom.identifier.typeFullName(pattern).newTagNode("crypto").store()(using dstGraph)
      atom.call.methodFullName(pattern).newTagNode("crypto").store()(using dstGraph)
    }

    // Crypto generate patterns
    val cryptoGeneratePatterns = Seq(
      "java.security.*doFinal.*",
      "org.bouncycastle.*(doFinal|generate|build).*",
      "org.apache.xml.security.*(doFinal|create|decrypt|encrypt|load|martial).*",
      "javax.(security|crypto).*doFinal.*"
    )

    cryptoGeneratePatterns.foreach { pattern =>
        atom.call.methodFullName(pattern).newTagNode("crypto-generate").store()(using dstGraph)
    }

    // Crypto algorithms
    atom.literal.code(
      "\"(DSA|ECDSA|GOST-3410|ECGOST-3410|MD5|SHA1|SHA224|SHA384|SHA512|ECDH|PKCS12|DES|DESEDE|IDEA|RC2|RC5|MD2|MD4|MD5|RIPEMD128|RIPEMD160|RIPEMD256|AES|Blowfish|CAST5|CAST6|DES|DESEDE|GOST-28147|IDEA|RC6|Rijndael|Serpent|Skipjack|Twofish|OpenPGPCFB|PKCS7Padding|ISO10126-2Padding|ISO7816-4Padding|TBCPadding|X9.23Padding|ZeroBytePadding|PBEWithMD5AndDES|PBEWithSHA1AndDES|PBEWithSHA1AndRC2|PBEWithMD5AndRC2|PBEWithSHA1AndIDEA|PBEWithSHA1And3-KeyTripleDES|PBEWithSHA1And2-KeyTripleDES|PBEWithSHA1And40BitRC2|PBEWithSHA1And40BitRC4|PBEWithSHA1And128BitRC2|PBEWithSHA1And128BitRC4|PBEWithSHA1AndTwofish|ChaCha20|ChaCha20-Poly1305|DESede|DiffieHellman|OAEP|PBEWithMD5AndDES|PBEWithHmacSHA256AndAES|RSASSA-PSS|X25519|X448|XDH|X.509|PKCS7|PkiPath|PKIX|AESWrap|ARCFOUR|ISO10126Padding|OAEPWithMD5AndMGF1Padding|OAEPWithSHA-512AndMGF1Padding|PKCS1Padding|PKCS5Padding|SSL3Padding|ECMQV|HmacMD5|HmacSHA1|HmacSHA224|HmacSHA256|HmacSHA384|HmacSHA512|HmacSHA3-224|HmacSHA3-256|HmacSHA3-384|HmacSHA3-512|SHA3-224|SHA3-256|SHA3-384|SHA3-512|SHA-1|SHA-224|SHA-256|SHA-384|SHA-512|CRAM-MD5|DIGEST-MD5|GSSAPI|NTLM|PBKDF2WithHmacSHA256|NativePRNG|NativePRNGBlocking|NativePRNGNonBlocking|SHA1PRNG|Windows-PRNG|NONEwithRSA|MD2withRSA|MD5withRSA|SHA1withRSA|SHA224withRSA|SHA256withRSA|SHA384withRSA|SHA512withRSA|SHA3-224withRSA|SHA3-256withRSA|SHA3-384withRSA|SHA3-512withRSA|NONEwithECDSAinP1363Format|SHA1withECDSAinP1363Format|SHA224withECDSAinP1363Format|SHA256withECDSAinP1363Format|SHA384withECDSAinP1363Format|SHA512withECDSAinP1363Format|SSLv2|SSLv3|TLSv1|DTLS|SSL_|TLS_).*"
    ).newTagNode("crypto-algorithm").store()(using dstGraph)
  end tagJavaPatterns

  private def containsRegex(str: String): Boolean =
      str.exists(RE_CHARS.contains)
end EasyTagsPass
