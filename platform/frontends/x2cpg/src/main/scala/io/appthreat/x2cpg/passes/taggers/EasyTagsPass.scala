package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{Languages, Operators}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

/** Creates tags on any node
  */
class EasyTagsPass(atom: Cpg) extends CpgPass(atom):

  val language: String = atom.metaData.language.head

  override def run(dstGraph: DiffGraphBuilder): Unit =
    atom.method.internal.name(".*(valid|check).*").newTagNode("validation").store()(dstGraph)
    atom.method.internal.name("is[A-Z].*").newTagNode("validation").store()(dstGraph)
    atom.method.internal.name("is_[a-z].*").newTagNode("validation").store()(dstGraph)
    atom.method.internal.name("has_[a-z].*").newTagNode("validation").store()(dstGraph)
    atom.method.internal.name(".*(encode|escape|sanit).*").newTagNode("sanitization").store()(
      dstGraph
    )
    atom.method.internal.name(".*(login|authenti).*").newTagNode("authentication").store()(
      dstGraph
    )
    atom.method.internal.name(".*(has_perm|get_perms).*").newTagNode("authentication").store()(
      dstGraph
    )
    atom.method.internal.name(".*(authori).*").newTagNode("authorization").store()(dstGraph)
    if language == Languages.JSSRC || language == Languages.JAVASCRIPT then
      // Tag cli source
      atom.method.internal.fullName("(index|app).(js|jsx|ts|tsx)::program").newTagNode(
        "cli-source"
      ).store()(
        dstGraph
      )
      // Tag exported methods
      atom.call.where(_.methodFullName(Operators.assignment)).code(
        "(module\\.)?exports.*"
      ).argument.isCall.methodFullName.filterNot(_.startsWith("<")).foreach { m =>
          atom.method.nameExact(m).newTagNode("exported").store()(dstGraph)
      }
      // DOM-related events
      atom.method.external.name(
        "(addEventListener|fetch|createElement|createTextNode|importNode|appendChild|insertBefore)"
      ).parameter.newTagNode(
        "dom"
      ).store()(
        dstGraph
      )
      atom.method.internal.name("(GET|POST|PUT|DELETE|HEAD|OPTIONS|request)").parameter.newTagNode(
        "http"
      ).store()(
        dstGraph
      )
    else if language == Languages.PYTHON || language == Languages.PYTHONSRC then
      atom.method.internal.name("is_[a-z].*").newTagNode("validation").store()(dstGraph)
      atom.call.methodFullName(Operators.equals).code(
        """__name__ == ["']__main__["']"""
      ).controls.isCall.filterNot(_.name.startsWith("<operator")).newTagNode(
        "cli-source"
      ).store()(dstGraph)
      atom.tag.name("cli-source").call.callee(NoResolve).newTagNode(
        "cli-source"
      ).store()(dstGraph)
      atom.method.filename(".*(cli|main|command).*").parameter.newTagNode(
        "cli-source"
      ).store()(dstGraph)
    end if
    if language == Languages.NEWC || language == Languages.C
    then
      atom.method.internal.name("main").parameter.newTagNode("cli-source").store()(dstGraph)
      atom.method.internal.name("wmain").parameter.newTagNode("cli-source").store()(dstGraph)
      atom.method.internal.name(".*(ucm_|ucbuf_|event).*").parameter.newTagNode("event").store()(
        dstGraph
      )
      atom.method.internal.name(".*(ucm_|ucbuf_|event).*").parameter.newTagNode("framework-input")
          .store()(
            dstGraph
          )
      // TODO: Find a way to make these generic
      Seq("json", "glibc", "regex", "decode", "wasm", "execution", "unicode", "utf8").foreach {
          stag =>
            atom.method.external.name(s".*${stag}.*").callIn(NoResolve).argument.newTagNode(stag)
                .store()(dstGraph)
            atom.method.external.name(s".*${stag}.*").callIn(NoResolve).argument.newTagNode(
              "library-call"
            )
                .store()(dstGraph)
      }
      atom.method.external.name("(cuda|curl_|BIO_).*").parameter.newTagNode(
        "library-call"
      ).store()(
        dstGraph
      )
      atom.method.external.name("DriverEntry").parameter.newTagNode("driver-source").store()(
        dstGraph
      )
      atom.method.external.name("WdfDriverCreate").parameter.newTagNode(
        "driver-source"
      ).store()(dstGraph)
      atom.method.external.name("OnDeviceAdd").parameter.newTagNode(
        "driver-source"
      ).store()(dstGraph)
      atom.method.external.fullName(
        "(Aws|Azure|google|cloud)(::|\\.).*"
      ).parameter.newTagNode(
        "cloud"
      ).store()(dstGraph)
      atom.method.external.fullName("(CDevice|CDriver)(::|\\.).*").parameter.newTagNode(
        "device-driver"
      ).store()(dstGraph)
      atom.method.external.fullName(
        "(Windows|WEX|WDMAudio|winrt|wilEx)(::|\\.).*"
      ).parameter.newTagNode("windows").store()(dstGraph)
      atom.method.external.fullName("(RpcServer)(::|\\.).*").parameter.newTagNode(
        "rpc"
      ).store()(
        dstGraph
      )
      atom.method.external.fullName(
        "(Pistache|Http|Rest|oatpp|HttpClient|HttpRequest|WebSocketClient|HttpResponse|drogon|chrono|httplib|web)(::|\\.).*"
      ).parameter.newTagNode(
        "http"
      ).store()(
        dstGraph
      )
      atom.method.external.name("(kore_|onion_|coro_).*").parameter.newTagNode(
        "http"
      ).store()(
        dstGraph
      )
    end if
    if language == Languages.PHP
    then
      atom.call.code("\\$_(GET|POST|FILES|REQUEST|COOKIE|SESSION|ENV).*").argument.newTagNode(
        "framework-input"
      ).store()(dstGraph)
      // Wordpress plugins.
      atom.method.name("add_action").parameter.newTagNode("framework-input").store()(dstGraph)
      atom.method.name("add_filter").parameter.newTagNode("framework-input").store()(dstGraph)
      // TODO: Needs testing with more plugins
      /*
            atom.call.methodFullName(".*add_action.*").argument.isLiteral.foreach { a =>
                atom.method.nameExact(a.code).parameter.newTagNode("framework-input").store()(
                  dstGraph
                )
            }
            atom.call.methodFullName(".*add_filter.*").argument.isLiteral.foreach { a =>
                atom.method.nameExact(a.code).parameter.newTagNode("framework-input").store()(
                  dstGraph
                )
            }
       */
      atom.method.name("wp_cron").newTagNode("cron").store()(dstGraph)
      atom.method.name("wp_mail").newTagNode("mail").store()(dstGraph)
      atom.method.name("wp_signon").newTagNode("authentication").store()(dstGraph)
      atom.method.name("wp_remote_.*").newTagNode("http").store()(dstGraph)
    end if
    if language == Languages.JAVA || language == Languages.JAVASRC then
      atom.identifier.typeFullName("java.security.*").newTagNode("crypto").store()(dstGraph)
      atom.identifier.typeFullName("org.bouncycastle.*").newTagNode("crypto").store()(
        dstGraph
      )
      atom.identifier.typeFullName("org.apache.xml.security.*").newTagNode("crypto").store()(
        dstGraph
      )
      atom.identifier.typeFullName("javax.(security|crypto).*").newTagNode("crypto").store()(
        dstGraph
      )
      atom.call.methodFullName("java.security.*").newTagNode("crypto").store()(dstGraph)
      atom.call.methodFullName("org.bouncycastle.*").newTagNode("crypto").store()(dstGraph)
      atom.call.methodFullName("org.apache.xml.security.*").newTagNode("crypto").store()(
        dstGraph
      )
      atom.call.methodFullName("javax.(security|crypto).*").newTagNode("crypto").store()(
        dstGraph
      )
      atom.call.methodFullName("java.security.*doFinal.*").newTagNode(
        "crypto-generate"
      ).store()(dstGraph)
      atom.call.methodFullName("org.bouncycastle.*(doFinal|generate|build).*").newTagNode(
        "crypto-generate"
      ).store()(dstGraph)
      atom.call.methodFullName(
        "org.apache.xml.security.*(doFinal|create|decrypt|encrypt|load|martial).*"
      ).newTagNode(
        "crypto-generate"
      ).store()(dstGraph)
      atom.call.methodFullName("javax.(security|crypto).*doFinal.*").newTagNode(
        "crypto-generate"
      ).store()(
        dstGraph
      )
      atom.literal.code(
        "\"(DSA|ECDSA|GOST-3410|ECGOST-3410|MD5|SHA1|SHA224|SHA384|SHA512|ECDH|PKCS12|DES|DESEDE|IDEA|RC2|RC5|MD2|MD4|MD5|RIPEMD128|RIPEMD160|RIPEMD256|AES|Blowfish|CAST5|CAST6|DES|DESEDE|GOST-28147|IDEA|RC6|Rijndael|Serpent|Skipjack|Twofish|OpenPGPCFB|PKCS7Padding|ISO10126-2Padding|ISO7816-4Padding|TBCPadding|X9.23Padding|ZeroBytePadding|PBEWithMD5AndDES|PBEWithSHA1AndDES|PBEWithSHA1AndRC2|PBEWithMD5AndRC2|PBEWithSHA1AndIDEA|PBEWithSHA1And3-KeyTripleDES|PBEWithSHA1And2-KeyTripleDES|PBEWithSHA1And40BitRC2|PBEWithSHA1And40BitRC4|PBEWithSHA1And128BitRC2|PBEWithSHA1And128BitRC4|PBEWithSHA1AndTwofish|ChaCha20|ChaCha20-Poly1305|DESede|DiffieHellman|OAEP|PBEWithMD5AndDES|PBEWithHmacSHA256AndAES|RSASSA-PSS|X25519|X448|XDH|X.509|PKCS7|PkiPath|PKIX|AESWrap|ARCFOUR|ISO10126Padding|OAEPWithMD5AndMGF1Padding|OAEPWithSHA-512AndMGF1Padding|PKCS1Padding|PKCS5Padding|SSL3Padding|ECMQV|HmacMD5|HmacSHA1|HmacSHA224|HmacSHA256|HmacSHA384|HmacSHA512|HmacSHA3-224|HmacSHA3-256|HmacSHA3-384|HmacSHA3-512|SHA3-224|SHA3-256|SHA3-384|SHA3-512|SHA-1|SHA-224|SHA-256|SHA-384|SHA-512|CRAM-MD5|DIGEST-MD5|GSSAPI|NTLM|PBKDF2WithHmacSHA256|NativePRNG|NativePRNGBlocking|NativePRNGNonBlocking|SHA1PRNG|Windows-PRNG|NONEwithRSA|MD2withRSA|MD5withRSA|SHA1withRSA|SHA224withRSA|SHA256withRSA|SHA384withRSA|SHA512withRSA|SHA3-224withRSA|SHA3-256withRSA|SHA3-384withRSA|SHA3-512withRSA|NONEwithECDSAinP1363Format|SHA1withECDSAinP1363Format|SHA224withECDSAinP1363Format|SHA256withECDSAinP1363Format|SHA384withECDSAinP1363Format|SHA512withECDSAinP1363Format|SSLv2|SSLv3|TLSv1|DTLS|SSL_|TLS_).*"
      ).newTagNode("crypto-algorithm").store()(dstGraph)
    end if
    if language == Languages.PYTHON || language == Languages.PYTHONSRC then
      val known_crypto_libs = "(cryptography|Crypto|ecdsa|nacl).*"
      atom.identifier.typeFullName(known_crypto_libs).newTagNode(
        "crypto"
      ).store()(dstGraph)
      atom.call.methodFullName(known_crypto_libs).newTagNode(
        "crypto"
      ).store()(dstGraph)
      atom.call.methodFullName(
        s"${known_crypto_libs}(generate|encrypt|decrypt|derive|sign|public_bytes|private_bytes|exchange|new|update|export_key|import_key|from_string|from_pem|to_pem).*"
      ).newTagNode(
        "crypto-generate"
      ).store()(dstGraph)
      atom.call.name("[A-Z0-9]+").methodFullName(
        s"${known_crypto_libs}(primitives|serialization).*"
      ).argument.inCall.newTagNode(
        "crypto-algorithm"
      ).store()(dstGraph)
  end run
end EasyTagsPass
