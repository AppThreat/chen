package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{Languages, Operators}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.{Call, StoredNode}
import scala.util.matching.Regex

/** Creates tags on nodes based on common patterns and language-specific conventions */
class EasyTagsPass(atom: Cpg) extends CpgPass(atom):

  private val RE_CHARS = "[](){}*+&|?.,\\$"

  /** A precompiled regex plus the literal substrings every match must contain (P.2 prefilter, the
    * template ChennaiTagsPass established for the juice-shop hot spot). The per-call loop below
    * tests ~20 of these against every CALL node - 1.3M on the django wheel - and the regex engine
    * is only entered when at least one literal of every group occurs in the string. A group is an
    * OR over its literals; multiple groups are ANDed. A prefilter that is subtly narrower than its
    * regex is a silent detection loss, so every wrapped pattern keeps its literals inside this file
    * next to the pattern and EasyTagsPassTests proves, for each regex's representative matches,
    * that the literals do not reject them.
    */
  private class PrefilteredRegex(pattern: String, requiredLiterals: Seq[String]*):
    private val re = pattern.r
    def matches(s: String): Boolean =
        requiredLiterals.forall(group => group.exists(s.contains)) && re.matches(s)

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

  // NB(py-upgrade P1.4): the filename-keyed PY_REQUEST_PATTERNS heuristic
  // (".*(views|engine|api|base|http).py:<module>.*") was removed once the Task-4 framework
  // recognizers landed (see passes/taggers/python/): they tag handler parameters and request
  // accesses structurally (decorators, inheritance, parameter names/types), which covers Django
  // views and Flask apps regardless of the file they live in. The request-ACCESS expression
  // tagging below (step 3b) remains: it is framework-agnostic and keyed on the expression.

  // NB: get_object_* helpers are ORM reads, not response outputs - they are handled as `db-read`
  // (G1), not framework-output, so they are intentionally absent here.
  private val PY_RESPONSE_PATTERNS = Array(
    ".*\\.(views|engine|api|base|http)\\..*(HttpResponse|render|Response|jsonify|make_response|render_template|abort).*",
    ".*(HttpResponse|render|Response|jsonify|make_response|render_template|abort).*"
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
        case _ =>

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
    val pyResponseRegexes = PY_RESPONSE_PATTERNS.map(_.r)
    val pyResponseCallRegex =
        ".*(HttpResponse|render|Response|abort|jsonify|make_response|render_template).*".r
    val pyResponseFileRegex = ".*(views|engine|core|api|base|http).py.*".r
    val validationRegex     = "^is_[a-z].*$".r
    val cliFilenameRegex    = ".*(cli|main|command).*".r

    // Identifiers and calls are both per-node loops over the whole graph; every PrefilteredRegex
    // below declares the literals its pattern cannot match without, so the regex engine is
    // skipped for the vast majority of nodes.
    val aiohttpRegex = PrefilteredRegex(".*aiohttp.*", Seq("aiohttp"))
    val socketRegex = PrefilteredRegex(
      ".*socket\\.(socket|connect|send|recv|sendto|recvfrom|wrap_socket|getprotobyname).*",
      Seq("socket.")
    )
    val sslRegex = PrefilteredRegex(
      ".*ssl\\.(wrap_socket|SSLContext|create_default_context|get_server_certificate).*",
      Seq("ssl.")
    )
    val netProtocolRegex = PrefilteredRegex(
      ".*(ftplib\\.FTP|poplib\\.POP3|impacket\\.smbconnection|telnetlib\\.Telnet).*",
      Seq("ftplib.", "poplib.", "impacket.", "telnetlib.")
    )
    val shutilRegex =
        PrefilteredRegex(".*(shutil\\.copy|Path\\.open).*", Seq("shutil.", "Path."))
    // Safe (round-trippable) (de)serialisation: json/yaml-safe/csv. Kept distinct from the unsafe
    // loaders below so an `appsec`-style profile can treat only the dangerous ones as sinks.
    val serializationRegex = PrefilteredRegex(
      ".*(json\\.(loads|dumps)|yaml\\.(safe_load|dump)|csv\\.DictWriter).*",
      Seq("json.", "yaml.", "csv.")
    )
    // Unsafe deserialisation: loaders that can instantiate arbitrary objects / execute code when fed
    // attacker-controlled bytes. base64/json are intentionally excluded (encoding, not deser).
    val deserializationRegex = PrefilteredRegex(
      ".*(pickle\\.(load|loads)|cPickle\\.(load|loads)|_pickle\\.(load|loads)|yaml\\.(unsafe_load|full_load)|yaml\\.load|marshal\\.(load|loads)|jsonpickle\\.decode|dill\\.(load|loads)|shelve\\.open).*",
      Seq("pickle.", "cPickle.", "_pickle.", "yaml.", "marshal.", "jsonpickle.", "dill.", "shelve.")
    )
    // Django/SQLAlchemy ORM read accessors. Their return value is data already persisted in the
    // datastore, a different trust level from live request input; tagged `db-read` so profiles can
    // treat the accessor as a declassification barrier and prune object-identity over-tainting.
    // Matched by call name (helpers) or accessor-name + an `objects`/`query` manager in the
    // methodFullName, since the frontend lowers the receiver chain to a temporary.
    val dbReadHelperNames =
        Set("get_object_or_404", "get_list_or_404", "get_object", "get_queryset")
    val ormAccessorNames =
        Set("get", "filter", "first", "last", "all", "get_or_create", "earliest", "latest")
    // G6+: well-known Django/DRF/stdlib neutralisers. A flow passing through one of these is
    // considered sanitised for the relevant category (open-redirect guards, HTML/JS escapers,
    // tag strippers). Tagged `sanitization` so the appsec profile drops the flow.
    val sanitizerCallNames =
        Set(
          "url_has_allowed_host_and_scheme",
          "is_safe_url",
          "escape",
          "conditional_escape",
          "escapejs",
          "strip_tags",
          "format_html",
          "urlize"
        )
    val regexLibRegex  = PrefilteredRegex(".*re\\.(compile|findall|search|match).*", Seq("re."))
    val importlibRegex = PrefilteredRegex(".*importlib\\.import_module.*", Seq("importlib."))
    val sqlRegex = PrefilteredRegex(
      ".*(sqlalchemy|apsw|cursor|conn|session|sqlite3)\\.(execute|executemany|executescript|raw|extra|query|add|commit|create_engine|sessionmaker).*",
      Seq("sqlalchemy", "apsw", "cursor", "conn", "session", "sqlite3")
    )
    val sqlIdentifierRegex = PrefilteredRegex(
      ".*(sqlalchemy|apsw|sqlite3).*",
      Seq("sqlalchemy", "apsw", "sqlite3")
    )
    val concurrentRegex = PrefilteredRegex(
      ".*(multiprocess|multiprocessing|threading)\\.(Process|Thread).*",
      Seq("multiprocess", "threading")
    )
    val cryptoLibs        = "(cryptography|Crypto|ecdsa|nacl|OpenSSL).*"
    val cryptoLibLiterals = Seq("cryptography", "Crypto", "ecdsa", "nacl", "OpenSSL")
    val cryptoLibsRegex   = PrefilteredRegex(cryptoLibs, cryptoLibLiterals)
    // Two groups, ANDed: a match must contain a crypto library name AND one of the operation
    // names. `++` here would flatten them into a single OR - still correct, since a wider
    // prefilter can only pass more, but it would let every `cryptography.*` node through to the
    // regex and give back most of what the prefilter is for.
    val cryptoGenerateRegex = PrefilteredRegex(
      s"$cryptoLibs(generate|encrypt|decrypt|derive|sign|public_bytes|private_bytes|exchange|new|update|export_key|import_key|from_string|from_pem|to_pem|load_certificate).*",
      cryptoLibLiterals,
      Seq(
        "generate",
        "encrypt",
        "decrypt",
        "derive",
        "sign",
        "public_bytes",
        "private_bytes",
        "exchange",
        "new",
        "update",
        "export_key",
        "import_key",
        "from_string",
        "from_pem",
        "to_pem",
        "load_certificate"
      )
    )
    val cryptoAlgorithmRegex = PrefilteredRegex(
      s"$cryptoLibs(primitives|serialization).*",
      cryptoLibLiterals,
      Seq("primitives", "serialization")
    )
    val cryptoAlgoNameRegex = "^[A-Z0-9]+$".r

    // P1.1: code-execution sinks. Only `eval`/`exec` were covered before, which killed
    // most realistic Python taint results. Matched on methodFullName first (cross-module
    // call resolution is good: `subprocess.getoutput` resolves to `subprocess.getoutput`), with
    // a `code` fallback for unresolved calls.
    //
    // The module must END at the alternation and START at a module boundary. The lookbehind
    // supplies the second half - it rejects both `myos.system` (a longer name merely ending in
    // a sink module) and `venv.subprocess.run`, where a leading dot means a DIFFERENT outer
    // module that happens to vendor one. `(\\.\\w+)*` supplies the first half, admitting modules
    // INSIDE the package: once `python-deps=full` puts real dependency bodies in the graph a
    // resolved call carries `subprocess.compat.run`, and a pattern that only knew
    // `subprocess.run` would go deaf exactly when the callee is real. `subprocessing.utils.run`
    // matches nothing either way - that near-miss is what keeps the widening from being a
    // wildcard, and EasyTagsPassTests pins both halves.
    val moduleSep = "(\\.\\w+)*\\."
    val codeExecutionSinks = Seq(
      "subprocess" -> Seq(
        "run",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
        "Popen"
      ),
      "os" -> Seq(
        "system",
        "popen",
        "execv",
        "execve",
        "execl",
        "execlp",
        "execvp",
        "spawnl",
        "spawnv",
        "posix_spawn"
      ),
      "commands" -> Seq("getoutput", "getstatusoutput"),
      "pty"      -> Seq("spawn"),
      "asyncio"  -> Seq("create_subprocess_shell", "create_subprocess_exec")
    )
    // Every match contains its module literal followed by a dot - `moduleSep` always ends in one,
    // whether or not it took the package-internal hop - so the prefilter can demand `subprocess.`
    // rather than the looser `subprocess`. The module alternatives form ONE or-group: a match
    // contains exactly one of them. Derived from the sink list itself, never from a neighbouring
    // one, so adding a module to a family cannot leave its prefilter behind - that would be a
    // prefilter narrower than its regex, which is a silent detection loss.
    def modulePrefilter(sinks: Seq[(String, Seq[String])]): Seq[String] = sinks.map(_._1 + ".")
    val codeExecutionModulePrefilter: Seq[Seq[String]] = Seq(modulePrefilter(codeExecutionSinks))
    val codeExecutionFullNameRegex = PrefilteredRegex(
      ".*(?<![\\w.])(" + codeExecutionSinks
          .map { case (mod, fns) => s"""$mod$moduleSep(${fns.mkString("|")})""" }
          .mkString("|") + ")$",
      codeExecutionModulePrefilter*
    )
    val codeExecutionCallPrefilter: Seq[Seq[String]] =
        Seq(modulePrefilter(codeExecutionSinks), Seq("("))
    val codeExecutionCodeRegex = PrefilteredRegex(
      ".*(" + codeExecutionSinks
          .map { case (mod, fns) => s"""\\b$mod\\.(${fns.mkString("|")})\\s*\\(""" }
          .mkString("|") + ")",
      codeExecutionCallPrefilter*
    )

    // P1.2: the subset of code-execution sinks that runs the command through a shell.
    // `subprocess.run(["ls", x])` and `subprocess.run("ls " + x, shell=True)` are not
    // the same risk and must not rank the same. The argv-list APIs (os.exec*, spawn*,
    // posix_spawn) are excluded: they never invoke a shell.
    val shellCapableSinks = Seq(
      "subprocess" -> Seq(
        "run",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
        "Popen"
      ),
      "os"       -> Seq("system", "popen"),
      "commands" -> Seq("getoutput", "getstatusoutput"),
      "pty"      -> Seq("spawn"),
      "asyncio"  -> Seq("create_subprocess_shell")
    )
    val shellTrueCodeRegex =
        PrefilteredRegex(".*shell\\s*=\\s*True.*", Seq("shell"))
    val shellCapableFullNameRegex = PrefilteredRegex(
      ".*(?<![\\w.])(" + shellCapableSinks
          .map { case (mod, fns) => s"""$mod$moduleSep(${fns.mkString("|")})""" }
          .mkString("|") + ")$",
      modulePrefilter(shellCapableSinks)
    )
    val shellCapableCallPrefilter: Seq[Seq[String]] =
        Seq(modulePrefilter(shellCapableSinks), Seq("("))
    val shellCapableCodeRegex = PrefilteredRegex(
      ".*(" + shellCapableSinks
          .map { case (mod, fns) => s"""\\b$mod\\.(${fns.mkString("|")})\\s*\\(""" }
          .mkString("|") + ")",
      shellCapableCallPrefilter*
    )

    // P1.3: sink families completed for Python parity with the Java tagger.
    val ssrfFullNameRegex = PrefilteredRegex(
      ".*(?<![\\w.])(requests|httpx|urllib|aiohttp|httplib)(\\.\\w+)*\\.(get|post|put|patch|delete|head|options|request|urlopen|open)$",
      Seq("requests.", "httpx.", "urllib.", "aiohttp.", "httplib.")
    )
    val ssrfCodeRegex = PrefilteredRegex(
      ".*\\b(requests|httpx|urllib\\.request|aiohttp)\\.(get|post|put|patch|delete|head|options|request|urlopen)\\s*\\(",
      Seq("requests.", "httpx.", "urllib.", "aiohttp."),
      Seq("(")
    )
    val pathTraversalFullNameRegex = PrefilteredRegex(
      ".*(?<![\\w.])(posixpath|ntpath|pathlib|glob)(\\.\\w+)*\\.(join|Path|glob|iglob)$",
      Seq("posixpath.", "ntpath.", "pathlib.", "glob.")
    )
    val templateInjectionFullNameRegex = PrefilteredRegex(
      ".*(?<![\\w.])jinja2(\\.\\w+)*\\.(Template|Environment)$",
      Seq("jinja2.")
    )
    val ldapFullNameRegex = PrefilteredRegex(
      ".*(?<![\\w.])ldap(\\.\\w+)*\\.(initialize|open|search_s|search_st|search_ext_s|modify_s|modify_ext_s|add_s|delete_s|bind_s|simple_bind_s|unbind_ext_s)$",
      Seq("ldap.")
    )
    val ldapCodeRegex = PrefilteredRegex(
      ".*\\bldap\\.(initialize|search_s|search_st|search_ext_s|modify_s|modify_ext_s|add_s|delete_s|bind_s|simple_bind_s|unbind_ext_s)\\s*\\(",
      Seq("ldap."),
      Seq("(")
    )
    val xxeFullNameRegex = PrefilteredRegex(
      ".*(lxml|xml\\.etree|ElementTree).*\\.(fromstring|parse|XMLParser|XML|iterparse)$",
      Seq("lxml", "xml.etree", "ElementTree"),
      Seq(".fromstring", ".parse", ".XMLParser", ".XML", ".iterparse")
    )
    val xxeCodeRegex = PrefilteredRegex(
      ".*\\b(etree|ElementTree)\\.(fromstring|parse|XMLParser|XML|iterparse)\\s*\\(",
      Seq("etree.", "ElementTree."),
      Seq("(")
    )

    // Precompiled: this is tested against every call node's name, and String.matches would
    // recompile the pattern per node (the juice-shop lesson, ChennaiTagsPass:66).
    val dbReadHelperRegex = "get_object_or_\\w+|get_list_or_\\w+".r

    def hasDynamicArgument(call: Call): Boolean =
        call.argument.exists(a => a.label == "IDENTIFIER" || a.label == "CALL")

    // Receiver accesses (`conn.execute`, `render_template_string`) are lowered to
    // `<operator>.fieldAccess` CALL nodes with the same name as the invocation. They are
    // not sinks themselves; tagging them double-counts every sink site.
    def isOperatorCall(call: Call): Boolean =
        call.methodFullName.startsWith("<operator") || call.name.startsWith("<operator")

    val methodTags = scala.collection.mutable.LinkedHashMap.empty[
      String,
      scala.collection.mutable.LinkedHashSet[StoredNode]
    ]
    def addTag(tag: String, node: StoredNode): Unit =
        methodTags.getOrElseUpdate(tag, scala.collection.mutable.LinkedHashSet.empty) += node

    // 1. Methods & Parameters
    atom.method.foreach { method =>
      val fullName = method.fullName

      var matchedResp = false
      var i           = 0
      while i < pyResponseRegexes.length do
        if pyResponseRegexes(i).matches(fullName) then matchedResp = true
        i += 1
      if matchedResp then
        method.parameter.foreach(p => addTag("framework-output", p))

      if !method.isExternal && validationRegex.matches(method.name) then
        addTag("validation", method)

      if cliFilenameRegex.matches(method.filename) then
        method.parameter.foreach(p => addTag("cli-source", p))
    }

    // 2. Identifiers
    atom.identifier.foreach { identifier =>
      val name         = identifier.name
      val typeFullName = identifier.typeFullName
      if name == "flask_request" then
        addTag("framework-input", identifier)
      if aiohttpRegex.matches(typeFullName) then
        addTag("http-client", identifier)
      if sqlIdentifierRegex.matches(typeFullName) then
        addTag("sql", identifier)
      if cryptoLibsRegex.matches(typeFullName) then
        addTag("crypto", identifier)
    }

    // 3. Calls
    atom.call.foreach { call =>
      val name           = call.name
      val methodFullName = call.methodFullName
      val code           = call.code

      // G3/G4: a render/redirect whose dynamic argument is a constant is not an
      // attacker-influenced output (template name is a literal, redirect target is a
      // url-name literal or `reverse(...)`). Skip framework-output for these benign sinks.
      val benignOutput =
          if name == "render" || name == "render_to_string" || name == "get_template" ||
            name == "get_template_names" || name == "render_template"
          then
            // A template resolver (self.get_template()) is itself benign, and a render whose
            // template comes from a literal, a resolver call or a member access (self.template)
            // is not attacker-influenced. The template sits at positional arg 2 of render.
            name == "get_template" || name == "get_template_names" ||
            call.argument.isLiteral.exists(l =>
                Seq(".html", ".txt", ".xml", ".json", ".htm").exists(l.code.contains)
            ) ||
            call.argument.isCall.name(
              "get_template|get_template_names|get_template_name"
            ).nonEmpty ||
            call.argument.argumentIndex(2).exists(x => x.label == "CALL" || x.label == "LITERAL")
          else if name == "redirect" || name == "HttpResponseRedirect" ||
            name == "HttpResponsePermanentRedirect"
          then
            call.argument.isLiteral.nonEmpty || call.argument.isCall.name("reverse").nonEmpty
          else false

      var matchedResp = false
      var i           = 0
      while i < pyResponseRegexes.length do
        if pyResponseRegexes(i).matches(code) then matchedResp = true
        i += 1
      if matchedResp && !benignOutput then
        addTag("framework-output", call)

      if !benignOutput && pyResponseCallRegex.matches(code) then
        val filename = call.method.filename
        if pyResponseFileRegex.matches(filename) then
          addTag("framework-output", call)

      // G1: ORM read accessor - return value is persisted data, a distinct trust level
      // from live request input. Tagged so profiles can use it as a declassification barrier.
      if dbReadHelperNames.contains(name) ||
        dbReadHelperRegex.matches(name) ||
        (ormAccessorNames.contains(name) &&
            (methodFullName.contains(".objects.") || methodFullName.contains(".query.")))
      then
        addTag("db-read", call)

      // G6: DRF/serializer validation entrypoint.
      if name == "is_valid" then
        addTag("validation", call)

      // G6+: Django/DRF/stdlib security neutralisers (open-redirect guards, HTML escapers, ...).
      if sanitizerCallNames.contains(name) then
        addTag("sanitization", call)

      if name == "get_value" then
        addTag("framework-input", call)

      if aiohttpRegex.matches(methodFullName) then
        addTag("http-client", call)

      if socketRegex.matches(methodFullName) then
        addTag("network", call)

      if sslRegex.matches(methodFullName) then
        addTag("network", call)

      if netProtocolRegex.matches(methodFullName) then
        addTag("network", call)

      if name == "open" then
        addTag("file-io", call)

      if shutilRegex.matches(methodFullName) then
        addTag("file-io", call)

      if serializationRegex.matches(methodFullName) then
        addTag("serialization", call)

      // G5: unsafe deserialisation is a true code-exec-class sink, kept distinct from safe
      // (de)serialisation above.
      if deserializationRegex.matches(methodFullName) || deserializationRegex.matches(code) then
        addTag("unsafe-deserialization", call)

      if regexLibRegex.matches(methodFullName) then
        addTag("regex", call)

      if importlibRegex.matches(methodFullName) then
        addTag("reflection", call)

      // G2: getattr/setattr/delattr is only reflection-as-a-sink when the attribute name is
      // dynamic. A string-literal attribute (e.g. getattr(user, "is_anonymous")) is an ordinary
      // field access and must not be flagged.
      if name == "getattr" || name == "delattr" || name == "setattr" then
        val attrArg = call.argument.argumentIndex(2).headOption
        // A literal attribute, or a member access on self/cls (self.target_name), is an
        // effectively constant field name - not attacker-controlled reflection.
        val constantAttr = attrArg.exists { a =>
            a.label == "LITERAL" ||
            (a.label == "CALL" && (a.code.startsWith("self.") || a.code.startsWith("cls.")))
        }
        if !constantAttr then
          addTag("reflection", call)

      if sqlRegex.matches(methodFullName) then
        addTag("sql", call)

      // P1.1: the code-execution sink family (previously only eval/exec).
      if name == "eval" || name == "exec" ||
        codeExecutionFullNameRegex.matches(methodFullName) ||
        codeExecutionCodeRegex.matches(code)
      then
        addTag("code-execution", call)
        // P1.2: shell-execution risk rank. shell=True, or a single string command
        // rather than an argv list, means the command line reaches a shell.
        val argvListArg = call.argument.argumentIndex(1).exists { a =>
            a.code.startsWith("[") || a.code.startsWith("(")
        }
        if shellTrueCodeRegex.matches(code) ||
          (shellCapableFullNameRegex.matches(methodFullName) ||
              shellCapableCodeRegex.matches(code)) && !argvListArg
        then
          addTag("shell-exec", call)

      // P1.3: sql sinks beyond the receiver-keyed sqlRegex above. `.execute` on any
      // receiver is a SQL entrypoint (Django `cursor.execute(...)` resolves through a
      // temporary and carries no receiver hint), and `.raw()`/`.extra()` are true SQLi
      // sinks. `text()` is constrained to SQLAlchemy to avoid colliding with other
      // `text` methods.
      if !isOperatorCall(call) &&
        (name == "execute" || name == "executemany" || name == "executescript" ||
            name == "raw" || name == "extra" ||
            (name == "text" && (methodFullName.contains("sqlalchemy") || code.contains(
              "sqlalchemy"
            ))))
      then
        addTag("sql", call)

      // P1.3: ssrf - HTTP client calls whose URL is not a literal.
      if ssrfFullNameRegex.matches(methodFullName) || ssrfCodeRegex.matches(code) then
        if hasDynamicArgument(call) then
          addTag("ssrf", call)
        else
          addTag("http-client", call)

      // P1.3: path traversal - open/os.path.join/pathlib.Path/glob with a dynamic
      // (non-literal) path component.
      if !isOperatorCall(call) &&
        ((name == "open" && hasDynamicArgument(call)) ||
            (pathTraversalFullNameRegex.matches(methodFullName) && hasDynamicArgument(call)))
      then
        addTag("path-traversal", call)

      // P1.3: template injection.
      if !isOperatorCall(call) &&
        (name == "render_template_string" || templateInjectionFullNameRegex.matches(
          methodFullName
        ))
      then
        addTag("template-injection", call)

      // P1.3: ldap injection.
      if ldapFullNameRegex.matches(methodFullName) || ldapCodeRegex.matches(code) then
        addTag("ldap", call)

      // P1.3: xxe - XML parsers of the lxml/ElementTree families. lxml resolves
      // entities by default, so the parse entrypoints themselves carry the risk.
      if xxeFullNameRegex.matches(methodFullName) || xxeCodeRegex.matches(code) then
        addTag("xxe", call)

      if concurrentRegex.matches(methodFullName) then
        addTag("concurrent", call)

      if cryptoLibsRegex.matches(methodFullName) then
        addTag("crypto", call)

      if cryptoGenerateRegex.matches(methodFullName) then
        addTag("crypto-generate", call)

      if name.nonEmpty && cryptoAlgoNameRegex.matches(name) then
        if cryptoAlgorithmRegex.matches(methodFullName) && call.argument.nonEmpty then
          addTag("crypto-algorithm", call)
    }

    // PEP 750 t-strings: tag the template and each of its interpolations `template-literal` so
    // profiles can treat them as interpolation boundaries rather than string sinks. NOT a
    // sanitiser: the taint sits in the interpolations, and a consumer that renders the template
    // (str(), a sql driver) receives it - the tag marks the deferral, not a declassification.
    atom.call.name("<operator>.templateString").newTagNode("template-literal").store()(using
    dstGraph)
    atom.call.name("<operator>.interpolation").newTagNode("template-literal").store()(using
    dstGraph)

    // 3b. Request-access EXPRESSIONS as framework-input.
    //
    // Previously a request source was only tagged when it was assigned to a local
    // (ChennaiTagsPass tagged the assignment's LHS identifier), so an inline use --
    // `sink(request.args["v"])` -- had no tagged source at all and produced no flow.
    // That looked like "reachables only finds intra-method flows"; it was really a
    // missing source. Tag the access expression itself and both forms work.
    //
    // Framework-agnostic on purpose: matched on the expression, not on the file name,
    // so Flask in app.py is covered as well as Django in views.py. Task 3's framework
    // recognizers will subsume this with proper proxy/parameter typing.
    // ANCHORED at the head of the expression on purpose. Matching `request.args` as a
    // substring anywhere would also match every *enclosing* expression -- the code of
    // `sink(request.args["v"])` contains it too -- and the outermost-wins rule below
    // would then tag the sink call as the source. An optional dotted qualifier admits
    // `self.request.args` (Django CBVs) and `flask.request.args` while still excluding
    // anything with a `(` before the accessor.
    //
    // The `session` arm preserves the coverage of ChennaiTagsPass's now-removed
    // HTTP_METHODS_REGEX (`(request|session)\.(args|get|post|put|form)`): Flask's
    // session is client-supplied signed-cookie data.
    // `query`/`query_params`/`match_info` were added by Task 4 (B3): aiohttp/Starlette-style
    // request-proxy accessors, tagged the same way as the Flask/Django ones.
    val requestAccessRegex =
        ("""(?s)(\w+\.)*(request\.(form|args|values|json|data|files|headers|cookies|""" +
            """query_string|query_params|query|match_info|remote_addr|host|method|full_path|url|""" +
            """path|user_agent|GET|POST|COOKIES|META|body|get_json|get_data|getlist)""" +
            """|session\.(args|get|post|put|form))\b.*""").r

    val requestAccessCalls = atom.call
        // Cheap substring prefilter before the regex. This runs over every call node in the
        // graph - 1.3M of them on the django wheel - and the pattern can only match code
        // containing one of these literals, so the regex engine is skipped for the vast
        // majority. Same technique as the Vue `$route` prefilter in ChennaiTagsPass, which
        // was added after `Pattern.compile` dominated the juice-shop tagging phase.
        .filter(c => c.code.contains("request.") || c.code.contains("session."))
        // The RHS is the source; tagging the assignment as well would double-report it.
        .filterNot(c => c.name == Operators.assignment)
        .filter(c => requestAccessRegex.matches(c.code))
        .l
    val requestAccessIds = requestAccessCalls.map(_.id()).toSet

    // `request.args["v"]` yields nested matching calls (fieldAccess `request.args`
    // inside indexAccess `request.args["v"]`). Keep only the outermost, otherwise one
    // source is reported once per nesting level.
    requestAccessCalls
        .filterNot { c =>
            // `astParentOption`: "is my parent one of these calls" is a question with a
            // legitimate "there is no parent" answer, and a tagging pass must not die on a
            // parentless node - which the asserting `astParent` would now make it do.
            c.astParentOption match
              case Some(p: Call) => requestAccessIds.contains(p.id())
              case _             => false
        }
        .foreach(c => addTag("framework-input", c))

    // 4. CLI Source controlled calls & their callees
    val cliSourceCalls = atom.call
        .methodFullName(Operators.equals)
        .code("""__name__ == ["']__main__["']""")
        .controls
        .isCall
        .filterNot(_.name.startsWith("<operator"))
        .l

    cliSourceCalls.foreach { c =>
      addTag("cli-source", c)
      c.callee(using NoResolve).foreach(m => addTag("cli-source", m))
    }

    // Emit tags to dstGraph
    methodTags.foreach { case (tag, nodes) =>
        nodes.iterator.newTagNode(tag).store()(using dstGraph)
    }
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
