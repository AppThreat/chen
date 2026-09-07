package io.appthreat.pysrc2cpg

/** The path -> dotted-module rules; since task 09 the PRIMARY name computation of the frontend
  * (every METHOD/TYPE_DECL full name is built from it), no longer a tag index's helper.
  *
  * The rules, in order:
  *
  *   - the longest run of directories, starting at the file's own directory and walking up, each
  *     containing an ingested `__init__.py`, anchors the name; the chain itself is part of the name
  *     (`flask/app.py` under a `flask` package is `flask.app`), and a `src/` hop above the chain
  *     disappears;
  *   - files under no regular package resolve as PEP 420 namespace modules: their path under the
  *     input root, dotted (`flask/sansio/app.py` with no `sansio/__init__.py` ->
  *     `flask.sansio.app`);
  *   - `__init__.py` contributes its directory, not a name segment of its own (`flask/__init__.py`
  *     -> `flask`);
  *   - `.py` and `.pyi` are the SAME module and map to the same name (`pkg/mod.py` and
  *     `pkg/mod.pyi` are both `pkg.mod`): a module that ships both spellings must not become two;
  *   - `pkg/mod.py` next to `pkg/mod/__init__.py` is resolved by CPython's own rule: the finder
  *     checks directories before file loaders, so the REGULAR PACKAGE wins and the shadowed module
  *     file is unimportable. The package takes `pkg.mod`; the shadowed file gets
  *     `pkg.mod.__shadowed__` - deterministic, disclosed, and unable to merge two distinct methods
  *     under one full name, which would be worse than an ugly name.
  */
object PythonModuleName:

  /** Dotted module name of `relPath`, given the set of ingested file names. `None` only for names
    * that are not `.py`/`.pyi` sources (the global `N/A` holder, config files).
    */
  def moduleFor(fileNames: Set[String], relPath: String): Option[String] =
    if !(relPath.endsWith(".py") || relPath.endsWith(".pyi")) then None
    else
      val dirParts = relPath.split('/').toSeq.dropRight(1)
      val fileName = relPath.split('/').last
      val isInit   = fileName == "__init__.py" || fileName == "__init__.pyi"
      val stem     = fileName.stripSuffix(".pyi").stripSuffix(".py")

      // longest run of consecutive package dirs, starting at the file's own dir
      var chainLen = 0
      var walking  = dirParts.nonEmpty
      def isPackageDir(parts: Seq[String]): Boolean =
          fileNames.contains(parts.mkString("/") + "/__init__.py") ||
              fileNames.contains(parts.mkString("/") + "/__init__.pyi")
      while walking && chainLen < dirParts.length do
        val candidate = dirParts.take(dirParts.length - chainLen)
        if isPackageDir(candidate) then chainLen += 1
        else walking = false

      val moduleParts =
          if chainLen > 0 then dirParts.drop(dirParts.length - chainLen) else dirParts
      val dotted = if isInit then moduleParts else moduleParts :+ stem

      // CPython import precedence: a directory containing __init__.py beats a same-named
      // module file in the same directory. The package keeps the plain name.
      val shadowedByPackage = !isInit && isPackageDir(dirParts :+ stem)

      if dotted.isEmpty then None
      else if shadowedByPackage then Some((dotted :+ "__shadowed__").mkString("."))
      else Some(dotted.mkString("."))
    end if
  end moduleFor

  /** Dotted full name of a METHOD/TYPE_DECL full name, given a module-name resolver for the file
    * part. Full names shaped `path/to.py:<qualname>` resolve; anything else (`__builtin.*`, `ANY`,
    * recovery placeholders) yields `None`.
    */
  def dottedFromFullName(moduleFor: String => Option[String], fullName: String): Option[String] =
      fullName.split(":", 2) match
        case Array(filePart, qualPart) if filePart.endsWith(".py") || filePart.endsWith(".pyi") =>
            moduleFor(filePart).map { module =>
              val segments = qualPart.split('.').toSeq
              val withoutModuleScope =
                  if segments.headOption.contains("<module>") then segments.drop(1) else segments
              val significant = withoutModuleScope.filter(_.nonEmpty)
              if significant.isEmpty then module
              else s"$module.${significant.mkString(".")}"
            }
        case _ => None
  end dottedFromFullName
end PythonModuleName
