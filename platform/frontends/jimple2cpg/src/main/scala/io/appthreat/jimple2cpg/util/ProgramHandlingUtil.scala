package io.appthreat.jimple2cpg.util

import better.files.*
import io.appthreat.x2cpg.parse.ParseReporter
import org.objectweb.asm.ClassReader.SKIP_CODE
import org.objectweb.asm.{ClassReader, ClassVisitor, Opcodes}

import java.io.InputStream
import java.util.zip.ZipEntry
import scala.util.{Failure, Left, Success, Try}

/** Responsible for handling JAR unpacking and handling the temporary build directory.
  */
object ProgramHandlingUtil:

  /** Common properties of a File and ZipEntry, used to determine whether a file in a directory or
    * an entry in an archive is worth emitting/extracting
    */
  sealed class Entry(entry: Either[File, ZipEntry]):

    def this(file: File) = this(Left(file))
    def this(entry: ZipEntry) = this(Right(entry))
    private def file: File          = entry.fold(identity, e => File(e.getName))
    def name: String                = file.name
    def extension: Option[String]   = file.extension
    def isDirectory: Boolean        = entry.fold(_.isDirectory, _.isDirectory)
    def maybeRegularFile(): Boolean = entry.fold(_.isRegularFile, !_.isDirectory)

    /** Determines whether a zip entry is potentially malicious.
      * @return
      *   whether the entry is a ZipEntry and uses '..' in it's components
      */
    // Note that we consider either type of path separator as although the spec say that only
    // unix separators are to be used, zip files in the wild may vary.
    def isZipSlip: Boolean = entry.fold(_ => false, _.getName.split("[/\\\\]").contains(".."))

  /** Process files that may lead to more files to process or to emit a resulting value of [[A]]
    *
    * @param src
    *   The file/directory to traverse
    * @param emitOrUnpack
    *   A function that takes a file and either emits a value or returns more files to traverse
    * @tparam A
    *   The type of emitted values
    * @return
    *   The emitted values
    */
  private def unfoldArchives[A](
    src: File,
    emitOrUnpack: File => Either[A, List[File]],
    depth: Int = 0,
    maxDepth: Int = 10 // Prevent infinite recursion
  ): IterableOnce[A] =
    if depth > maxDepth then
      return Seq.empty

    emitOrUnpack(src) match
      case Left(a) => Seq(a)
      case Right(disposeFiles) =>
          disposeFiles.flatMap(x => unfoldArchives(x, emitOrUnpack, depth + 1, maxDepth))

  /** Find <pre>.class</pre> files, including those inside archives.
    *
    * @param src
    *   The file/directory to search.
    * @param tmpDir
    *   A temporary directory for extracted archives
    * @param isArchive
    *   Whether an entry is an archive to extract
    * @param isClass
    *   Whether an entry is a class file
    * @param recurse
    *   Whether to unpack recursively
    * @param onlyClasses
    *   Include only .class files
    * @return
    *   The list of class files found, which may either be in [[src]] or in an extracted archive
    *   under [[tmpDir]]
    */
  private def extractClassesToTmp(
    src: File,
    tmpDir: File,
    isArchive: Entry => Boolean,
    isClass: Entry => Boolean,
    recurse: Boolean,
    onlyClasses: Boolean,
    rootArchivePath: Option[String]
  ): IterableOnce[ClassFile] =

    def shouldExtract(e: Entry) =
        !e.isZipSlip && e.maybeRegularFile() && (isArchive(e) || isClass(e))
    unfoldArchives(
      src,
      {
          case f if isClass(Entry(f)) =>
              Left(ClassFile(f, rootArchivePath))
          case f if f.isDirectory() =>
              var files = f.listRecursively.filterNot(_.isDirectory)
              if onlyClasses then
                files = files.filter(_.pathAsString.endsWith(".class"))
              val dirSourceArchivePath = if src.isDirectory then None else rootArchivePath
              Right(files.toList)
          case f if isArchive(Entry(f)) && (recurse || f == src) =>
              val xTmp = File.newTemporaryDirectory("extract-archive-", parent = Some(tmpDir))
              val unzipDirs = Try(f.unzipTo(xTmp, e => shouldExtract(Entry(e)))) match
                case Success(dir) =>
                    val nestedArchives = if recurse then
                      dir.listRecursively.filter(file =>
                          file.isRegularFile && isArchive(Entry(file))
                      ).toList
                    else
                      List.empty[File]
                    dir :: nestedArchives
                case Failure(e) =>
                    List.empty
              Right(unzipDirs)
          case _ =>
              Right(List.empty)
      }
    )
  end extractClassesToTmp

  object ClassFile:
    private def readPackagePathFromStream(is: InputStream): Option[String] =
      val cr = new ClassReader(is)
      sealed class ClassNameVisitor extends ClassVisitor(Opcodes.ASM9):
        var path: Option[String] = None
        override def visit(
          version: Int,
          access: Int,
          name: String,
          signature: String,
          superName: String,
          interfaces: Array[String]
        ): Unit =
            path = Some(name)
      val rootVisitor = new ClassNameVisitor()
      cr.accept(rootVisitor, SKIP_CODE)
      rootVisitor.path

    /** Attempt to retrieve the package path from JVM bytecode.
      *
      * @param file
      *   The class file
      * @return
      *   The package path, or why it could not be read
      */
    private def getPackagePathFromByteCode(file: File): Either[String, String] =
        Try(file.fileInputStream.apply(readPackagePathFromStream)) match
          case Success(Some(path)) => Right(path)
          case Success(None)       => Left("the bytecode names no class")
          case Failure(e)          => Left(ParseReporter.describe(e))
  end ClassFile

  /** @param unreadable
    *   why the package path could not be read from the bytecode, when it could not: such a class
    *   file is left out, and the reason goes into the parse report
    */
  sealed class ClassFile(
    val file: File,
    val packagePath: Option[String],
    val sourceArchivePath: Option[String],
    val unreadable: Option[String] = None
  ):
    def this(file: File, sourceArchivePath: Option[String], read: Either[String, String]) =
        this(file, read.toOption, sourceArchivePath, read.left.toOption)

    def this(file: File, sourceArchivePath: Option[String]) =
        this(file, sourceArchivePath, ClassFile.getPackagePathFromByteCode(file))

    private val components: Option[Array[String]] = packagePath.map(_.split("/"))

    val fullyQualifiedClassName: Option[String] = components.map(_.mkString("."))

    /** Copy the class file to its package path relative to destDir. This will overwrite a class
      * file at the destination if it exists.
      * @param destDir
      *   The directory in which to place the class file
      * @return
      *   The class file at the destination if the package path could be retrieved from the its
      *   bytecode
      */
    def copyToPackageLayoutIn(destDir: File): Option[ClassFile] =
        packagePath
            .map { path =>
              val destClass = destDir / s"$path.class"
              destClass.parent.createDirectories()
              ClassFile(
                file.copyTo(destClass)(using File.CopyOptions(overwrite = true)),
                packagePath,
                sourceArchivePath
              )
            }
            .orElse {
                None
            }
  end ClassFile

  /** Find <pre>.class</pre> files, including those inside archives and copy them to their package
    * path location relative to destDir
    *
    * @param src
    *   The file/directory to search.
    * @param destDir
    *   The directory in which to place the class files
    * @param isArchive
    *   Whether an entry is an archive to extract
    * @param isClass
    *   Whether an entry is a class file
    * @param recurse
    *   Whether to unpack recursively
    * @param onlyClasses
    *   Include only .class files
    * @return
    *   The copied class files in destDir
    */
  def extractClassesInPackageLayout(
    src: File,
    destDir: File,
    isClass: Entry => Boolean,
    isArchive: Entry => Boolean,
    recurse: Boolean,
    onlyClasses: Boolean
  ): (List[ClassFile], Option[String]) =
    val rootArchivePath: Option[String] =
        if isArchive(new Entry(src)) then Some(src.pathAsString) else None
    File
        .temporaryDirectory("extract-classes-")
        .apply { tmpDir =>
          val result = extractClassesToTmp(
            src,
            tmpDir,
            isArchive,
            isClass,
            recurse: Boolean,
            onlyClasses: Boolean,
            rootArchivePath
          ).iterator
              .flatMap(classFile =>
                val copied = classFile.copyToPackageLayoutIn(destDir)
                if copied.isEmpty then recordUnreadable(classFile, src, tmpDir)
                copied
              )
              .toList

          (result, rootArchivePath)
        }
  end extractClassesInPackageLayout

  /** A class file whose package path cannot be read never reaches the AST pass (chen#255). It is
    * named by its path under `src`, or, when it came out of an archive, as `archive!entry`.
    */
  private def recordUnreadable(classFile: ClassFile, src: File, tmpDir: File): Unit =
      if ParseReporter.isEnabled then
        val path = classFile.file.pathAsString
        val name =
            if src.isDirectory && path.startsWith(src.pathAsString) then
              ParseReporter.relativeTo(src.pathAsString, path)
            else
              // <tmpDir>/extract-archive-<n>/<entry>
              val entry =
                  ParseReporter.relativeTo(tmpDir.pathAsString, path).split('/').drop(1).mkString(
                    "/"
                  )
              s"${src.name}!$entry"
        ParseReporter.record(
          ParseReporter.Frontend.Jimple,
          name,
          ParseReporter.Outcome.Unparsed,
          ParseReporter.Stage.Parse,
          s"the package path could not be read from the bytecode: ${classFile.unreadable
                  .getOrElse("no reason given")}"
        )
end ProgramHandlingUtil
