package io.appthreat.edg2atom.passes

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.edg2atom.Edg2Atom
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.util.concurrent.TimeUnit
import scala.util.Properties.isWin

/** A project header is attributed to the project over real paths, not by the spelling each side of
  * the comparison carries (atom#390). edga's `inRoot` flag compares the header's path with the
  * project root byte by byte, so it comes out false when one side spells the directory differently
  * from the other: the 8.3 short name a temporary directory carries on Windows (`RUNNER~1`) against
  * its long one, or the same file named through a redundant segment. The exporter's flag then hides
  * a header the project owns.
  *
  * The stub answers `--edga-version` and exports one canned unit whose header entry names an
  * existing file through a redundant segment and carries `inRoot: false`, as edga reports a header
  * of a directory spelled two ways. Everything else in the pipeline real-paths its paths already
  * (the header's owner, the unit that writes it), so the flag is the only gate the test turns: the
  * header is dropped while attribution trusts the spelling, and written once it is decided over
  * real paths. The redundant segment stands in for the short name, which only a Windows runner can
  * spell; both call for the same reconciliation, and neither needs symlinks or privileges.
  */
class EdgShortNameAttributionTests extends AnyWordSpec with Matchers:

  private val main   = "main.c"     -> "#include \"proj_hdr.h\"\nint main(void) { return 0; }\n"
  private val header = "proj_hdr.h" -> "int h(void);\nint h(void) { return 42; }\n"

  private def project(files: (String, String)*)(test: File => Unit): Unit =
      File.usingTemporaryDirectory("edg2atom") { dir =>
        files.foreach { (name, text) =>
            (dir / name).createIfNotExists(createParents = true).writeText(text)
        }
        test(dir)
      }

  private def graph(dir: File)(check: Cpg => Unit): Unit =
    val out = File.newTemporaryFile("edg2atom", ".atom")
    val config = Config().withInputPath(dir.pathAsString).withOutputPath(out.pathAsString)
        .withFunctionBodies(true)
    val cpg = new Edg2Atom().createCpg(config).get
    try check(cpg)
    finally
      cpg.close()
      out.delete(swallowIOExceptions = true)

  /** The unit the stub exports: `h` is defined in the header, whose entry names the real file
    * through a redundant segment and carries the false `inRoot` a byte-by-byte comparison leaves
    * when the two sides spell the directory differently.
    */
  private def cannedUnit(dir: File): String =
    // the project root, spelled as the runner gives it and with the separators JSON needs
    val dirPath = dir.pathAsString.replace("\\", "\\\\")
    s"""{
        |  "schema": "edga/1",
        |  "tu": { "path": "$dirPath/main.c", "language": "c", "status": "ok" },
        |  "files": [
        |    { "id": 0, "path": "$dirPath/main.c", "written": "main.c", "system": false, "inRoot": true },
        |    { "id": 1, "path": "$dirPath/./proj_hdr.h", "written": "proj_hdr.h", "system": false,
        |      "inRoot": false, "includedFrom": [0, 1], "systemInclude": false }
        |  ],
        |  "types": [
        |    { "id": 0, "kind": "routine", "name": "int (void)", "returns": 1, "params": [] },
        |    { "id": 1, "kind": "integer", "name": "int", "size": 4, "signed": true },
        |    { "id": 2, "kind": "routine", "name": "int (void)", "returns": 1, "params": [] }
        |  ],
        |  "routines": [
        |    {
        |      "id": 1, "name": "h", "qualifiedName": "h", "type": 0, "returnType": 1,
        |      "prototyped": true, "linkage": "external", "storage": "unspecified",
        |      "p": [1, 2, 5], "start": [1, 2, 1], "defined": true, "params": [],
        |      "body": {
        |        "k": "block", "p": [1, 2, 13], "end": [1, 2, 26],
        |        "stmts": [
        |          { "k": "return", "p": [1, 2, 15], "end": [1, 2, 24],
        |            "expr": { "k": "constant", "t": 1, "p": [1, 2, 22], "ck": "integer", "value": "42" } }
        |        ]
        |      }
        |    },
        |    {
        |      "id": 2, "name": "main", "qualifiedName": "main", "type": 2, "returnType": 1,
        |      "prototyped": true, "linkage": "external", "storage": "unspecified",
        |      "p": [0, 2, 5], "start": [0, 2, 1], "defined": true, "params": [],
        |      "body": {
        |        "k": "block", "p": [0, 2, 16], "end": [0, 2, 28],
        |        "stmts": [
        |          { "k": "return", "p": [0, 2, 18], "end": [0, 2, 26],
        |            "expr": { "k": "constant", "t": 1, "p": [0, 2, 25], "ck": "integer", "value": "0" } }
        |        ]
        |      }
        |    }
        |  ],
        |  "diagnostics": []
        |}""".stripMargin
  end cannedUnit

  /** Runs `test` with edga replaced by a compiled program that logs the arguments of every run and
    * exports the canned unit through `--edga-out`, in a directory of its own: the unit and the log
    * sit next to the stub, none of it inside the project the parse walks. The test reads the log to
    * prove the runner's command line reached a program that parsed it.
    *
    * The stub is compiled, not scripted: the runner's command line carries parentheses (a
    * `--define_macro` value such as `_Noreturn=__attribute__((noreturn))`) that a batch file's
    * `for` loop breaks on, and a script that misreads it exits 0 with an output file of no bytes,
    * which the runner reads as no export. A compiled program receives each argument as one word,
    * as edga does. The compiler is `gcc`, `clang` or `cc`, and on Windows, where none of those may
    * be installed, the .NET Framework's `csc`.
    */
  private def withStubEdga(dir: File)(test: File => Unit): Unit =
    File.usingTemporaryDirectory("edg2atom-edga-stub") { stubDir =>
      (stubDir / "edga-stub-unit.json").write(cannedUnit(dir))
      val stub = compileStub(stubDir)
      assume(
        stub.isDefined,
        "no compiler for the edga stub: the suite builds one from C, or from C# on Windows"
      )
      val saved = sys.props.get("edga.path")
      sys.props("edga.path") = stub.get.pathAsString
      try test(stubDir)
      finally saved match
          case Some(p) => sys.props("edga.path") = p
          case None    => sys.props.remove("edga.path")
    }
  end withStubEdga

  /** The stub, compiled from C, or from C# where Windows has no C compiler on the `PATH`. */
  private def compileStub(dir: File): Option[File] =
    val stub   = dir / (if isWin then "edga-stub.exe" else "edga-stub")
    val source = dir / "edga-stub.c"
    source.write(StubSource)
    val fromC = Seq("gcc", "clang", "cc")
        .exists(cc => runs(Seq(cc, "-o", stub.pathAsString, source.pathAsString)))
    val built =
        if fromC then true
        else if isWin then
          val csharp = dir / "edga-stub.cs"
          csharp.write(StubSourceCSharp)
          cscCompiler.exists(csc =>
              runs(Seq(csc, "/nologo", s"/out:${stub.pathAsString}", csharp.pathAsString))
          )
        else false
    if built then
      stub.toJava.setExecutable(true)
      Some(stub)
    else None
  end compileStub

  /** Windows's own C# compiler, in the .NET Framework the Windows directory ships. */
  private def cscCompiler: Option[String] = Seq(
    "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe",
    "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe"
  ).find(p => new java.io.File(p).isFile)

  /** Runs `command` to completion, true when it exits 0: whether the compiler is there and took
    * the invocation.
    */
  private def runs(command: Seq[String]): Boolean =
    try
      val process = new ProcessBuilder(command*).redirectErrorStream(true).start()
      process.getInputStream.readAllBytes()
      if process.waitFor(2, TimeUnit.MINUTES) then process.exitValue() == 0
      else
        process.destroyForcibly()
        false
    catch case _: Exception => false

  /** The stub's evidence that the runner's command line reached it whole: its log names the file
    * to write behind `--edga-out` and the unit last, each as the single argument the runner sent.
    * A stub that parsed none of the line leaves the output file empty, which the runner reads as no
    * export, and nothing lands in the graph.
    */
  private def checkStubLog(log: File): Unit =
    assume(log.exists, s"the stub never ran: no argument log at ${log.pathAsString}")
    val args = log.lineIterator.toSeq
    args should contain("== invocation ==")
    withClue("the stub found no --edga-out argument in the runner's command line: ") {
      val i = args.indexOf("--edga-out")
      i should be > 0
      args(i + 1) should endWith(".json")
    }
    args should contain("--edga-root")
    args.filter(_.endsWith("main.c")) should not be empty
    args should not contain "no --edga-out"
    args should not contain "no unit file"
  end checkStubLog

  "a project header the exporter's root check misses" should {
      "still be written, named by its real path in the project" in {
          project(main, header) { dir =>
              withStubEdga(dir) { stubDir =>
                  graph(dir) { cpg =>
                    val h = cpg.method.nameExact("h").filter(_.block.astChildren.nonEmpty).l
                    h.size shouldBe 1
                    h.head.filename shouldBe "proj_hdr.h"
                    // the unit itself is unaffected
                    cpg.method.nameExact("main").filter(_.block.astChildren.nonEmpty).size shouldBe 1
                  }
                  checkStubLog(stubDir / "edga-stub-argv.log")
              }
          }
      }
  }

  /** The stub, in C. It finds the canned unit and its log next to itself, answers
    * `--edga-version`, and copies the unit over the file the argument behind `--edga-out` names.
    */
  private val StubSource: String =
    """#include <stdio.h>
      |#include <stdlib.h>
      |#include <string.h>
      |
      |static char *sibling(const char *arg0, const char *name) {
      |  static char path[4096];
      |  size_t n = strlen(arg0);
      |  while (n > 0 && arg0[n - 1] != '/' && arg0[n - 1] != '\\') n--;
      |  if (n + strlen(name) + 1 > sizeof path) return NULL;
      |  memcpy(path, arg0, n);
      |  memcpy(path + n, name, strlen(name) + 1);
      |  return path;
      |}
      |
      |static void note(const char *arg0, const char *text) {
      |  const char *logPath = sibling(arg0, "edga-stub-argv.log");
      |  FILE *log = logPath == NULL ? NULL : fopen(logPath, "a");
      |  if (log != NULL) {
      |    fprintf(log, "%s\n", text);
      |    fclose(log);
      |  }
      |}
      |
      |int main(int argc, char **argv) {
      |  const char *out = NULL;
      |  int i;
      |  {
      |    const char *logPath = sibling(argv[0], "edga-stub-argv.log");
      |    FILE *log = logPath == NULL ? NULL : fopen(logPath, "a");
      |    if (log != NULL) {
      |      fputs("== invocation ==\n", log);
      |      for (i = 0; i < argc; i++) fprintf(log, "%s\n", argv[i]);
      |      fclose(log);
      |    }
      |  }
      |  if (argc > 1 && strcmp(argv[1], "--edga-version") == 0) {
      |    puts("edga-stub");
      |    return 0;
      |  }
      |  for (i = 1; i + 1 < argc; i++)
      |    if (strcmp(argv[i], "--edga-out") == 0) {
      |      out = argv[i + 1];
      |      break;
      |    }
      |  if (out == NULL) {
      |    note(argv[0], "no --edga-out");
      |    return 4;
      |  }
      |  {
      |    const char *unit = sibling(argv[0], "edga-stub-unit.json");
      |    FILE *src = unit == NULL ? NULL : fopen(unit, "rb");
      |    FILE *dst = fopen(out, "wb");
      |    char buffer[8192];
      |    size_t chunk;
      |    while (src != NULL && (chunk = fread(buffer, 1, sizeof buffer, src)) > 0)
      |      fwrite(buffer, 1, chunk, dst);
      |    if (src != NULL) fclose(src);
      |    if (dst != NULL) fclose(dst);
      |    if (src == NULL) note(argv[0], "no unit file");
      |    return src == NULL || dst == NULL ? 5 : 0;
      |  }
      |}
      |""".stripMargin

  /** The same stub, in C#, for the hosts where no C compiler is installed. */
  private val StubSourceCSharp: String =
    """// The same stand-in, compiled by csc where no C compiler is installed.
      |using System;
      |using System.IO;
      |using System.Reflection;
      |
      |class EdgaStub
      |{
      |    static int Main(string[] args)
      |    {
      |        string dir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
      |        string logPath = Path.Combine(dir, "edga-stub-argv.log");
      |        using (StreamWriter log = new StreamWriter(logPath, true))
      |        {
      |            log.WriteLine("== invocation ==");
      |            foreach (string arg in args) log.WriteLine(arg);
      |        }
      |        if (args.Length > 1 && args[1] == "--edga-version")
      |        {
      |            Console.WriteLine("edga-stub");
      |            return 0;
      |        }
      |        string outPath = null;
      |        for (int i = 0; i + 1 < args.Length; i++)
      |            if (args[i] == "--edga-out") { outPath = args[i + 1]; break; }
      |        if (outPath == null)
      |        {
      |            File.AppendAllText(logPath, "no --edga-out" + Environment.NewLine);
      |            return 4;
      |        }
      |        string unitPath = Path.Combine(dir, "edga-stub-unit.json");
      |        if (!File.Exists(unitPath))
      |        {
      |            File.AppendAllText(logPath, "no unit file" + Environment.NewLine);
      |            return 5;
      |        }
      |        File.Copy(unitPath, outPath, true);
      |        return 0;
      |    }
      |}
      |""".stripMargin
end EdgShortNameAttributionTests
