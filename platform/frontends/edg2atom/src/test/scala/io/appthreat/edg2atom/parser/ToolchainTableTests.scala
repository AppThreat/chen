package io.appthreat.edg2atom.parser

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.CompileDatabase
import io.appthreat.c2cpg.parser.ProjectSources
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Path
import java.nio.file.Paths

/** The macros the edga command line gives a translation unit of another toolchain: the driver
  * table's fallback macros must reach the front end for every toolchain fixture, so the unit
  * preprocesses without reaching its `#error`. The edga binary itself is not needed here: the
  * command line is read before it is run.
  */
class ToolchainTableTests extends AnyWordSpec with Matchers:

  private val fixtures = Seq(
    ("nvcc", "vec_add.cu", Set("__CUDACC__", "__NVCC__", "__GNUC__")),
    ("icx", "simd_dot.c", Set("__INTEL_LLVM_COMPILER", "__clang__")),
    ("icpx", "simd_dot.cpp", Set("__INTEL_LLVM_COMPILER", "__clang__")),
    ("emcc", "wasm_entry.c", Set("__EMSCRIPTEN__", "__clang__")),
    ("empp", "wasm_entry.cpp", Set("__EMSCRIPTEN__", "__clang__")),
    ("zig-cc", "clang_guarded.c", Set("__clang__")),
    ("zig-cpp", "clang_guarded.cpp", Set("__clang__")),
    ("tcc", "small_kernel.c", Set("__TINYC__")),
    ("armclang", "cortex_m_irq.c", Set("__ARMCC_VERSION", "__clang__")),
    ("iccarm", "arm_irq.c", Set("__ICCARM__")),
    ("armcl", "ti_arm_task.c", Set("__TI_ARM__", "__TI_COMPILER_VERSION__")),
    ("cl430", "msp430_blink.c", Set("__MSP430__", "__TI_COMPILER_VERSION__")),
    ("clang-cl-mode", "msvc_mode.cpp", Set("_MSC_VER", "__clang__")),
    ("arm-none-eabi-gcc", "bare_metal_delay.c", Set("__GNUC__", "__arm__")),
    ("ccache", "cached_build.c", Set("__GNUC__"))
  )

  "the edga command line" should {
      "define every fixture's identifying macros, from the table or the compiler it runs" in {
          fixtures.foreach { (name, source, macros) =>
              withClue(s"$name: ") {
                  val dir = fixtureDir(name)
                  val config = Config()
                      .withInputPath(dir.toString)
                      .withCompileCommands(dir.resolve(CompileDatabase.FileName).toString)
                  val runner  = new EdgaRunner(config, new ProjectSources(config))
                  val args    = runner.arguments(dir.resolve(source))
                  val defined = definedMacros(args)
                  (defined should contain).allElementsOf(macros)
              }
          }
      }

      "preprocess a toolchain unit as the language its driver compiles it as" in {
          val dir = fixtureDir("nvcc")
          val config = Config()
              .withInputPath(dir.toString)
              .withCompileCommands(dir.resolve(CompileDatabase.FileName).toString)
          val runner = new EdgaRunner(config, new ProjectSources(config))
          val args   = runner.arguments(dir.resolve("vec_add.cu"))
          // a .cu unit is preprocessed as C++, with the host compiler's macros plus nvcc's own
          args should contain("--c++17")
      }

      "emulate the dialect the driver table's entry names, not only the macros' reading" in {
          // clang in MSVC driver mode: its macros carry __clang__, whose own reading would give
          // the clang emulation, but the entry names the Microsoft one
          val clArgs = argumentsFor("clang-cl-mode", "msvc_mode.cpp")
          clArgs should contain("--microsoft")
          clArgs should contain("--microsoft_version=1940")
          clArgs should not contain "--clang"
          // a clang-based toolchain without an override is emulated as clang, from the table's
          // clang macros
          argumentsFor("armclang", "cortex_m_irq.c") should contain("--clang")
          // and a compiler the front end has no emulation of keeps the front end's default
          // dialect: no emulation flag at all
          val tccArgs = argumentsFor("tcc", "small_kernel.c")
          Seq("--clang", "--gcc", "--g++", "--microsoft").foreach(flag =>
              withClue(s"$flag: ") { tccArgs should not contain flag }
          )
      }
  }

  /** The front end's arguments for one fixture unit. */
  private def argumentsFor(name: String, source: String): Seq[String] =
    val dir = fixtureDir(name)
    val config = Config()
        .withInputPath(dir.toString)
        .withCompileCommands(dir.resolve(CompileDatabase.FileName).toString)
    new EdgaRunner(config, new ProjectSources(config)).arguments(dir.resolve(source))

  private def fixtureDir(name: String): Path = Paths.get(
    getClass.getClassLoader.getResource(s"toolchains/$name").toURI
  )

  /** The macros the arguments define: the ones of the preinclude macro file, plus the ones the
    * command line itself carries.
    */
  private def definedMacros(arguments: Seq[String]): Set[String] =
    val fromArguments = arguments.zipWithIndex.collect {
        case ("--define_macro", i) =>
            arguments(i + 1).takeWhile(c => c.isLetterOrDigit || c == '_')
    }.toSet
    val fromFile = arguments.zipWithIndex
        .collectFirst { case ("--preinclude_macros", i) => arguments(i + 1) }
        .toSeq
        .flatMap { path =>
          val source = scala.io.Source.fromFile(path, "UTF-8")
          try source.getLines().toSeq
          finally source.close()
        }
        .collect {
            case line if line.startsWith("#define ") =>
                line.stripPrefix("#define ").takeWhile(c => c.isLetterOrDigit || c == '_')
        }
        .toSet
    fromArguments ++ fromFile
  end definedMacros
end ToolchainTableTests
