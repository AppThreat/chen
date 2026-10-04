package io.appthreat.c2cpg.parser

import io.appthreat.c2cpg.Config
import org.eclipse.cdt.core.CCorePlugin
import org.eclipse.core.runtime.IStatus
import org.osgi.framework.FrameworkUtil
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.io.{ByteArrayOutputStream, PrintStream}

/** CDT logs internal conditions through its plugin object, which c2cpg runs without an OSGi
  * runtime. A log call must neither throw (which lost the file being parsed) nor print to standard
  * output.
  */
class CdtLoggingTests extends AnyWordSpec with Matchers:

  "CDT's log" should {
      "be set up by the parser, with the bundle the OSGi lookup gives CDT's plugin" in {
          val parser = new CdtParser(Config(), new HeaderFileFinder(""))
          parser should not be null
          CCorePlugin.getDefault should not be null
          FrameworkUtil.getBundle(classOf[CCorePlugin]) shouldBe CdtCoreBundle
          CCorePlugin.getDefault.getBundle.getSymbolicName shouldBe CCorePlugin.PLUGIN_ID
          FrameworkUtil.getBundle(classOf[CdtLoggingTests]) shouldBe null
      }

      "accept messages and exceptions" in {
          CdtLogging.install()
          CdtLogging.installed shouldBe true
          noException should be thrownBy {
              CCorePlugin.log("a message")
              CCorePlugin.log(IStatus.WARNING, "a warning")
              CCorePlugin.log(new IllegalStateException("an exception"))
              CCorePlugin.log("a message and an exception", new RuntimeException("cause"))
          }
      }

      "go to the debug log, not standard output, while CDT runs" in {
          val saved = System.out
          val sink  = new ByteArrayOutputStream()
          System.setOut(new PrintStream(sink, true))
          try
            CdtLogging.install()
            CdtLogging.captured {
                CCorePlugin.log("logged while parsing", new RuntimeException("with a stack trace"))
                CdtLogging.captured(CCorePlugin.log("logged in a nested parse"))
            }
            System.out.println("printed by the caller")
          finally System.setOut(saved)
          val printed = sink.toString
          printed should include("printed by the caller")
          (printed should not).include("logged while parsing")
          (printed should not).include("with a stack trace")
          (printed should not).include("logged in a nested parse")
      }
  }

end CdtLoggingTests
