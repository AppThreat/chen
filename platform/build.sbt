name := "platform"

BareBuildSyntax.dependsOn(Projects.dataflowengineoss, Projects.x2cpg)

libraryDependencies ++= Seq(
  "io.appthreat"     %% "cpg2"        % Versions.cpg,
  "com.lihaoyi"      %% "requests"    % Versions.requests,
  "com.github.scopt" %% "scopt"       % "4.1.0",
  "org.reflections"   % "reflections" % "0.10.2",
  "org.scalatest"    %% "scalatest"   % Versions.scalatest % Test
)

Test / compile := Def.uncached {
    (Test / compile).dependsOn((Projects.c2cpg / stage), (Projects.jssrc2cpg / stage)).value
}
Test / fork := false

enablePlugins(JavaAppPackaging, UniversalPlugin)

//wildcard import from staged `lib` dir, for simplicity and also to avoid `line too long` error on windows
scriptClasspath := Seq("*")

topLevelDirectory := Some(packageName.value)

Compile / packageDoc / mappings := Seq()

def frontendMappings(
    frontendName: String,
    stagedProject: File
)(using FileConverter): Seq[(HashedVirtualFileRef, String)] = {
    NativePackagerHelper.contentOf(stagedProject).map { case (file, name) =>
        summon[FileConverter].toVirtualFile(file.toPath) -> s"frontends/$frontendName/$name"
    }
}

// These frontends are defined once in project/Projects.scala; referencing them
// via Projects.* here keeps this directory's build.sbt free of duplicate
// project definitions, which sbt 2 cannot reconcile with the root ones.
Universal / mappings ++= frontendMappings("javasrc2cpg", (Projects.javasrc2cpg / stage).value)(using
  fileConverter.value
)
Universal / mappings ++= frontendMappings("c2cpg", (Projects.c2cpg / stage).value)(using
  fileConverter.value
)
Universal / mappings ++= frontendMappings("jssrc2cpg", (Projects.jssrc2cpg / stage).value)(using
  fileConverter.value
)
Universal / mappings ++= frontendMappings("jimple2cpg", (Projects.jimple2cpg / stage).value)(using
  fileConverter.value
)
Universal / mappings ++= frontendMappings("pysrc2cpg", (Projects.pysrc2cpg / stage).value)(using
  fileConverter.value
)

lazy val cpgVersionFile = taskKey[File]("persist cpg version in file (e.g. for schema-extender)")
cpgVersionFile := Def.uncached {
    val ret = target.value / "cpg-version"
    better.files
        .File(ret.getPath)
        .createIfNotExists(createParents = true)
        .writeText(Versions.cpg)
    ret
}
Universal / mappings += fileConverter.value.toVirtualFile(cpgVersionFile.value.toPath) -> "schema-extender/cpg-version"

Universal / packageBin / mappings ++= {
    val converter = fileConverter.value
    sbt.Path.directory(new File("platform/src/main/resources/scripts")).map { case (f, n) =>
        converter.toVirtualFile(f.toPath) -> n
    }
}

maintainer       := "cloud@appthreat.com"
githubOwner      := "appthreat"
githubRepository := "chen"
credentials +=
    Credentials(
      "GitHub Package Registry",
      "maven.pkg.github.com",
      "appthreat",
      sys.env.getOrElse("GITHUB_TOKEN", "N/A")
    )
