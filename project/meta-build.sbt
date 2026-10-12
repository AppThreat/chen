libraryDependencies ++= Seq(
  "com.typesafe"          % "config"       % "1.4.9",
  "com.michaelpollmeier"  % "versionsort"  % "1.0.17",
  "net.lingala.zip4j"     % "zip4j"        % "2.11.6",
  "com.github.pathikrit" %% "better-files" % "3.9.2",
  "net.java.dev.javacc"   % "javacc"       % "7.0.13",
  "com.lihaoyi"          %% "os-lib"       % "0.11.8",
  // ANTLR 4 tool used by project/Antlr4.scala to generate the dataflowengineoss
  // parser; the antlr4-runtime version (Versions.antlr) is read from this jar
  "org.antlr"             % "antlr4"       % "4.13.2"
)
