addSbtPlugin("com.github.sbt"  % "sbt-native-packager" % "1.13.0")
addSbtPlugin("org.scalameta"   % "sbt-scalafmt"        % "2.6.2")
addSbtPlugin("com.eed3si9n"    % "sbt-assembly"        % "2.5.0")

// sbt-antlr4 and sbt-github-packages have no sbt 2.x builds; their slices are
// covered by project/Antlr4.scala and project/GithubPackages.scala instead.
