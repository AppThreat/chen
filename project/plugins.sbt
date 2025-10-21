addSbtPlugin("com.simplytyped" % "sbt-antlr4"           % "0.8.3")
addSbtPlugin("com.github.sbt"  % "sbt-native-packager"  % "1.11.1")
addSbtPlugin("org.scalameta"   % "sbt-scalafmt"         % "2.5.4")
addSbtPlugin("com.codecommit"  % "sbt-github-packages"  % "0.5.3")
addSbtPlugin("com.eed3si9n"    % "sbt-assembly"         % "2.3.1")

libraryDependencies += "ai.kien" %% "python-native-libs" % "0.2.5"
