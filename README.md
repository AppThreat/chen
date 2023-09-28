# chen

Code Hierarchy Exploration Net (chen) is an advanced exploration toolkit for your application source code and its dependency hierarchy.

[![chennai demo](https://asciinema.org/a/hwDt9f8ED9WmXeiLS90a9en2Y.svg)](https://asciinema.org/a/hwDt9f8ED9WmXeiLS90a9en2Y)

## Requirements

- Java 17 - 20
- Python > 3.8.1
- Node.js > 16 (To run [atom](https://github.com/AppThreat/atom))
- Minimum 16GB RAM

## Installation

```shell
# Install atom
sudo npm install -g @appthreat/atom

# Install chen from pypi
pip install appthreat-chen
```

To download the chen distribution including the science pack.

```shell
chen --download
```

Once the download finishes, the command will display the download location along with the environment variables that need to be set to invoke `chennai` console. Example output below:

```shell
[21:53:36] INFO     To run chennai console, add the following environment variables to your .zshrc or .bashrc:
export JAVA_OPTS="-Xmx16G"
export SCALAPY_PYTHON_LIBRARY=python3.10
export CHEN_HOME=/home/user/.local/share/chen
export PATH=$PATH:/home/user/.local/share/chen/platform:/home/user/.local/share/chen/platform/bin:
```

## Running the console

Type `chennai` to launch the console.

```shell
chennai
```

```shell

 _                          _   _   _   _  __
/  |_   _  ._  ._   _. o   |_  / \ / \ / \  / |_|_
\_ | | (/_ | | | | (_| |   |_) \_/ \_/ \_/ /    |


Version: 0.0.7
Type `help` to begin


chennai>
```

## Sample commmands

### Help command

```shell
chennai> help
val res0: Helper = Welcome to the interactive help system. Below you find a table of all available
top-level commands. To get more detailed help on a specific command, just type

`help.<command>`.

Try `help.importCode` to begin with.
_______________________________________________________________________________________________________________________________________________________________
command          | description                                                               | example                                                       |
==============================================================================================================================================================|
annotations      | List annotations                                                          | annotations                                                   |
close            | Close project by name                                                     | close(projectName)                                            |
declarations     | List declarations                                                         | declarations                                                  |
distance         | Show graph edit distance from the source method to the comparison methods | distance(source method iterator, comparison method iterators) |
exit             | Exit the REPL                                                             |                                                               |
files            | List files                                                                | files                                                         |
importAtom       | Create new project from existing atom                                     | importAtom("app.atom")                                        |
importCode       | Create new project from code                                              | importCode("example.jar")                                     |
imports          | List imports                                                              | imports                                                       |
methods          | List methods                                                              | methods('Methods', includeCalls=true, tree=true)              |
sensitive        | List sensitive literals                                                   | sensitive                                                     |
showSimilar      | Show methods similar to the given method                                  | showSimilar(method full name)                                 |
summary          | Display summary information                                               | summary                                                       |
```

Refer to the documentation site to learn more about the commands.

## Languages supported

- C/C++ (Requires Java 17 or above)
- H (C/C++ Header files alone)
- Java (Requires compilation)
- Jar
- Android APK (Requires Android SDK. Set the environment variable `ANDROID_HOME`)
- JavaScript
- TypeScript
- Python

## Origin of chen

chen is a fork of the popular [joern](https://github.com/joernio/joern) project. We deviate from the joern project in the following ways:

- Make code analysis accessible by adding first-class integration with Python and frameworks such as NetworkX and PyTorch
- Enable broader hierarchical analysis (Application + Dependency + Container + OS layer)
- By creating a more welcoming community more appropriate for beginner users with great support

## License

Apache-2.0

## Enterprise support

Enterprise support including custom language development and integration services is available via AppThreat Ltd. Free community support is also available via [Discord](https://discord.gg/UD4sHgbXYr).
