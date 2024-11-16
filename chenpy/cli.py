#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import shutil
import subprocess
import sys

import oras.client
from rich.progress import Progress

import chenpy.config as config
from chenpy.client import ChenDistributionRegistry
from chenpy.logger import LOG, console
from chenpy.utils import USE_SHELL, check_command, get_version, max_memory, unzip_unsafe

try:
    os.environ["PYTHONIOENCODING"] = "utf-8"
except Exception:
    pass


def build_args():
    """
    Constructs command line arguments for the chennai tool
    """
    parser = argparse.ArgumentParser(
        description="Code Hierarchy Exploration Net (chen)."
    )
    parser.add_argument(
        "--download",
        action="store_true",
        default=False,
        dest="download",
        help="Download the latest chen distribution in platform specific "
        "user_data_dir",
    )
    parser.add_argument(
        "--with-science",
        action="store_true",
        default=False,
        dest="science_pack",
        help="Download the science pack",
    )
    parser.add_argument(
        "--server",
        action="store_true",
        default=False,
        dest="server_mode",
        help="Start chen server",
    )
    parser.add_argument(
        "-v",
        "--version",
        help="Display the version",
        action="version",
        version="%(prog)s " + get_version(),
    )
    return parser.parse_args()


def find_jars(lib_dir):
    jars = []
    for dirname, subdirs, files in os.walk(lib_dir):
        for filename in files:
            if filename.endswith(".jar"):
                jars.append(os.path.join(dirname, filename))
    return ":".join(jars)


def fix_envs():
    if not os.getenv("CHEN_HOME") or config.chen_home not in os.getenv("PATH"):
        py_version = "python" + sys.version[:4]
        # On Windows, there is no dot
        if sys.platform == "win32":
            py_version = py_version.replace(".", "")
        platform_dir = os.path.join(config.chen_home, "platform")
        platform_bin_dir = os.path.join(config.chen_home, "platform", "bin")
        pylib_dir, lpy_version = detect_python_lib_path()
        if lpy_version and py_version != lpy_version:
            py_version = lpy_version
        if sys.platform == "win32":
            LOG.info(
                "To run chennai console, set the following user environment variables:"
            )
        else:
            LOG.info(
                "To run chennai console, add the following environment variables to your .zshrc or .bashrc:"
            )
        console.print(
            f'export JAVA_OPTS="-Xmx{max_memory}"\nexport JAVA_TOOL_OPTIONS="-Dfile.encoding=UTF-8 -Djna.library.path={pylib_dir}"\nexport SCALAPY_PYTHON_LIBRARY={py_version}\nexport CHEN_HOME="{config.chen_home}"\nexport PATH=$PATH{os.pathsep}"{platform_dir + os.pathsep + platform_bin_dir + os.pathsep}"'
        )
        if not os.getenv("JAVA_HOME"):
            LOG.info(
                "Ensure Java >= 21 is installed. Set the environment variable JAVA_HOME to point the correct "
                "java directory."
            )
        LOG.info(
            "After setting the values, restart the terminal and type chennai to launch the console."
        )
        os.environ[
            "JAVA_TOOL_OPTIONS"
        ] = f'"-Dfile.encoding=UTF-8 -Djna.library.path={pylib_dir}"'
        os.environ["SCALAPY_PYTHON_LIBRARY"] = py_version
        os.environ["CHEN_HOME"] = config.chen_home
        os.environ["CLASSPATH"] = (
            find_jars(os.path.join(config.chen_home, "platform", "lib"))
            + os.pathsep
            + os.getenv("CLASSPATH", "")
        )
        os.environ["PATH"] = (
            os.environ["PATH"] + platform_dir + os.pathsep + platform_bin_dir
        )


def download_chen_distribution(overwrite=False, science_pack=False):
    if os.path.exists(os.path.join(config.chen_home, "platform")):
        if not overwrite:
            if science_pack:
                install_py_modules("science")
            fix_envs()
            return
        LOG.debug(
            "Existing chen distribution at %s would be overwritten", config.chen_home
        )
    LOG.info(
        "About to download chen distribution from %s", config.chen_distribution_url
    )
    req_files = []
    oras_client = oras.client.OrasClient(registry=ChenDistributionRegistry())
    paths_list = oras_client.pull(
        target=config.chen_distribution_url,
        outdir=config.chen_home,
        allowed_media_type=[],
        overwrite=overwrite,
    )
    if paths_list:
        LOG.debug("Extracting chen to %s", config.chen_home)
        zip_files = [file for file in paths_list if file.endswith(".zip")]
        req_files = [file for file in paths_list if file.endswith(".txt")]
        if not zip_files:
            return
        unzip_unsafe(zip_files[0], config.chen_home)
        # Add execute permissions
        for dirname, subdirs, files in os.walk(config.chen_home):
            for filename in files:
                if (
                    not filename.endswith(".zip")
                    and not filename.endswith(".jar")
                    and not filename.endswith(".json")
                    and not filename.endswith(".dll")
                    and (
                        filename.endswith(".sh")
                        or "2cpg" in filename
                        or "chen" in filename
                        or "repl" in filename
                    )
                ):
                    try:
                        os.chmod(os.path.join(dirname, filename), 0o755)
                    except Exception:
                        pass
    # Install the science pack
    if req_files:
        install_py_modules("database")
    if science_pack:
        install_py_modules("science")
    fix_envs()


def install_py_modules(pack="database"):
    """
    Install the required science modules
    """
    if check_command("conda"):
        LOG.info(
            "About to install the science pack using conda. A new environment called 'chenpy-local' will be created."
        )
        with Progress(transient=True) as progress:
            conda_install_script = """conda create --name chenpy-local python=3.12 -y
conda install -n chenpy-local -c conda-forge networkx -y
conda install -n chenpy-local -c pytorch pytorch torchtext cpuonly -y
conda install -n chenpy-local -c conda-forge numpy packageurl-python nbconvert jupyter_core jupyter_client notebook -y
conda install -n chenpy-local -c conda-forge oras-py==0.1.26 httpx websockets orjson rich appdirs psutil gitpython -y"""
            for line in conda_install_script.split("\n"):
                if line.strip():
                    task = progress.add_task(line, start=False, total=100)
                    subprocess.check_call(
                        line.split(" "),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        shell=USE_SHELL,
                    )
                    progress.stop_task(task)
                    progress.update(task, completed=100)
        LOG.info(
            "Activate the conda environment using the command 'conda activate chenpy-local'"
        )
    else:
        LOG.info("About to install the science pack using cpu-only configuration")
        req_file = os.path.join(config.chen_home, f"chen-{pack}-requirements.txt")
        if os.path.exists(req_file):
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-r", req_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=USE_SHELL,
            )


def detect_python_lib_path():
    lib_dir = ""
    py_version = ""
    if sys.platform == "win32":
        python_exe_path = shutil.which("python")
        if python_exe_path:
            lib_dir = os.sep.join(python_exe_path.split(os.sep)[:-1])
            if lib_dir.endswith("Scripts") or os.getenv("VIRTUAL_ENV"):
                LOG.info(
                    "Unable to identify the directory containing python3.dll. Set the value for jna.library.path "
                    "in JAVA_TOOL_OPTIONS environment variable correctly."
                )
                lib_dir = ""
        return lib_dir, py_version
    cp = subprocess.run(
        ["python3-config", "--ldflags", "--embed"],
        check=True,
        capture_output=True,
        encoding="utf-8",
        shell=USE_SHELL,
    )
    if cp.returncode != 0:
        LOG.info("Unable to identify the python lib directory using python3-config")
        return lib_dir, py_version
    stdout = cp.stdout
    if stdout:
        tmpA = stdout.split(" ")
        if tmpA and len(tmpA) > 2:
            if tmpA[0].startswith("-L"):
                lib_dir = os.sep.join(tmpA[0].replace("-L", "").split(os.sep)[:-2])
            if tmpA[1].startswith("-l"):
                py_version = tmpA[1].replace("-l", "")
    return lib_dir, py_version


def main():
    """
    Detects the project type, performs various scans and audits,
    and generates reports based on the results.
    """
    args = build_args()
    download_chen_distribution(args.download, args.science_pack)


if __name__ == "__main__":
    main()
