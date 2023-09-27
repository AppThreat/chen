#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import subprocess
import sys

import oras.client

import chenpy.config as config
from chenpy.client import ChenDistributionRegistry
from chenpy.logger import LOG, console
from chenpy.utils import USE_SHELL, get_version, max_memory, unzip_unsafe

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
        if sys.platform == "win32":
            LOG.info(
                "To run chennai console, set the following user environment variables:"
            )
        else:
            LOG.info(
                "To run chennai console, add the following environment variables to your .zshrc or .bashrc:"
            )
        console.print(
            f"""export JAVA_OPTS="-Xmx{max_memory}"\nexport SCALAPY_PYTHON_LIBRARY={py_version}\nexport CHEN_HOME={config.chen_home}\nexport PATH=$PATH{os.pathsep}{platform_dir + os.pathsep + platform_bin_dir + os.pathsep}"""
        )
        if not os.getenv("JAVA_HOME"):
            LOG.info(
                "Ensure Java >= 17 up to 20 is installed. Set the environment variable JAVA_HOME to point the correct java directory."
            )
        try:
            import networkx
        except Exception:
            LOG.info(
                "Scientific dependencies missing. Please refer to the documentation to install the science pack or use the official chen container image."
            )
        LOG.info(
            "After setting the values, restart the terminal and type chennai to launch the console."
        )
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


def download_chen_distribution(overwrite=False):
    if os.path.exists(os.path.join(config.chen_home, "platform")):
        if not overwrite:
            fix_envs()
            return
        LOG.debug(
            "Existing chen distribution at %s would be overwritten", config.chen_home
        )
    LOG.debug(
        "About to download chen distribution from %s", config.chen_distribution_url
    )
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
            install_science_modules()
        fix_envs()


def install_science_modules():
    """
    Install the required science modules
    """
    LOG.debug("About to install the science pack using cpu-only configuration")
    req_file = os.path.join(config.chen_home, "chen-science-requirements.txt")
    if os.path.exists(req_file):
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-r", req_file],
            stdout=subprocess.DEVNULL,
            shell=USE_SHELL,
        )


def main():
    """
    Detects the project type, performs various scans and audits,
    and generates reports based on the results.
    """
    args = build_args()
    download_chen_distribution(args.download)


if __name__ == "__main__":
    main()
