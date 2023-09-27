#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os

import oras.client

import chenpy.config as config
from chenpy.client import ChenDistributionRegistry
from chenpy.logger import LOG
from chenpy.utils import get_version, unzip_unsafe

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
    if not os.getenv("CHEN_HOME"):
        os.environ["CHEN_HOME"] = config.chen_home
        os.environ["CLASSPATH"] = (
            find_jars(os.path.join(config.chen_home, "platform", "lib"))
            + os.pathsep
            + os.getenv("CLASSPATH", "")
        )
        os.environ["PATH"] = (
            os.environ["PATH"]
            + os.path.join(config.chen_home, "platform")
            + os.pathsep
            + os.path.join(config.chen_home, "platform", "bin")
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
        unzip_unsafe(paths_list[0], config.chen_home)
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
        fix_envs()


def main():
    """
    Detects the project type, performs various scans and audits,
    and generates reports based on the results.
    """
    args = build_args()
    download_chen_distribution(args.download)


if __name__ == "__main__":
    main()
