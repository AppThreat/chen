#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import shutil
import sys
import zipfile

import oras.client
from oras.logger import logger, setup_logger
import pkg_resources

import chenpy.config as config


def get_version():
    """
    Returns the version of depscan
    """
    return pkg_resources.get_distribution("appthreat-chen").version


def unzip_unsafe(zf, to_dir):
    """Method to unzip the file in an unsafe manne"""
    with zipfile.ZipFile(zf, "r") as zip_ref:
        zip_ref.extractall(to_dir)
    shutil.rmtree(zf, ignore_errors=True)


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
        "-v",
        "--version",
        help="Display the version",
        action="version",
        version="%(prog)s " + get_version(),
    )
    return parser.parse_args()


def download_chen_distribution():
    oras_client = oras.client.OrasClient()
    paths_list = oras_client.pull(
        target=config.chen_distribution_url,
        outdir=config.chen_home,
        allowed_media_type=[],
        overwrite=True,
    )
    print(paths_list)


def main():
    """
    Detects the project type, performs various scans and audits,
    and generates reports based on the results.
    """
    args = build_args()
    if args.download:
        setup_logger(quiet=False, debug=True)
        download_chen_distribution()


if __name__ == "__main__":
    main()
