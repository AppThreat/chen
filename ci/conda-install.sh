#!/usr/bin/env bash

export PATH=/opt/miniconda3/bin:${PATH}:
pip install -U pip poetry
conda config --set always_yes yes --set changeps1 no
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r
conda install -c conda-forge networkx -y
conda install -c conda-forge scipy numpy -y
conda install -c pytorch pytorch torchtext cpuonly -y
conda install -c conda-forge packageurl-python nbconvert jupyter_core jupyter_client notebook -y
conda install -c conda-forge oras-py httpx websockets orjson rich appdirs psutil gitpython -y
