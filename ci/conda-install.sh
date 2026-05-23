#!/usr/bin/env bash

set -euo pipefail

export PATH=/opt/miniconda3/bin:${PATH}:
conda config --set always_yes yes --set changeps1 no
conda config --add channels conda-forge
conda config --set solver classic
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r

conda install -y \
  -c conda-forge \
  -c pytorch \
  python=3.12 \
  networkx \
  scipy \
  numpy \
  pytorch::pytorch \
  pytorch::torchtext \
  pytorch::cpuonly \
  packageurl-python \
  nbconvert \
  jupyter_core \
  jupyter_client \
  notebook \
  oras-py \
  httpx \
  websockets \
  orjson \
  rich \
  appdirs \
  psutil \
  gitpython

python -m pip install --no-cache-dir -U pip poetry
