#!/usr/bin/env bash

set -euo pipefail

export PATH=/opt/miniconda3/bin:${PATH}
conda config --set always_yes yes --set changeps1 no
conda config --add channels conda-forge
conda config --set solver classic
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r

conda install -y \
  -c conda-forge \
  python=3.12 \
  networkx \
  scipy \
  numpy \
  packageurl-python \
  nbconvert \
  jupyter_core \
  jupyter_client \
  notebook \
  requests \
  tqdm \
  oras-py \
  httpx \
  websockets \
  orjson \
  rich \
  appdirs \
  psutil \
  gitpython

python -m pip install -U pip poetry

# The upstream pytorch Conda channel does not publish pytorch/torchtext for
# linux-aarch64. Install CPU wheels instead so both amd64 and arm64 images can
# build from the same script. torchtext CPU wheels are currently published for
# linux x86_64, but not linux aarch64, and chen does not require torchtext at
# import/runtime in the container build path.
python -m pip install --index-url https://download.pytorch.org/whl/cpu "torch>=2.5.1,<3"

case "$(uname -m)" in
  x86_64|amd64)
    python -m pip install --index-url https://download.pytorch.org/whl/cpu --no-deps "torchtext==0.18.0+cpu"
    ;;
  aarch64|arm64)
    echo "Skipping torchtext: no linux-aarch64 CPU wheel is published by PyTorch."
    ;;
  *)
    echo "Skipping torchtext: unsupported architecture $(uname -m)."
    ;;
esac
