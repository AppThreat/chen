#!/usr/bin/env bash

export PATH=/opt/miniconda3/bin:${PATH}:
conda config --set always_yes yes --set changeps1 no
pip install -U pip setuptools
eval "$(conda shell.bash activate chenpy)"
conda install -n chenpy -c conda-forge networkx -y
conda install -n chenpy -c pytorch pytorch torchtext cpuonly -y
pip install pyg_lib -f https://data.pyg.org/whl/torch-2.1.0+cpu.html
conda install -n chenpy -c conda-forge packageurl-python nbconvert jupyter_core jupyter_client notebook -y
conda install -n chenpy -c conda-forge httpx websockets orjson rich appdirs psutil gitpython -y
