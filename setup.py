from __future__ import annotations

import os.path
import importlib
import importlib.resources

from setuptools import setup

# Import setuptools_rust to ensure an error is raised if not installed
try:
    _ = importlib.import_module("setuptools_rust")
except ImportError as err:
    raise Exception("angr requires setuptools-rust to build") from err


PYVEX_INCLUDE_PATH = str(importlib.resources.files("pyvex").joinpath("include"))
PYVEX_LIB_PATH = str(importlib.resources.files("pyvex").joinpath("lib"))

CMAKE_SOURCE_DIR = str(os.path.join(os.path.dirname(__file__), "native", "unicornlib"))
CMAKE_ARGS = [f"-DPYVEX_INCLUDE_PATH={PYVEX_INCLUDE_PATH}", f"-DPYVEX_LIB_PATH={PYVEX_LIB_PATH}"]

setup(
    cmake_source_dir=CMAKE_SOURCE_DIR,
    cmake_args=CMAKE_ARGS,
)
