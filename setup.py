from __future__ import annotations

from os.path import dirname, join

import pyvex
from pybind11.setup_helpers import Pybind11Extension
from setuptools import setup

PYVEX_INCLUDE_DIR = join(dirname(pyvex.__file__), "include")
VENDOR_INCLUDE_DIR = join(dirname(__file__), "native", "unicornlib", "vendor")

setup(
    ext_modules=[
        Pybind11Extension(
            "angr.unicornlib",
            [
                "native/unicornlib/pymodule.cpp",
                "native/unicornlib/sim_unicorn.cpp",
                "native/unicornlib/unicorn_dynamic.cpp",
            ],
            include_dirs=[PYVEX_INCLUDE_DIR, VENDOR_INCLUDE_DIR],
            cxx_std=17,
        ),
    ],
)
