from __future__ import annotations

import platform
from os.path import dirname, join

from pybind11.setup_helpers import Pybind11Extension
from setuptools import setup

try:
    import pyvex
    PYVEX_LIB_DIR = join(dirname(pyvex.__file__), "lib")
    PYVEX_INCLUDE_DIR = join(dirname(pyvex.__file__), "include")
except ImportError:
    PYVEX_LIB_DIR = None
    PYVEX_INCLUDE_DIR = None

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
            library_dirs=[PYVEX_LIB_DIR],
            libraries=["pyvex"],
            cxx_std=17,
            # FIXME: This is a workaround for duplicate symbols originating from
            # sim_unicorn.hpp, included in both sim_unicorn.cpp and pymodule.cpp.
            extra_link_args=["/FORCE:MULTIPLE"] if platform.system() == "Windows" else [],
        ),
    ],
)
