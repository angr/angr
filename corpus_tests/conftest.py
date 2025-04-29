"""
Configures pytest to include binary paths for use with pytest-insta.
"""

# pylint: disable=import-error,missing-function-docstring
from __future__ import annotations
import os
import glob
import re
import pytest_insta.utils

regex = re.compile("corpus__decompilation__(.*)__[0-9a-f]*.txt")

bin_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "snapshots")


def pytest_addoption(parser):
    parser.addoption("--binaries", nargs="+")


def pytest_generate_tests(metafunc):
    if "binary" in metafunc.fixturenames:
        binaries = metafunc.config.getoption("--binaries")
        if not binaries:
            globbed = glob.glob("**/*.txt", recursive=True, root_dir=bin_location)
            binaries = {re.sub(regex, "\\1", x).replace("__", "/") for x in globbed if re.match(regex, x)}
        metafunc.parametrize("binary", binaries)


# monkeypatch pytest-insta to make the snapshot paths more parsable


def normalize_node_name(name: str) -> str:
    return re.sub("[][/]", "__", re.sub(r"^(tests?[_/])*|([_/]tests?)*(\.\w+)?$", "", name)).strip("_")


pytest_insta.utils.normalize_node_name = normalize_node_name
