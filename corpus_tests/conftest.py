"""
Configures pytest to include binary paths for use with pytest-insta.
"""

# pylint: disable=import-error,missing-function-docstring
from __future__ import annotations
import os
import pytest

bin_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "dec-test-corpus")


def pytest_addoption(parser):
    parser.addoption("--binary", action="store", default="")


@pytest.fixture
def binary(request):
    return os.path.join(bin_location, request.config.getoption("--binary"))
