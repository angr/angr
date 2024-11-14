"""
Configures pytest to include binary paths for use with pytest-insta.
"""

# pylint: disable=import-error,missing-function-docstring
from __future__ import annotations
import pytest


def pytest_addoption(parser):
    parser.addoption("--binary", action="store", default="")


@pytest.fixture
def binary(request):
    return request.config.getoption("--binary")
