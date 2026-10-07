#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.errors import AngrValueError
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestProject(unittest.TestCase):
    def test_negative_entry_is_rejected(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        proj.loader.main_object._custom_entry_point = -1
        with self.assertRaises(AngrValueError):
            angr.Project(proj.loader)


if __name__ == "__main__":
    unittest.main()
