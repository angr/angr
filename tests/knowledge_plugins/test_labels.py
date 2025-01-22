#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from tests.common import bin_location


test_location = os.path.join(bin_location, "tests")


class LabelsTests(unittest.TestCase):
    """
    Basic Labels knowledge plugin tests
    """

    def test_get_unique_label(self):
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(binpath, auto_load_libs=False)

        assert proj.kb.labels.get_unique_label("authenticate") != "authenticate"


if __name__ == "__main__":
    unittest.main()
