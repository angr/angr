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

    def test_copy(self):
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(binpath, auto_load_libs=False)

        labels = proj.kb.labels
        addr = labels.lookup("authenticate")
        assert addr is not None
        # a label that the loader does not know about, and the removal of one that it does
        labels[0xDEAD0000] = "custom_label"
        del labels[labels.lookup("main")]
        original_items = dict(labels.items())
        original_names = set(labels)

        copied = labels.copy()
        assert isinstance(copied, angr.knowledge_plugins.Labels)
        assert copied is not labels
        assert dict(copied.items()) == original_items
        assert set(copied) == original_names
        assert copied.lookup("custom_label") == 0xDEAD0000
        assert copied.lookup("main") is None

        # mutating the copy does not affect the original
        copied[0xDEAD1000] = "copy_only_label"
        del copied[addr]
        assert dict(labels.items()) == original_items
        assert set(labels) == original_names
        assert labels.lookup("copy_only_label") is None
        assert labels[addr] == "authenticate"

        # ... and vice versa
        labels[0xDEAD2000] = "original_only_label"
        assert 0xDEAD2000 not in copied
        assert copied.lookup("original_only_label") is None


if __name__ == "__main__":
    unittest.main()
