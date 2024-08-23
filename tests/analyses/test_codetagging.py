#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.code_tagging import CodeTags

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestCodetagging(unittest.TestCase):
    def test_hasxor(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "HashTest"), auto_load_libs=False)
        cfg = p.analyses.CFG()

        ct_rshash = p.analyses.CodeTagging(cfg.kb.functions["RSHash"])
        assert CodeTags.HAS_XOR not in ct_rshash.tags
        ct_jshash = p.analyses.CodeTagging(cfg.kb.functions["JSHash"])
        assert CodeTags.HAS_XOR in ct_jshash.tags
        assert CodeTags.HAS_BITSHIFTS in ct_jshash.tags
        ct_elfhash = p.analyses.CodeTagging(cfg.kb.functions["ELFHash"])
        assert CodeTags.HAS_BITSHIFTS in ct_elfhash.tags


if __name__ == "__main__":
    unittest.main()
