#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.factory.block"  # pylint:disable=redefined-builtin

import logging
import unittest
import os

import angr

from ...common import bin_location


test_location = os.path.join(bin_location, "tests")
l = logging.getLogger("angr.tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestBlockCache(unittest.TestCase):
    def test_block_cache(self):
        p = angr.Project(
            os.path.join(test_location, "x86_64", "fauxware"), translation_cache=True, auto_load_libs=False
        )
        b = p.factory.block(p.entry)
        assert p.factory.block(p.entry).vex is b.vex

        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), translation_cache=False)
        b = p.factory.block(p.entry)
        assert p.factory.block(p.entry).vex is not b.vex


if __name__ == "__main__":
    unittest.main()
