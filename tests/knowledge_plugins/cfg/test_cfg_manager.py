#!/usr/bin/env python3
from __future__ import annotations
from unittest import main, TestCase

from angr.knowledge_plugins.cfg import CFGManager


class TestCFGManager(TestCase):
    def setUp(self):
        self.cfg_manager = CFGManager(None)

    def test_when_both_cfg_emulated_and_cfg_fast_are_present(self):
        self.cfg_manager["CFGEmulated"] = "fake CFGEmulated"
        self.cfg_manager["CFGFast"] = "fake CFGFast"

        result = self.cfg_manager.get_most_accurate()
        self.assertEqual(result, "fake CFGEmulated")

    def test_when_only_cfg_emulated_is_present(self):
        self.cfg_manager["CFGEmulated"] = "fake CFGEmulated"

        result = self.cfg_manager.get_most_accurate()
        self.assertEqual(result, "fake CFGEmulated")

    def test_when_only_cfg_fast_is_present(self):
        self.cfg_manager["CFGFast"] = "fake CFGFast"

        result = self.cfg_manager.get_most_accurate()
        self.assertEqual(result, "fake CFGFast")

    def test_when_no_cfg_is_present(self):
        result = self.cfg_manager.get_most_accurate()
        self.assertEqual(result, None)


if __name__ == "__main__":
    main()
