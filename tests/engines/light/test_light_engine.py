#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

from unittest import TestCase, main

from angr.engines.light.engine import longest_prefix_lookup


class TestLightEngine(TestCase):
    def test_unop_handler(self):

        def handle_unop_32to1():
            pass

        mapping = {
            "32to1": handle_unop_32to1,
        }

        assert longest_prefix_lookup("32to1", mapping) is handle_unop_32to1
        assert longest_prefix_lookup("32to1_foo", mapping) is handle_unop_32to1
        assert longest_prefix_lookup("32to", mapping) is None


if __name__ == "__main__":
    main()
