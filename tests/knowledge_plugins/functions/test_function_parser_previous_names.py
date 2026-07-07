#!/usr/bin/env python3
# pylint: disable=missing-class-docstring
"""Regression test: parse_from_cmsg assigned the protobuf RepeatedScalarContainer
directly to Function.previous_names instead of converting it to a plain list.
This breaks pickling of Function objects.
"""

from __future__ import annotations

import pickle
import tempfile
import unittest

import angr
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions.function import Function


class TestFunctionParserPreviousNames(unittest.TestCase):
    def test_parsed_previous_names_is_plain_list_and_picklable(self):
        blob = bytes.fromhex("c3")  # ret
        addr = 0x400000

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(blob)
            blob_path = f.name

        proj = angr.Project(
            blob_path,
            main_opts={
                "backend": "blob",
                "base_addr": addr,
                "arch": "AMD64",
                "entry_point": addr,
            },
            auto_load_libs=False,
        )

        fm = proj.kb.functions
        func = fm.function(addr=addr, create=True)
        assert func is not None
        func._register_node(True, BlockNode(addr, 1, bytestr=blob))
        func.name = "original_name"
        func.name = "renamed"  # records "original_name" in previous_names
        self.assertIn("original_name", func.previous_names)
        expected = list(func.previous_names)

        cmsg = func.serialize_to_cmessage()
        loaded = Function.parse_from_cmessage(cmsg, function_manager=fm, project=proj)

        # previous_names must be a plain list, not a live protobuf container
        self.assertIs(type(loaded.previous_names), list)
        self.assertEqual(loaded.previous_names, expected)

        # mutating the parsed function must not alias back into the cmsg
        loaded.previous_names.append("another_name")
        self.assertEqual(list(cmsg.previous_names), expected)

        # the parsed function must round-trip through pickle
        unpickled = pickle.loads(pickle.dumps(loaded))
        self.assertEqual(unpickled.previous_names, [*expected, "another_name"])


if __name__ == "__main__":
    unittest.main()
