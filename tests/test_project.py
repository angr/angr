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

    def test_wsock32_import_uses_ws2_32_definition(self):
        binary = os.path.join(
            test_location,
            "i386",
            "windows",
            "064e1d62c8542d658d83f7e231cc3b935a1f18153b8aea809dcccfd446a91c93",
        )
        project = angr.Project(binary, auto_load_libs=False)
        relocation = project.loader.main_object.imports["gethostbyname"]
        assert relocation.symbol is not None
        assert relocation.symbol.resolvedby is not None
        procedure = project.hooked_by(relocation.symbol.resolvedby.rebased_addr)
        assert procedure is not None
        ws2_32 = angr.SIM_LIBRARIES["ws2_32.dll"][0]
        expected_procedure = ws2_32.get("gethostbyname", project.arch)

        self.assertEqual(relocation.resolvewith, "wsock32.dll")
        self.assertEqual(procedure.library_name, "ws2_32.dll")
        self.assertEqual(procedure.prototype, expected_procedure.prototype)
        self.assertIs(type(procedure.cc), type(expected_procedure.cc))


if __name__ == "__main__":
    unittest.main()
