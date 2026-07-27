# pylint: disable=no-self-use,missing-class-docstring
from __future__ import annotations

import unittest

import angr


class TestLoadShellcode(unittest.TestCase):
    def test_simos(self):
        for simos, arch in (
            ("linux", "x86"),
            ("windows", "x86"),
            ("windows", "amd64"),
            ("windows", "armel"),
            ("windows", "aarch64"),
        ):
            with self.subTest(simos=simos, arch=arch):
                project = angr.load_shellcode(b"\xc3", arch=arch, simos=simos)
                project.factory.entry_state()


if __name__ == "__main__":
    unittest.main()
