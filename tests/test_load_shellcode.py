# pylint: disable=no-self-use,missing-class-docstring
from __future__ import annotations
import unittest

import angr


class TestLoadShellcode(unittest.TestCase):
    def test_simos(self):
        for os in "windows", "linux":
            p = angr.load_shellcode(b"\xc3", arch="x86", simos=os)
            p.factory.entry_state()


if __name__ == "__main__":
    unittest.main()
