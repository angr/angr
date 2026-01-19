# pylint:disable=no-self-use
from __future__ import annotations
import os
import unittest

import angr

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestTraceClassifier(unittest.TestCase):
    """
    TraceClassifier tests
    """

    def test_not_smc_shellcode(self):
        """
        Simple not-self-modifying shellcode.
        """
        code_src = """
                        mov rax, 0xdeadbeef
                        ret
                   """
        p = angr.load_shellcode(code_src, "amd64", selfmodifying_code=True)
        is_smc = p.analyses.SMC(p.entry).result
        assert not is_smc

    def test_smc_shellcode(self):
        """
        Simple self-modifying shellcode.
        """
        code_src = """
                        inc dword ptr [here+1]
                        here:
                        mov rax, 0xdeadbeef
                        ret
                   """
        p = angr.load_shellcode(code_src, "amd64", selfmodifying_code=True)
        is_smc = p.analyses.SMC(p.entry).result
        assert is_smc

    def test_smc_buffer(self):
        """
        Evaluate a binary that allocates a buffer, writes code to that buffer, then runs it.
        """
        p = angr.Project(os.path.join(test_location, "x86_64", "smc"), selfmodifying_code=True, auto_load_libs=False)
        is_smc = p.analyses.SMC("main").result
        assert is_smc


def main():
    unittest.main()


if __name__ == "__main__":
    main()
