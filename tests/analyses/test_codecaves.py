from unittest import main, TestCase
import os.path

import angr
from angr.analyses.codecave import CodeCaveClassification


TEST_LOCATION = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(TEST_LOCATION, "x86_64", "fauxware")


class TestCodeCaveAnalysis(TestCase):
    def test_function_aligments(self):
        p = angr.Project(FAUXWARE, auto_load_libs=False)
        p.analyses.CFGFast(normalize=True)
        result = p.analyses.CodeCaves()
        assert [
            c for c in result.codecaves if c.addr == 0x400634 and c.classification == CodeCaveClassification.ALIGNMENT
        ]

    def test_unreachable(self):
        p = angr.load_shellcode(
            """
            _start:
                push rbp
                mov rbp, rsp
                call func_1
                pop rbp
                ret
        
            func_0:
                xor rax, rax
                ret
        
            func_1:
                mov rax, 1
                ret
            """,
            "amd64",
        )
        p.analyses.CFGFast()
        result = p.analyses.CodeCaves()
        assert len([c for c in result.codecaves if c.classification == CodeCaveClassification.UNREACHABLE]) == 1


if __name__ == "__main__":
    main()
