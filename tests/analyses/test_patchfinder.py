# pylint:disable=missing-class-docstring,no-self-use,pointless-string-statement
from __future__ import annotations
from unittest import main, TestCase
import os.path

import angr


TEST_LOCATION = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(TEST_LOCATION, "x86_64", "fauxware")


class TestPatchFinderAnalysis(TestCase):
    def test_overlapping_functions(self):
        p = angr.load_shellcode(
            """
            _start:
                push rbp;
                mov rbp, rsp;
                jmp over;          # Looks like a patch

            unreachable:
                inc rax;
                pop rbp;
                ret;

            over:
                call called_func
                xor rax, rax;
                pop rbp;
                ret;

            non_overlapping:
                mov rax, rdi;
                inc rax;
                ret

            called_func:
                ret
            """,
            "amd64",
        )
        p.analyses.CFGFast(normalize=True)
        r = p.analyses.PatchFinder()
        assert len(r.possibly_patched_out) == 1

    def test_alignment(self):
        p = angr.load_shellcode(
            bytes.fromhex(
                "554889e5e8070000005dc34831c0c390"
                + "c3909090909090909090909090909090"
                + "c3909090909090909090909090909090"
                + "c3909090909090909090909090909090"
                + "c3909090909090909090909090909090"
                + "c3909090909090909090909090909090"
                + "c3909090909090909090909090909090"
                + "c3909090909090909090909090909090"
                + "c3909090909090909090909090909090"
                + "c3909090909090909090909090909090"
                + "c3"
            ),
            "amd64",
        )
        """
        bits 64
        align 16
        func_0:
            push rbp
            mov rbp, rsp
            call func_1
            pop rbp
            ret

        unaligned_func:
            xor rax, rax
            ret

        %macro simple_func 1
        align 16
        func_%1:
            ret
        %endmacro
        %assign i 1
        %rep 10
        simple_func i
        %assign i i+1
        %endrep
        """
        r = p.analyses.CFGFast(normalize=True)
        r = p.analyses.PatchFinder()
        assert len(r.atypical_alignments) == 1


if __name__ == "__main__":
    main()
