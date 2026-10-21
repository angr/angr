#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestStackBufferTypes(unittest.TestCase):
    """
    Stack buffers whose only uses are their addresses passed to callees. The callees are decompiled first so that
    their recovered parameter types (char *) reach the callers, as the corpus snapshot run does.
    """

    def _decompile(self, binary: str, callee: int, caller: int) -> str:
        bin_path = os.path.join(test_location, "x86_64", "cgc-linux64", binary)
        proj, cfg = load_project_with_scoped_cfg(bin_path, callee, extra_func_addrs=[caller])
        for addr in (callee, caller):
            dec = proj.analyses.Decompiler(proj.kb.functions[addr], cfg=cfg.model, options=[("show_casts", False)])
            assert dec.codegen is not None and dec.codegen.text is not None
            print_decompilation_result(dec)
        return dec.codegen.text

    def test_buffer_passed_to_memset_and_a_char_pointer_callee(self):
        # cgc_receiveBalance: a 1 KB buffer handed to memset (char as sint8) and to cgc_recvline (char *): the two
        # bounds meet at a char array of the slot size
        text = self._decompile("Music_Store_Client", 0x401530, 0x401EB0)
        m = re.search(r"char (\w+)\[1036\];", text)
        assert m is not None, text
        assert f"memset({m.group(1)}, 0, 0x400);" in text, text

    def test_int_followed_by_a_char_array_passed_at_an_offset(self):
        # cgc_check: int len; char buf[64]; with &buf passed to cgc_receive_delim(char *). the char at offset 4 of
        # the pointee types the whole slot as a char array rather than leaving it to its raw 6-byte size
        text = self._decompile("Palindrome2", 0x401240, 0x401420)
        assert "uint48_t" not in text, text
        m = re.search(r"char (\w+)\[68\];", text)
        assert m is not None, text
        assert f"cgc_receive_delim(0, &{m.group(1)}[4], 128, 10)" in text, text


if __name__ == "__main__":
    unittest.main()
