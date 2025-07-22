# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

import angr
from angr.analyses.decompiler import Decompiler
from angr.analyses.decompiler.notes.deobfuscated_strings import DeobfuscatedStringsNote
from angr.sim_type import parse_signature

from tests.common import bin_location, print_decompilation_result


binaries_base = os.path.join(bin_location, "tests")


class TestDecompilationNotes(unittest.TestCase):
    """
    Tests for decompilation notes.
    """

    def test_decompilation_notes_obfuscated_string_netfilter_b64(self):
        """
        Test that decompilation notes are correctly generated.
        """

        bin_path = os.path.join(binaries_base, "x86_64", "netfilter_b64.sys")

        proj = angr.Project(bin_path, auto_load_libs=False)
        _ = proj.analyses.CFG(force_smart_scan=False, normalize=True, show_progressbar=True)

        proj.kb.functions["PsLookupProcessByProcessId"].prototype = parse_signature(
            "int PsLookupProcessByProcessId(uint64_t a, uint64_t b);"
        ).with_arch(proj.arch)

        # ensure we correctly recognize security_check_cookie
        assert proj.kb.functions[0x1400070B0].name == "_security_check_cookie"

        proj.analyses.CompleteCallingConventions(recover_variables=True)

        _ = proj.analyses.StringObfuscationFinder(fail_fast=True)
        assert proj.kb.obfuscations.type1_deobfuscated_strings
        assert proj.kb.obfuscations.type2_deobfuscated_strings

        dec = proj.analyses[Decompiler].prep(fail_fast=True)(
            proj.kb.functions[0x140005174], options=[("display_notes", True)]
        )
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert "// Obfuscated strings are found in decompilation and have been deobfuscated:" in dec.codegen.text
        assert dec.codegen.text.count("explorer.exe") == 2
        assert "deobfuscated_strings" in dec.notes
        assert dec.notes["deobfuscated_strings"] is not None
        the_note = dec.notes["deobfuscated_strings"]
        assert isinstance(the_note, DeobfuscatedStringsNote)
        assert len(the_note.strings) == 1

        dec = proj.analyses[Decompiler].prep(fail_fast=True)(
            proj.kb.functions[0x140003504], options=[("display_notes", True)]
        )
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert "// Obfuscated strings are found in decompilation and have been deobfuscated:" in dec.codegen.text
        assert '"AutoConfigURL"' in dec.codegen.text

        dec = proj.analyses[Decompiler].prep(fail_fast=True)(
            proj.kb.functions[0x140006208], options=[("display_notes", True)]
        )
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert "// Obfuscated strings are found in decompilation and have been deobfuscated:" in dec.codegen.text
        assert '" HTTP/1.1\\r\\nHost: "' in dec.codegen.text

        dec = proj.analyses[Decompiler].prep(fail_fast=True)(
            proj.kb.functions[0x1400035A0], options=[("display_notes", True)]
        )
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert "// Obfuscated strings are found in decompilation and have been deobfuscated:" in dec.codegen.text
        assert "\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings" in dec.codegen.text


if __name__ == "__main__":
    unittest.main()
