# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations
from unittest import TestCase, main
import os

from tests.common import slow_test

import angr
from angr.sim_type import parse_signature

binaries_base = os.path.join(
    os.path.dirname(os.path.realpath(str(__file__))),
    "..",
    "..",
    "..",
    "binaries",
    "tests",
)


class TestStringObfFinder(TestCase):
    def test_netfilter_b64(self):
        # - type 1 string obfuscation: deobfuscator at 0x140001A90
        # - type 2 string obfuscation: deobfuscator at 0x140001A18

        bin_path = os.path.join(binaries_base, "x86_64", "netfilter_b64.sys")

        proj = angr.Project(bin_path, auto_load_libs=False)
        _ = proj.analyses.CFG(force_smart_scan=False, normalize=True, show_progressbar=True)

        # sadly we do not yet have function prototypes for Windows kernel
        # gotta manually specify prototypes for a few Windows kernel APIs
        proj.kb.functions["PsLookupProcessByProcessId"].prototype = parse_signature(
            "int PsLookupProcessByProcessId(uint64_t a, uint64_t b);"
        ).with_arch(proj.arch)

        # ensure we correctly recognize security_check_cookie
        assert proj.kb.functions[0x1400070B0].name == "_security_check_cookie"

        proj.analyses.CompleteCallingConventions(recover_variables=True)

        # it will update kb.obfuscations
        _ = proj.analyses.StringObfuscationFinder()
        assert proj.kb.obfuscations.type1_deobfuscated_strings
        assert proj.kb.obfuscations.type2_deobfuscated_strings

        dec = proj.analyses.Decompiler(proj.kb.functions[0x140005174])
        assert dec.codegen is not None and dec.codegen.text is not None
        # print(dec.codegen.text)
        assert '"explorer.exe"' in dec.codegen.text

        dec = proj.analyses.Decompiler(proj.kb.functions[0x140003504])
        assert dec.codegen is not None and dec.codegen.text is not None
        # print(dec.codegen.text)
        assert '"AutoConfigURL"' in dec.codegen.text

        dec = proj.analyses.Decompiler(proj.kb.functions[0x140006208])
        assert dec.codegen is not None and dec.codegen.text is not None
        # print(dec.codegen.text)
        assert '" HTTP/1.1\\r\\nHost: "' in dec.codegen.text

        dec = proj.analyses.Decompiler(proj.kb.functions[0x1400035A0])
        assert dec.codegen is not None and dec.codegen.text is not None
        # print(dec.codegen.text)
        assert "\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings" in dec.codegen.text

    @slow_test
    def test_find_obfuscated_strings_543991(self):
        bin_path = os.path.join(
            binaries_base, "x86_64", "windows", "543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91.sys"
        )

        proj = angr.Project(bin_path, auto_load_libs=False)
        _ = proj.analyses.CFG(force_smart_scan=False, normalize=True, show_progressbar=False)

        proj.analyses.CompleteCallingConventions(recover_variables=True)
        finder = proj.analyses.StringObfuscationFinder()

        assert not finder.type1_candidates
        assert not finder.type2_candidates
        assert not finder.type3_candidates

    @slow_test
    def test_find_obfuscated_strings_28ce9d(self):
        # - type 3 string obfuscation
        bin_path = os.path.join(
            binaries_base, "x86_64", "windows", "28ce9dfc983d8489242743635c792d3fc53a45c96316b5854301f6fa514df55e.sys"
        )

        proj = angr.Project(bin_path, auto_load_libs=False)
        _ = proj.analyses.CFG(force_smart_scan=False, normalize=True, show_progressbar=False)
        proj.analyses.CompleteCallingConventions(recover_variables=True)
        _ = proj.analyses.StringObfuscationFinder()

        dec = proj.analyses.Decompiler(proj.kb.functions[0x140004790])
        assert dec.codegen is not None and dec.codegen.text is not None
        # print(dec.codegen.text)
        assert "socket create false\\n" in dec.codegen.text
        assert "connet false\\n" in dec.codegen.text
        assert "message Size err\\n" in dec.codegen.text

    @slow_test
    def test_find_obfuscated_strings_dd5640(self):
        # - type 3 string obfuscation
        bin_path = os.path.join(
            binaries_base, "x86_64", "windows", "dd56403d14ffe220a645a964a19f8b488e200b84ae5a414b0c020b561ae40880.sys"
        )

        proj = angr.Project(bin_path, auto_load_libs=False)
        _ = proj.analyses.CFG(force_smart_scan=False, normalize=True, show_progressbar=False)
        proj.analyses.CompleteCallingConventions(recover_variables=True)
        _ = proj.analyses.StringObfuscationFinder()

        dec = proj.analyses.Decompiler(proj.kb.functions[0x1400017E8])
        assert dec.codegen is not None and dec.codegen.text is not None
        # print(dec.codegen.text)
        assert "IsWhitelist->RvStrJson=%s\\\\n" in dec.codegen.text
        assert "0xda" not in dec.codegen.text and "218" not in dec.codegen.text


if __name__ == "__main__":
    main()
