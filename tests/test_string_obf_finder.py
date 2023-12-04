from unittest import TestCase, main

import os

import angr
from angr.analyses import deobfuscator
from angr.sim_type import parse_signature

binaries_base = os.path.join(
    os.path.dirname(os.path.realpath(str(__file__))),
    "..",
    "..",
    "binaries",
    "tests",
)


class TestStringObfFinder(TestCase):
    def test_smoketest(self):
        bin_path = os.path.join(binaries_base, "x86_64", "netfilter_b64.sys")

        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)

        # sadly we do not yet have function prototypes for Windows kernel
        # gotta manually specify prototypes for a few Windows kernel APIs
        proj.kb.functions["PsLookupProcessByProcessId"].prototype = parse_signature(
            "int PsLookupProcessByProcessId(uint64_t a, uint64_t b);"
        ).with_arch(proj.arch)

        # also sadly we do not yet identify "__security_check_cookie" on Windows binaries
        # hard-code it for now
        proj.kb.functions[0x1400070B0].name = "_security_check_cookie"
        proj.kb.functions[0x1400070B0].is_default_name = False

        proj.analyses.CompleteCallingConventions(recover_variables=True, workers=4)

        # it will update kb.obfuscations
        finder = proj.analyses.StringObfuscationFinder()
        assert proj.kb.obfuscations.type1_deobfuscated_strings
        assert proj.kb.obfuscations.type2_deobfuscated_strings

        dec = proj.analyses.Decompiler(proj.kb.functions[0x140005174])
        print(dec.codegen.text)
        dec = proj.analyses.Decompiler(proj.kb.functions[0x1400035A0])
        print(dec.codegen.text)
        dec = proj.analyses.Decompiler(proj.kb.functions[0x140003504])
        print(dec.codegen.text)
        dec = proj.analyses.Decompiler(proj.kb.functions[0x140006208])
        print(dec.codegen.text)

    def test_find_obfuscated_strings_543991(self):
        bin_path = os.path.join(
            binaries_base, "x86_64", "windows", "543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91.sys"
        )

        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)

        proj.analyses.CompleteCallingConventions(recover_variables=True, workers=4)
        finder = proj.analyses.StringObfuscationFinder()

    def test_find_obfuscated_strings_28ce9d(self):
        bin_path = os.path.join(
            binaries_base, "x86_64", "windows", "28ce9dfc983d8489242743635c792d3fc53a45c96316b5854301f6fa514df55e.sys"
        )

        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions(recover_variables=True, workers=4)
        finder = proj.analyses.StringObfuscationFinder()

        dec = proj.analyses.Decompiler(proj.kb.functions[0x140004790])
        print(dec.codegen.text)


if __name__ == "__main__":
    main()
