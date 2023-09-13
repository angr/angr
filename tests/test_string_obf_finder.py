from unittest import TestCase, main

import os

import angr
from angr.analyses import deobfuscator

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

        # this is a Windows 64-bit binary!
        angr.DEFAULT_CC["AMD64"] = angr.calling_conventions.SimCCMicrosoftAMD64
        angr.calling_conventions.CC["AMD64"] = [angr.calling_conventions.SimCCMicrosoftAMD64]

        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions(recover_variables=True, workers=4)

        # it will update kb.obfuscations
        finder = proj.analyses.StringObfuscationFinder()

        dec = proj.analyses.Decompiler(proj.kb.functions[0x140005174])
        print(dec.codegen.text)
        dec = proj.analyses.Decompiler(proj.kb.functions[0x140006208])
        print(dec.codegen.text)


if __name__ == "__main__":
    main()
