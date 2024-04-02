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


class TestAPIObfFinder(TestCase):
    def test_smoketest(self):
        bin_path = os.path.join(
            binaries_base, "x86_64", "windows", "fc7a8e64d88ad1d8c7446c606731901063706fd2fb6f9e237dda4cb4c966665b.sys"
        )

        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)

        proj.analyses.CompleteCallingConventions(recover_variables=True, workers=4)

        # it will update kb.obfuscations
        finder = proj.analyses.APIObfuscationFinder()
        assert finder.type1_candidates
        assert proj.kb.obfuscations.type1_deobfuscated_apis


if __name__ == "__main__":
    # main()
    TestAPIObfFinder().test_smoketest()
