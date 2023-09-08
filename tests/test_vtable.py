# pylint: disable=missing-class-docstring,no-self-use,line-too-long

import os
import unittest

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestVtable(unittest.TestCase):
    def test_vtable_extraction_x86_64(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "cpp_classes"), auto_load_libs=False)
        vtables_sizes = {0x403CB0: 24, 0x403CD8: 16, 0x403CF8: 16, 0x403D18: 16}
        vtable_analysis = p.analyses.VtableFinder()
        vtables = vtable_analysis.vtables_list

        assert len(vtables) == 4

        for vtable in vtables:
            assert vtable.vaddr in [0x403CB0, 0x403CD8, 0x403CF8, 0x403D18]
            assert vtables_sizes[vtable.vaddr] == vtable.size


if __name__ == "__main__":
    unittest.main()
