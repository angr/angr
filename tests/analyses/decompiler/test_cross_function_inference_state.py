from __future__ import annotations

import unittest

import angr
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.decompiler.struct_union import pointer_to_layout
from angr.enums import Flavors
from angr.sim_type import SimTypeInt


class TestCrossFunctionInferenceState(unittest.TestCase):
    def test_flavors_do_not_share_evidence_or_pushed_arguments(self):
        project = angr.load_shellcode(b"\xc3", arch="amd64")
        function = project.kb.functions.function(addr=0, create=True)

        def context(flavor):
            clinic = Clinic.__new__(Clinic)
            clinic.project = project
            clinic.kb = project.kb
            clinic.function = function
            clinic.flavor = flavor
            return clinic

        pseudocode = context(Flavors.DEFAULT_FLAVOR)
        go = context(Flavors.GO_FLAVOR)
        layout = pointer_to_layout({0: SimTypeInt().with_arch(project.arch), 8: SimTypeInt().with_arch(project.arch)}, project.arch)
        ref, _ = pseudocode._union_of_evidence([layout])
        pushed = angr.sim_type.SimTypePointer(ref).with_arch(project.arch)
        pseudocode._pushed_arg_unions[(0, 0)] = pushed
        assert pseudocode._pushed_union_for_argument(0) is pushed
        assert go._pushed_union_for_argument(0) is None
        for table in (
            "_own_arg_layouts", "_own_local_layouts", "_pushed_arg_unions", "_arg_downward_evidence",
            "_arg_accessed_fields", "_global_union_contributors", "_union_struct_evidence", "_weak_layouts",
            "_weak_layout_cache",
        ):
            assert getattr(pseudocode, table) is not getattr(go, table), table
            assert getattr(context(Flavors.DEFAULT_FLAVOR), table) is getattr(pseudocode, table), table
        assert not go._is_minted_union_type(pushed)


if __name__ == "__main__":
    unittest.main()
