from __future__ import annotations

import pickle
import unittest

import angr
from angr.analyses.decompiler.cross_function_type_inference import CrossFunctionTypeInference
from angr.analyses.decompiler.struct_union import pointer_to_layout
from angr.enums import Flavors
from angr.sim_type import SimTypeInt


class TestCrossFunctionInferenceState(unittest.TestCase):
    def test_flavors_do_not_share_evidence_or_pushed_arguments(self):
        project = angr.load_shellcode(b"\xc3", arch="amd64")
        function = project.kb.functions.function(addr=0, create=True)

        def context(flavor):
            return CrossFunctionTypeInference(project, project.kb, function, flavor)

        pseudocode = context(Flavors.DEFAULT_FLAVOR)
        go = context(Flavors.GO_FLAVOR)
        layout = pointer_to_layout(
            {0: SimTypeInt().with_arch(project.arch), 8: SimTypeInt().with_arch(project.arch)}, project.arch
        )
        ref, _ = pseudocode._union_of_evidence([layout])
        pushed = angr.sim_type.SimTypePointer(ref).with_arch(project.arch)
        pseudocode._state.pushed_arg_unions[(0, 0)] = pushed
        assert pseudocode.pushed_union_for_argument(0) is pushed
        assert go.pushed_union_for_argument(0) is None
        for table in (
            "own_arg_layouts",
            "own_local_layouts",
            "pushed_arg_unions",
            "arg_downward_evidence",
            "arg_accessed_fields",
            "global_union_contributors",
            "union_struct_evidence",
            "weak_layouts",
            "weak_layout_cache",
        ):
            assert getattr(pseudocode._state, table) is not getattr(go._state, table), table
            assert getattr(context(Flavors.DEFAULT_FLAVOR)._state, table) is getattr(pseudocode._state, table), table
        assert not go._is_minted_union_type(pushed)

    def test_session_evidence_is_discarded_on_copy_and_serialization(self):
        project = angr.load_shellcode(b"\xc3", arch="amd64")
        function = project.kb.functions.function(addr=0, create=True)
        inference = CrossFunctionTypeInference(project, project.kb, function, Flavors.DEFAULT_FLAVOR)
        layout = pointer_to_layout({0: SimTypeInt().with_arch(project.arch)}, project.arch)
        inference._state.own_arg_layouts[(0, 0)] = layout
        copied = project.kb.types.copy()
        restored = pickle.loads(pickle.dumps(project.kb.types))
        assert not copied._cross_function_inference
        assert not restored._cross_function_inference
        assert inference._state.own_arg_layouts[(0, 0)] is layout


if __name__ == "__main__":
    unittest.main()
