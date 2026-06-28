# Tests for progressive cross-function argument struct type inference in the decompiler.
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.sim_type import SimStruct, SimTypePointer, TypeRef
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


def _pointee_struct(ty):
    if not isinstance(ty, SimTypePointer):
        return None
    pts = ty.pts_to
    while isinstance(pts, TypeRef):
        pts = pts.ty
    return pts if isinstance(pts, SimStruct) else None


class TestCrossFunctionArgTypes(unittest.TestCase):
    def _project(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "cross_function_struct")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions()
        return proj, cfg

    def test_caller_unions_partial_callee_structs(self):
        proj, cfg = self._project()

        # decompile the three callees first so their partial argument layouts are recovered and stored
        for fn in ("func_a", "func_b", "func_c"):
            proj.analyses.Decompiler(cfg.functions[fn], cfg=cfg.model)

        dec = proj.analyses.Decompiler(cfg.functions["caller"], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # the shared pointer in the caller must be typed as a pointer to the unioned struct
        varman = proj.kb.dec_variables["caller"]
        struct_ptrs = [
            _pointee_struct(varman.get_variable_type(v))
            for v in varman._variables
            if _pointee_struct(varman.get_variable_type(v)) is not None
        ]
        assert struct_ptrs, "no struct pointer recovered in the caller"
        union = max(struct_ptrs, key=lambda s: len(s.offsets))
        # struct A { int x@0; int y@4; long z@8; int w@16; } -> the union must contain all four fields
        offsets = sorted(union.offsets.values())
        assert offsets == [0, 4, 8, 16], (offsets, union.fields)

    def test_union_propagated_back_to_callees(self):
        proj, cfg = self._project()

        for fn in ("func_a", "func_b", "func_c"):
            proj.analyses.Decompiler(cfg.functions[fn], cfg=cfg.model)
        proj.analyses.Decompiler(cfg.functions["caller"], cfg=cfg.model)

        # after the caller is decompiled, every callee's first argument should be upgraded to the unioned struct
        for fn in ("func_a", "func_b", "func_c"):
            proto = cfg.functions[fn].prototype
            assert proto is not None and proto.args
            struct = _pointee_struct(proto.args[0])
            assert struct is not None, (fn, proto.args[0])
            assert sorted(struct.offsets.values()) == [0, 4, 8, 16], (fn, struct.fields)

        # re-decompiling a callee now renders the complete struct
        dec = proj.analyses.Decompiler(cfg.functions["func_c"], cfg=cfg.model, regen_clinic=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        # func_c reads z (offset 8) and w (offset 16) as fields of the unioned struct
        assert "->field_8" in dec.codegen.text and "->field_10" in dec.codegen.text, dec.codegen.text


if __name__ == "__main__":
    unittest.main()
