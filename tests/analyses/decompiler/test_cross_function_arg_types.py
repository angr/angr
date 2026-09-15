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


def _real_offsets(struct: SimStruct) -> set[int]:
    return {off for name, off in struct.offsets.items() if not name.startswith("padding_")}


class TestCrossFunctionArgTypes(unittest.TestCase):
    def _project(self, binary="cross_function_struct"):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", binary)
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

    def _decompile_struct2(self):
        proj, cfg = self._project("cross_function_struct2")
        callees = ("starts_with_dashes", "name_matches", "node_weight", "node_flags", "wide_sum")
        for fn in callees:
            proj.analyses.Decompiler(cfg.functions[fn], cfg=cfg.model)
        for fn in ("wide_head", "walk", "main"):
            proj.analyses.Decompiler(cfg.functions[fn], cfg=cfg.model)
        # a second round, as a user re-opening the callees would trigger, must keep every guarantee below
        decs = {}
        for fn in (*callees, "wide_head", "walk"):
            decs[fn] = proj.analyses.Decompiler(cfg.functions[fn], cfg=cfg.model, regen_clinic=True)
            assert decs[fn].codegen is not None and decs[fn].codegen.text is not None
        return proj, cfg, decs

    def test_library_prototypes_and_strings_stay_scalar(self):
        proj, cfg, decs = self._decompile_struct2()

        # strcmp is a library function: its prototype must never be rewritten from call-site evidence
        strcmp = cfg.functions["strcmp"]
        assert strcmp.prototype is not None
        assert _pointee_struct(strcmp.prototype.args[0]) is None, strcmp.prototype
        assert _pointee_struct(strcmp.prototype.args[1]) is None, strcmp.prototype

        # the string compared against a node name through strcmp stays a string in the callee ...
        proto = cfg.functions["name_matches"].prototype
        assert proto is not None and len(proto.args) >= 2
        assert _pointee_struct(proto.args[1]) is None, proto
        # ... while the node pointer next to it has picked up the fields the other callees see
        node = _pointee_struct(proto.args[0])
        assert node is not None, proto
        assert {16, 24, 32} <= _real_offsets(node), node.fields

        # a callee that reads s[0] and s[1] is reading a string, not a struct {char; char;}
        proto = cfg.functions["starts_with_dashes"].prototype
        assert proto is not None and proto.args
        assert _pointee_struct(proto.args[0]) is None, proto
        print_decompilation_result(decs["starts_with_dashes"])
        text = decs["starts_with_dashes"].codegen.text
        assert "ustruct" not in text and "field_1" not in text, text

        # the strings the caller passes down stay strings in the caller too
        walk_proto = cfg.functions["walk"].prototype
        assert walk_proto is not None and len(walk_proto.args) >= 3
        assert _pointee_struct(walk_proto.args[1]) is None, walk_proto
        assert _pointee_struct(walk_proto.args[2]) is None, walk_proto

    def test_union_never_takes_fields_away_from_a_callee(self):
        proj, cfg, decs = self._decompile_struct2()

        # wide_sum establishes all four fields on its own; wide_head only touches the first one. After wide_head is
        # decompiled, wide_sum's argument must still carry every field, and its output must still name them.
        proto = cfg.functions["wide_sum"].prototype
        assert proto is not None and proto.args
        wide = _pointee_struct(proto.args[0])
        assert wide is not None, proto
        assert {0, 8, 12, 16} <= _real_offsets(wide), wide.fields
        print_decompilation_result(decs["wide_sum"])
        text = decs["wide_sum"].codegen.text
        for field in ("field_8", "field_c", "field_10"):
            assert f"->{field}" in text, (field, text)

        # every union struct the output names is declared in that output
        for fn, dec in decs.items():
            text = dec.codegen.text
            for name in {m for m in _union_struct_names(text)}:
                assert f"typedef struct {name} " in text, (fn, name, text)


def _union_struct_names(text: str) -> set[str]:
    import re  # pylint:disable=import-outside-toplevel

    return set(re.findall(r"\b(ustruct_\d+)\b", text))


if __name__ == "__main__":
    unittest.main()
