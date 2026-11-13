#!/usr/bin/env python3
# Tests for argument-struct unions that must stay off raw pointer parameters (cross-function argument type inference).
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.sim_type import SimStruct, SimTypePointer, TypeRef
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# leaves first, then the functions passing pointers to them, as BinaryDecompiler's first pass does
CALLEES_FIRST = ("conn_head", "conn_tail", "save_bytes", "hash_bytes", "conn_both", "hash_obj", "serve")


def _pointee_struct(ty) -> SimStruct | None:
    if not isinstance(ty, SimTypePointer):
        return None
    pts = ty.pts_to
    while isinstance(pts, TypeRef):
        pts = pts.ty
    return pts if isinstance(pts, SimStruct) else None


def _real_offsets(struct: SimStruct) -> set[int]:
    return {off for name, off in struct.offsets.items() if not name.startswith("padding_")}


class TestUnionRawPointerParams(unittest.TestCase):
    def _decompile(self, names=CALLEES_FIRST):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "union_raw_pointer_params_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions()
        decs = {}
        for name in names:
            decs[name] = proj.analyses.Decompiler(cfg.functions[name], cfg=cfg.model, fail_fast=True)
            assert decs[name].codegen is not None and decs[name].codegen.text is not None, name
        return proj, cfg, decs

    def test_forwarders_without_dereference_get_no_union(self):
        _, cfg, _ = self._decompile()

        # save_bytes only hands src to memcpy, hash_obj only hands p to hash_bytes, which indexes it as bytes
        for name, arg_idx in (("save_bytes", 1), ("hash_obj", 0)):
            proto = cfg.functions[name].prototype
            assert proto is not None and len(proto.args) > arg_idx, name
            assert _pointee_struct(proto.args[arg_idx]) is None, (name, proto)

        # conn_both only passes c on as well, but its callees dereference it: it keeps the whole struct
        proto = cfg.functions["conn_both"].prototype
        assert proto is not None and proto.args
        struct = _pointee_struct(proto.args[0])
        assert struct is not None, proto
        assert _real_offsets(struct) == {0, 4, 8, 16, 24}, struct.fields


if __name__ == "__main__":
    unittest.main()
