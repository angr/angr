# Tests for cross-function recovery of global data structure types in the decompiler: every function touches a
# different member of the same global object, and the decompiler must combine what it learns across functions.
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from angr.sim_type import SimStruct, SimTypePointer, TypeRef
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

# struct settings { int verbose@0; char *name@8; long limit@16; int flags@24; }
SETTINGS_OFFSETS = {0, 8, 16, 24}
G_SETTINGS = 0x404040
G_CURRENT = 0x404060


def _resolve(ty):
    while isinstance(ty, TypeRef):
        ty = ty.ty
    return ty


def _struct(ty) -> SimStruct | None:
    ty = _resolve(ty)
    if isinstance(ty, SimTypePointer):
        ty = _resolve(ty.pts_to)
    return ty if isinstance(ty, SimStruct) else None


def _real_offsets(struct: SimStruct) -> set[int]:
    return {off for name, off in struct.offsets.items() if not name.startswith("padding_")}


class TestGlobalStructFields(unittest.TestCase):
    def _decompile_all(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "global_struct_fields")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions()
        order = (
            "set_verbose",
            "get_name",
            "bump_limit",
            "has_flag",
            "cur_verbose",
            "cur_limit",
            "cur_flags",
            "use_current",
            "main",
        )
        decs = {}
        # two rounds, callees first: the second round is what a user re-opening a function sees once every
        # function has contributed what it knows about the globals
        for regen in (False, True):
            for fn in order:
                decs[fn] = proj.analyses.Decompiler(cfg.functions[fn], cfg=cfg.model, regen_clinic=regen)
                assert decs[fn].codegen is not None and decs[fn].codegen.text is not None
        return proj, cfg, decs

    def _global_var(self, proj, addr):
        gm = proj.kb.dec_variables["global"]
        matches = [v for v in gm._variables if getattr(v, "addr", None) == addr]
        assert matches, f"no global variable recovered at {addr:#x}"
        return gm, matches[0]

    def test_global_struct_by_value_is_one_object_with_every_member(self):
        proj, _, decs = self._decompile_all()

        # g_settings is one 32-byte object (the symbol says so); four functions each touch one member
        gm, var = self._global_var(proj, G_SETTINGS)
        struct = _struct(gm.get_variable_type(var))
        assert struct is not None, (var, gm.get_variable_type(var))
        assert _real_offsets(struct) >= SETTINGS_OFFSETS, struct.fields

        # no accessor may see its member as a separate scalar global at an interior address
        for fn in ("set_verbose", "get_name", "bump_limit", "has_flag"):
            text = decs[fn].codegen.text
            print_decompilation_result(decs[fn])
            for interior in (G_SETTINGS + 8, G_SETTINGS + 16, G_SETTINGS + 24):
                assert f"g_{interior:x}" not in text, (fn, text)
            assert re.search(r"g_settings\.(field_[0-9a-f]+|verbose|name|limit|flags)", text), (fn, text)

    def test_global_struct_pointer_unions_across_callees(self):
        proj, cfg, decs = self._decompile_all()

        # g_current is passed to three callees that each read a different member: its pointee must carry all three,
        # and main adds the fourth (name @8)
        gm, var = self._global_var(proj, G_CURRENT)
        ty = gm.get_variable_type(var)
        assert isinstance(_resolve(ty), SimTypePointer), (var, ty)
        struct = _struct(ty)
        assert struct is not None, (var, ty)
        assert _real_offsets(struct) >= SETTINGS_OFFSETS, struct.fields

        # and the union reaches every callee's prototype
        for fn in ("cur_verbose", "cur_limit", "cur_flags"):
            proto = cfg.functions[fn].prototype
            assert proto is not None and proto.args, fn
            callee_struct = _struct(proto.args[0])
            assert callee_struct is not None, (fn, proto)
            assert {0, 16, 24} <= _real_offsets(callee_struct), (fn, callee_struct.fields)

        # every function that touches g_current declares it with the same struct pointer type
        names = set()
        for fn in ("use_current", "main"):
            text = decs[fn].codegen.text
            print_decompilation_result(decs[fn])
            m = re.search(r"extern (\w+) \*g_current;", text)
            assert m, (fn, text)
            names.add(m.group(1))
        assert len(names) == 1, names


if __name__ == "__main__":
    unittest.main()
