# Tests for global variable type inference in the decompiler.
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.sim_type import (
    SimStruct,
    SimTypeChar,
    SimTypeInt,
    SimTypePointer,
    TypeRef,
)
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


def _unwrap(ty):
    return ty.ty if isinstance(ty, TypeRef) else ty


class TestGlobalTypeInference(unittest.TestCase):
    def _analyze(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "global_type_inference")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions()

        # Decompile every user function so that inferred global types accumulate in the project KB.
        for func in cfg.functions.values():
            if func.is_simprocedure or func.is_plt or func.is_syscall or func.is_alignment:
                continue
            if func.name in {"_start", "frame_dummy", "register_tm_clones", "deregister_tm_clones"}:
                continue
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
            if dec.codegen is not None:
                print_decompilation_result(dec)
        return proj

    def _global_type(self, proj, name):
        sym = proj.loader.find_symbol(name)
        assert sym is not None, f"symbol {name} not found"
        gm = proj.kb.dec_variables["global"]
        variables = gm.get_global_variables(sym.rebased_addr)
        assert variables, f"no global variable recovered at {name} ({sym.rebased_addr:#x})"
        var = next(iter(variables))
        return _unwrap(gm.get_variable_type(var))

    def test_primitive_globals(self):
        proj = self._analyze()

        t_int = self._global_type(proj, "g_int")
        assert isinstance(t_int, SimTypeInt) and t_int.size == 32, t_int

        t_char = self._global_type(proj, "g_char")
        assert isinstance(t_char, SimTypeChar) and t_char.size == 8, t_char

        t_long = self._global_type(proj, "g_long")
        assert t_long.size == 64, t_long

        t_ptr = self._global_type(proj, "g_ptr")
        assert isinstance(t_ptr, SimTypePointer), t_ptr

    def test_struct_global(self):
        proj = self._analyze()

        t_pt = self._global_type(proj, "g_pt")
        assert isinstance(t_pt, SimStruct), t_pt
        # struct point { int x; int y; long z; } -> fields at offsets 0, 4, 8
        offsets = sorted(t_pt.offsets.values())
        assert offsets == [0, 4, 8], (offsets, t_pt.fields)
        sizes = [t_pt.fields[name].size for name in t_pt.fields]
        assert sizes == [32, 32, 64], (sizes, t_pt.fields)

    def test_struct_global_field_access_in_codegen(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "global_type_inference")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions()

        func = cfg.functions["init_pt"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text

        # The struct must not be split into separate synthetic globals.
        assert "g_404064" not in text and "g_404068" not in text, text
        # Each struct member must be assigned through a distinct field of the single struct global.
        for field in ("field_0", "field_4", "field_8"):
            assert f"g_pt.{field} =" in text, (field, text)


if __name__ == "__main__":
    unittest.main()
