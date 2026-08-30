#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest.mock import patch

import angr
from angr.analyses.decompiler.optimization_passes.register_save_area_simplifier import RegisterSaveAreaSimplifier
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestRegisterSaveAreaSimplifierAdv(unittest.TestCase):
    def test_reg_save_area_simplifier_removing_final_func_args(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "131252a8059fdbb12d77cd4711e597c45bb48e6d4bc3ddc808697a5e0488ff2c"
        )
        # The scoped CFG covers the function under test, sub_46aae0, the two functions that reach it, and one round of
        # call-tree expansion: only the prototypes of the direct callees influence the output here.
        proj, cfg = load_project_with_scoped_cfg(
            bin_path,
            0x46A6C0,
            extra_func_addrs=[0x46AAE0, 0x469F80, 0x46AA98],
            call_tree_depth=1,
            cfg_kwargs={"fail_fast": True},
            ccc_kwargs={"fail_fast": True},
        )

        callee = cfg.functions[0x46AAE0]
        func = cfg.functions[0x46A6C0]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        # should not crash
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert f"{callee.name}(" in dec.codegen.text

    @staticmethod
    def _decompile_recording_save_areas(bin_path: str, func_addr: int):
        """Decompile one function, returning the result and every save-area cache handed to the pass."""
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        func = proj.kb.functions[func_addr]

        caches = []
        original_analyze = RegisterSaveAreaSimplifier._analyze

        def record_cache(self, cache=None):
            if cache is not None:
                caches.append(cache["info"])
            return original_analyze(self, cache=cache)

        with patch.object(RegisterSaveAreaSimplifier, "_analyze", record_cache):
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        return dec, caches

    @staticmethod
    def _assert_save_areas_have_both_halves(caches) -> None:
        # An entry that reaches _analyze describes a register saved into a save area and reloaded from it, so both
        # halves must be present. Defaulting a missing half to an empty list would stop the crash while deleting
        # the statements of the half that is there, and a register with no save behind it is an ordinary
        # definition that the pass has no liveness argument for removing.
        for info in caches:
            for data in info.values():
                assert set(data) == {"stored", "restored"}

    def test_link_register_restored_without_being_saved(self):
        # 0x404070 loads $ra back from the stack near its return site, but nothing saves $ra in the entry block, so
        # the link register reaches the pass with a "restored" half and no "stored" half. The pass used to keep that
        # entry and then die with KeyError: 'stored', which the decompiler swallowed into an error log entry and
        # turned into empty output.
        bin_path = os.path.join(test_location, "mipsel", "darpa_ping")
        dec, caches = self._decompile_recording_save_areas(bin_path, 0x404070)

        assert not dec.errors
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert "setsockopt(" in dec.codegen.text
        self._assert_save_areas_have_both_halves(caches)

    def test_link_register_popped_without_being_pushed(self):
        # 0x40f144 is a resolver trampoline that pushes {r0, r1, r2, r3, r4} and pops {r0, r1, r2, r3, r4, lr}: lr
        # comes back off the stack having never been saved there. Dropping that half-matched entry must not stop
        # the pass from simplifying r2 and r3, which are saved and restored in the ordinary way.
        bin_path = os.path.join(test_location, "armhf", "ld-linux.so.3")
        dec, caches = self._decompile_recording_save_areas(bin_path, 0x40F144)

        assert not dec.errors
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        self._assert_save_areas_have_both_halves(caches)
        assert caches, "dropping the link register must not disable the pass entirely"


if __name__ == "__main__":
    unittest.main()
