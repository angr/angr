#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

import angr
from angr.calling_conventions import SimCCCdecl
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeDouble, SimTypeFloat, SimTypeFunction
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestX87FloatReturn(unittest.TestCase):
    """
    A 32-bit x86 function returns a float at the top of the x87 stack, and the calling convention
    names that location "st0". VEX models the stack as ``fpreg`` indexed by the run-time value of
    ``ftop``, so "st0" resolves only against a state and ``ArchX86.registers`` has no entry for it.
    ``ReturnMaker`` indexed the register map with that name and lost the whole function.

    The value itself stays unrepresentable: it reaches the return through VEX ``GetI``/``PutI``,
    which the AIL converter does not support. These tests pin that the failure is reported and the
    rest of the function still decompiles, not that the returned value appears.
    """

    def _assert_reported_not_raised(self, proj, cfg, func, structurer: str) -> str:
        ret_val = func.calling_convention.return_val(func.prototype.returnty)
        assert ret_val.reg_name == "st0"
        assert "st0" not in proj.arch.registers

        with self.assertLogs("angr.analyses.decompiler.return_maker", level="WARNING") as logs:
            dec = proj.analyses.Decompiler(
                func, cfg=cfg.model, options=[("structurer_cls", structurer)], update_cache=False
            )
        assert any("not a register on X86" in line for line in logs.output)
        assert not dec.errors
        assert dec.codegen is not None and dec.codegen.text
        return dec.codegen.text

    def test_library_declared_double_return(self):
        # The prototype here comes from the binary as shipped: these PLT stubs resolve to libc
        # declarations returning double, so nothing about the test manufactures the condition.
        # The CFG is scoped to the stubs themselves, taken from CLE's PLT map rather than
        # hard-coded; a full scan of this library costs minutes and none of it is needed here.
        proj = angr.Project(os.path.join(test_location, "i386", "libstdc++.so.6"), auto_load_libs=False)
        wanted = ("floor", "frexpl", "ceil")
        plt = {name: addr for addr, name in proj.loader.main_object.reverse_plt.items() if name in wanted}
        assert set(plt) == set(wanted), f"fixture no longer exposes these PLT stubs: {sorted(plt)}"

        regions = [(addr, addr + 0x10) for addr in plt.values()]
        cfg = proj.analyses.CFGFast(normalize=True, regions=regions, force_complete_scan=False)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model, recover_variables=True)

        for name, addr in sorted(plt.items()):
            func = cfg.functions.get_by_addr(addr)
            assert func.name == name and func.is_plt
            assert isinstance(func.prototype.returnty, SimTypeDouble)
            self._assert_reported_not_raised(proj, cfg, func, "phoenix")

    def test_declared_float_and_double_return(self):
        # manyfloatsum.c declares these as float and double. angr's own inference reports them as
        # returning void, because the same missing register name leaves _guess_retval_type unable
        # to recognise an x87 return, so the true prototype is stated here.
        proj = angr.Project(os.path.join(test_location, "i386", "manyfloatsum"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model, recover_variables=True)

        for func_name, returnty, decl in (
            ("sum_floats", SimTypeFloat, "float sum_floats"),
            ("sum_doubles", SimTypeDouble, "double sum_doubles"),
        ):
            func = cfg.functions.function(name=func_name)
            assert func is not None
            func.calling_convention = SimCCCdecl(proj.arch)
            func.prototype = SimTypeFunction([], returnty()).with_arch(proj.arch)
            func.prototype_source = PrototypeSource.USER
            for structurer in ("phoenix", "sailr"):
                text = self._assert_reported_not_raised(proj, cfg, func, structurer)
                assert text.startswith(decl)


if __name__ == "__main__":
    unittest.main()
