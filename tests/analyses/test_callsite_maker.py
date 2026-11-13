#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest
from types import SimpleNamespace
from typing import cast

import archinfo

import angr
from angr import ailment
from angr.analyses.decompiler.block_simplifier import BlockSimplifier
from angr.analyses.decompiler.callsite_maker import CallSiteMaker
from angr.calling_conventions import (
    SimArrayArg,
    SimCCARMLinuxSyscall,
    SimCCCdecl,
    SimCCX86LinuxSyscall,
    SimComboArg,
    SimRegArg,
    SimStructArg,
)
from angr.sim_type import (
    SimStruct,
    SimTypeChar,
    SimTypeFixedSizeArray,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLongLong,
    SimTypePointer,
)
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
# pylint: disable=protected-access
class TestCallsiteMaker(unittest.TestCase):
    def test_callsite_maker(self):
        project = angr.Project(
            os.path.join(test_location, "x86_64", "all"),
            auto_load_libs=False,
        )

        manager = ailment.Manager()

        # Generate a CFG
        cfg = project.analyses.CFG()

        new_cc_found = True
        while new_cc_found:
            new_cc_found = False
            for func in cfg.kb.functions.values():
                if func.calling_convention is None:
                    # determine the calling convention of each function
                    project.analyses.VariableRecoveryFast(func)
                    cc_analysis = project.analyses.CallingConvention(func)
                    if cc_analysis.cc is not None:
                        func.calling_convention = cc_analysis.cc
                        func.prototype = cc_analysis.prototype
                        new_cc_found = True

        main_func = cfg.kb.functions["main"]

        for block in sorted(main_func.blocks, key=lambda x: x.addr):
            print(block.vex.pp())
            ail_block = ailment.IRSBConverter.convert(block.vex, manager)
            simp = BlockSimplifier(project, ail_block, manager, main_func.addr)

            csm = CallSiteMaker(project, simp.result_block, ail_manager=manager)
            if csm.result_block:
                ail_block = csm.result_block
                simp = BlockSimplifier(project, ail_block, manager, main_func.addr)

            print(simp.result_block)

    def test_expand_arglocs_unfolds_a_fixed_size_array_struct_member(self):
        # A struct passed by value whose members include a fixed-size array -- BYTE Data4[8] of
        # struct Guid is the common one -- is laid out by refine_locs_with_struct_type with a
        # SimArrayArg for the array member. _expand_arglocs had no branch for that shape and
        # raised NotImplementedError, which costs the whole enclosing function: Clinic swallows
        # the exception and the function decompiles to nothing.
        arch = archinfo.ArchX86()
        struct_ty = SimStruct(
            {"tag": SimTypeInt(), "bytes": SimTypeFixedSizeArray(SimTypeChar(), 4)},
            name="WithArrayMember",
        ).with_arch(arch)
        prototype = SimTypeFunction([struct_ty], SimTypeInt()).with_arch(arch)

        arg_locs = SimCCCdecl(arch).arg_locs(prototype)

        # the calling convention really does produce the shape under test
        assert len(arg_locs) == 1
        struct_loc = arg_locs[0]
        assert isinstance(struct_loc, SimStructArg)
        array_loc = struct_loc.locs["bytes"]
        assert isinstance(array_loc, SimArrayArg)
        assert len(array_loc.locs) == 4

        # _expand_arglocs reads nothing from self, so a bare instance is enough
        maker = object.__new__(CallSiteMaker)
        expanded = maker._expand_arglocs(list(arg_locs))

        # one location per scalar member: the int, then one per array element
        assert expanded == [struct_loc.locs["tag"], *array_loc.locs]
        assert [loc.size for loc in expanded] == [4, 1, 1, 1, 1]

    def test_expand_arglocs_rejoins_wide_syscall_register_arguments(self):
        arch = archinfo.ArchX86()
        prototype = cast(
            SimTypeFunction,
            SimTypeFunction([SimTypeInt(), SimTypeLongLong(), SimTypeLongLong(), SimTypeInt()], SimTypeInt()).with_arch(
                arch
            ),
        )
        arg_locs = SimCCX86LinuxSyscall(arch).arg_locs(prototype)

        assert len(arg_locs) == 4
        assert isinstance(arg_locs[1], SimComboArg)
        assert isinstance(arg_locs[2], SimComboArg)

        maker = cast(CallSiteMaker, SimpleNamespace(project=SimpleNamespace(arch=arch)))
        expanded = CallSiteMaker._expand_arglocs(maker, arg_locs)

        assert len(expanded) == len(prototype.args)
        assert [loc.size for loc in expanded] == [4, 8, 8, 4]
        for combo, merged in zip(arg_locs[1:3], expanded[1:3]):
            assert isinstance(combo, SimComboArg)
            assert isinstance(merged, SimRegArg)
            assert merged.check_offset(arch) == min(loc.check_offset(arch) for loc in combo.locations)
            assert merged.size == sum(loc.size for loc in combo.locations)

        gapped = SimComboArg([SimRegArg("eax", 4), SimRegArg("edx", 4)])
        assert CallSiteMaker._expand_arglocs(maker, [gapped]) == gapped.locations

        partial = SimComboArg([SimRegArg("eax", 2, reg_offset=1), SimRegArg("eax", 1, reg_offset=3)], is_fp=True)
        merged_partial = CallSiteMaker._expand_arglocs(maker, [partial])
        assert len(merged_partial) == 1
        assert isinstance(merged_partial[0], SimRegArg)
        assert (merged_partial[0].reg_name, merged_partial[0].reg_offset, merged_partial[0].size) == ("eax", 1, 3)
        assert merged_partial[0].is_fp

    def test_expand_arglocs_rejoins_wide_arm_syscall_register_arguments(self):
        for endness in (archinfo.Endness.LE, archinfo.Endness.BE):
            arch = archinfo.ArchARM(endness=endness)
            prototype = cast(
                SimTypeFunction,
                SimTypeFunction(
                    [SimTypeInt(), SimTypePointer(SimTypeChar()), SimTypeInt(), SimTypeLongLong(), SimTypeInt()],
                    SimTypeInt(),
                ).with_arch(arch),
            )
            arg_locs = SimCCARMLinuxSyscall(arch).arg_locs(prototype)

            assert isinstance(arg_locs[3], SimComboArg)
            expected_combo = ["r4", "r5"] if endness == archinfo.Endness.LE else ["r5", "r4"]
            assert [loc.reg_name for loc in arg_locs[3].locations] == expected_combo

            maker = cast(CallSiteMaker, SimpleNamespace(project=SimpleNamespace(arch=arch)))
            expanded = CallSiteMaker._expand_arglocs(maker, arg_locs)

            assert len(expanded) == len(prototype.args)
            assert [loc.size for loc in expanded] == [4, 4, 4, 8, 4]
            assert isinstance(expanded[3], SimRegArg)
            assert (expanded[3].reg_name, expanded[3].reg_offset) == ("r4", 0)


if __name__ == "__main__":
    unittest.main()
