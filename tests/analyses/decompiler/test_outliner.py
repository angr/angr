from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use

import logging
import os.path
from unittest import TestCase
import unittest

from angr.ailment.expression import VirtualVariableCategory

import angr
from angr.analyses.decompiler.decompiler import Decompiler
from angr.sim_type import SimStruct, SimTypeArray, SimTypeWideChar, SimTypeChar
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr.analyses.decompiler.clinic import ClinicStage

from tests.common import bin_location


class TestOutliner(TestCase):
    def test_outlining_authenticate(self):
        bin_path = os.path.join(bin_location, "tests", "x86_64", "1after909")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions()

        func = proj.kb.functions["verify_password"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        print("[+] Original function:")
        assert dec.codegen is not None
        assert dec.codegen.text is not None
        assert dec._variable_kb is not None
        assert dec.clinic is not None
        print(dec.codegen.text)

        outliner = proj.analyses.Outliner(
            func,
            dec.ail_graph,
            src_loc=(0x4017BD, None),  # frontier=[(0x401847, None), (0x401867, 2)]
        )

        # now we have two graphs; gotta decompile them individually
        del dec._variable_kb.variables[func.addr]
        dec_outer = proj.analyses[Decompiler].prep(
            fail_fast=True,
        )(
            func,
            clinic_graph=dec.ail_graph,
            clinic_start_stage=ClinicStage.POST_CALLSITES,
            clinic_arg_vvars=dec.clinic.arg_vvars,
            cfg=cfg.model,
        )
        assert dec_outer.codegen is not None
        print("[+] Post-outlining:")
        print(dec_outer.codegen.text)

        # the second function
        out_funcargs = {}
        for arg_idx, arg_vvar in enumerate(outliner.out_funcargs):
            if arg_vvar.was_parameter:
                if arg_vvar.parameter_category == VirtualVariableCategory.REGISTER:
                    simvar = SimRegisterVariable(arg_vvar.reg_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
                elif arg_vvar.parameter_category == VirtualVariableCategory.STACK:
                    simvar = SimStackVariable(arg_vvar.stack_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
                else:
                    raise NotImplementedError
            elif arg_vvar.was_reg:
                simvar = SimRegisterVariable(arg_vvar.reg_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
            elif arg_vvar.was_stack:
                simvar = SimStackVariable(arg_vvar.stack_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
            else:
                raise NotImplementedError
            out_funcargs[arg_vvar.varid] = arg_vvar, simvar

        dec_inner = proj.analyses[Decompiler].prep(
            fail_fast=True,
        )(
            outliner.out_func,
            clinic_graph=outliner.out_graph,
            clinic_arg_vvars=out_funcargs,
            clinic_start_stage=ClinicStage.POST_CALLSITES,
            cfg=cfg.model,
        )
        assert dec_inner.codegen is not None
        print(dec_inner.codegen.text)

    def test_outlining_notepad_npinit(self):
        bin_path = r"F:\My Documents\Emotion Labs\ire\driver_samples\notepad_edited.exe"
        # bin_path = r"F:\My Documents\Emotion Labs\ire\driver_samples\notepad.exe"
        if not os.path.exists(bin_path):
            raise unittest.SkipTest("Hey, you're not Fish...")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        # proj.analyses.CompleteCallingConventions()

        func = proj.kb.functions[0x1400135D0]
        print(f"[+] Decompiling {func.name}...")
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None
        assert dec.codegen.text is not None
        assert dec._variable_kb is not None
        assert dec.clinic is not None
        print(dec.codegen.text)

        outlining_setups: list[tuple[tuple[int, int | None], list[tuple[int, int | None]] | None]] = [
            ((0x140014172, None), None),  # [(0x1400144DF, None), (0x14001472C, None)]),
            # (
            #     (0x140015368, None),
            #     [
            #         (0x14001539A, None),
            #         (0x1400154B5, None),
            #         (0x1400154B9, None),
            #         (0x1400173C9, None),
            #         (0x140015913, None),
            #         (0x140015935, None),
            #         # (0x14001598B, None),
            #         # (0x140015980, None),
            #     ],
            # ),
        ]
        outliner_vvar_id = 0xD000
        outliner_block_addr = 0xABCD0000
        for src_loc, frontier in outlining_setups:
            frontier_str = " ".join(f"{x[0]:#x}" for x in frontier) if frontier is not None else "TBD"
            print(f"[+] Outlining {src_loc[0]:#x} - [{frontier_str}]...")
            outliner = proj.analyses.Outliner(
                func,
                dec.ail_graph,
                src_loc=src_loc,
                frontier=frontier,
                vvar_id_start=outliner_vvar_id,
                block_addr_start=outliner_block_addr,
                min_step=2,
            )
            outliner_vvar_id, outliner_block_addr = outliner.vvar_id_start, outliner.block_addr_start

            # the newly outlined function
            out_funcargs = {}
            for arg_idx, arg_vvar in enumerate(outliner.out_funcargs):
                if arg_vvar.was_parameter:
                    if arg_vvar.parameter_category == VirtualVariableCategory.REGISTER:
                        simvar = SimRegisterVariable(arg_vvar.reg_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
                    elif arg_vvar.parameter_category == VirtualVariableCategory.STACK:
                        simvar = SimStackVariable(arg_vvar.stack_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
                    else:
                        raise NotImplementedError
                elif arg_vvar.was_reg:
                    simvar = SimRegisterVariable(arg_vvar.reg_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
                elif arg_vvar.was_stack:
                    simvar = SimStackVariable(arg_vvar.stack_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
                else:
                    raise NotImplementedError
                out_funcargs[arg_vvar.varid] = arg_vvar, simvar

            dec_inner = proj.analyses[Decompiler].prep(
                fail_fast=True,
            )(
                outliner.out_func,
                clinic_graph=outliner.out_graph,
                clinic_arg_vvars=out_funcargs,
                clinic_start_stage=ClinicStage.POST_CALLSITES,
                cfg=cfg.model,
            )
            assert dec_inner.codegen is not None
            print(dec_inner.codegen.text)

            if not outliner.out_funcargs:
                t = SimStruct(
                    {"module_name": SimTypeArray(SimTypeWideChar(), 10), "api": SimTypeArray(SimTypeChar(), 10)}
                )
                final_state, _ = outliner.execute()
                tt = t.with_arch(proj.arch)
                extracted = tt.extract(final_state, 0xC000_0000)
                print(extracted)

        del dec._variable_kb.variables[func.addr]
        dec_outer = proj.analyses[Decompiler].prep(
            fail_fast=True,
        )(
            func,
            clinic_graph=dec.ail_graph,
            clinic_start_stage=ClinicStage.POST_CALLSITES,
            clinic_arg_vvars=dec.clinic.arg_vvars,
            cfg=cfg.model,
        )
        assert dec_outer.codegen is not None
        print(dec_outer.codegen.text)

    def test_liveness_density_notepad_npinit(self):
        bin_path = r"F:\My Documents\Emotion Labs\ire\driver_samples\notepad_edited.exe"
        # bin_path = r"F:\My Documents\Emotion Labs\ire\driver_samples\notepad.exe"
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        # proj.analyses.CompleteCallingConventions()

        func = proj.kb.functions[0x1400135D0]
        print(f"[+] Decompiling {func.name}...")
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print(dec.codegen.text)


if __name__ == "__main__":
    # main()

    logging.getLogger("angr.analyses.outliner").setLevel(logging.DEBUG)
    # TestOutliner().test_outlining_authenticate()
    TestOutliner().test_outlining_notepad_npinit()
