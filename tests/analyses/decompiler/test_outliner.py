from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import logging
import os.path
import unittest
from unittest import TestCase

import angr
from angr.ailment.expression import Call, Phi, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.clinic import Clinic, ClinicStage
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.outliner import Outliner
from angr.sim_type import SimStruct, SimTypeArray, SimTypeChar, SimTypeWideChar
from angr.sim_variable import SimRegisterVariable, SimStackVariable
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
        assert dec.func.addr in dec.kb.dec_variables
        assert dec.clinic is not None
        print(dec.codegen.text)

        outliner = proj.analyses[Outliner](
            func,
            dec.ail_graph,
            src_loc=(0x4017BD, None),  # frontier=[(0x401847, None), (0x401867, 2)]
        )

        # now we have two graphs; gotta decompile them individually
        del dec.kb.dec_variables.function_managers[func.addr]
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
        for arg_idx, arg_vvar in enumerate(outliner.child_funcargs):
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
            out_funcargs[arg_idx] = arg_vvar, simvar

        dec_inner = proj.analyses[Decompiler].prep(
            fail_fast=True,
        )(
            outliner.child_func,
            clinic_graph=outliner.child_graph,
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
        assert dec.func.addr in dec.kb.dec_variables
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

        del dec.kb.dec_variables.function_managers[func.addr]
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
        if not os.path.exists(bin_path):
            raise unittest.SkipTest("Hey, you're not Fish...")
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


class TestOutlinerSSAInvariants(TestCase):
    """Outlining rewrites the parent graph; the result must still be valid SSA.

    Every problem below surfaces far downstream -- typically as an
    AttributeError inside dephication -- so it is checked here instead.
    """

    @classmethod
    def setUpClass(cls):
        bin_path = os.path.join(bin_location, "tests", "x86_64", "1after909")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions()
        cls.proj = proj
        cls.cfg = cfg
        cls.graphs = {}
        for name in ("convert", "read_str"):
            func = proj.kb.functions[name]
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
            assert dec.ail_graph is not None
            cls.graphs[name] = (func, dec.ail_graph)

    @staticmethod
    def _ssa_problems(graph) -> set:
        """Phis naming a block that is not a predecessor, and vvars defined twice."""
        locs = {(b.addr, b.idx) for b in graph}
        problems = set()
        definitions = {}
        for block in graph:
            preds = {(p.addr, p.idx) for p in graph.predecessors(block)}
            for i, stmt in enumerate(block.statements):
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    definitions.setdefault(stmt.dst.varid, []).append((block.addr, block.idx, i))
                if not isinstance(stmt, Assignment) or not isinstance(stmt.src, Phi):
                    continue
                for src, _ in stmt.src.src_and_vvars:
                    if src not in locs:
                        problems.add(("phi-sources-removed-block", block.addr, block.idx, i, src))
                    elif src not in preds:
                        problems.add(("phi-sources-non-predecessor", block.addr, block.idx, i, src))
        for varid, locations in definitions.items():
            if len(locations) > 1:
                problems.add(("vvar-defined-more-than-once", varid, None, None, None))
        return problems

    def test_outlining_never_introduces_ssa_problems(self):
        """Outline at every viable location and check nothing new breaks.

        Compared against the untouched graph rather than against zero: the
        decompiler itself can emit duplicated blocks that already define the
        same vvar twice, and that is not the Outliner's doing.
        """
        for name, (func, base) in self.graphs.items():
            baseline = self._ssa_problems(base)
            for block in sorted(base, key=lambda b: (b.addr, -1 if b.idx is None else b.idx)):
                if base.in_degree[block] == 0 or base.out_degree[block] == 0:
                    continue
                graph = Clinic._copy_graph(base)
                try:
                    self.proj.analyses[Outliner](func, graph, src_loc=(block.addr, block.idx), min_step=2)
                except Exception:  # pylint:disable=broad-except
                    continue
                introduced = self._ssa_problems(graph) - baseline
                assert not introduced, (
                    f"outlining {name} at {block.addr:#x}.{block.idx} introduced "
                    f"{len(introduced)} SSA problems, e.g. {min(introduced)}"
                )

    def test_call_returns_only_variables_the_region_defines(self):
        """The synthesized call must not become a second definition of a variable
        whose value reaches the frontier from outside the outlined region.

        Needs an explicit frontier: with a derived one ``frontier_vars`` is empty
        and the call only ever returns its own dispatcher variable.
        """
        checked = 0
        for name, (func, base) in self.graphs.items():
            for block in sorted(base, key=lambda b: (b.addr, -1 if b.idx is None else b.idx)):
                if base.in_degree[block] == 0 or base.out_degree[block] == 0:
                    continue
                # let the Outliner pick a frontier, then feed it back in explicitly
                probe_graph = Clinic._copy_graph(base)
                try:
                    probe = self.proj.analyses[Outliner](func, probe_graph, src_loc=(block.addr, block.idx), min_step=2)
                except Exception:  # pylint:disable=broad-except
                    continue
                if not probe.frontier_locs:
                    continue
                graph = Clinic._copy_graph(base)
                synthetic = 0x100000  # vvars the Outliner mints for itself start here
                try:
                    outliner = self.proj.analyses[Outliner](
                        func,
                        graph,
                        src_loc=(block.addr, block.idx),
                        frontier=set(probe.frontier_locs),
                        vvar_id_start=synthetic,
                        min_step=2,
                    )
                except Exception:  # pylint:disable=broad-except
                    continue
                child_defs = {
                    stmt.dst.varid
                    for node in outliner.child_graph
                    for stmt in node.statements
                    if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)
                }
                call_block = next((b for b in graph if (b.addr, b.idx) == (block.addr, block.idx)), None)
                if call_block is None:
                    continue
                for stmt in call_block.statements:
                    if not isinstance(stmt, Assignment) or not isinstance(stmt.src, Call):
                        continue
                    if not isinstance(stmt.dst, VirtualVariable) or stmt.dst.varid >= synthetic:
                        # the call's own dispatcher variable, not a returned value
                        continue
                    checked += 1
                    assert stmt.dst.varid in child_defs, (
                        f"outlining {name} at {block.addr:#x}: the call returns vvar "
                        f"{stmt.dst.varid}, which the outlined region never defines"
                    )
        assert checked, "no explicit-frontier outline produced a call with a return value"
