# pylint:disable=too-many-boolean-expressions
from __future__ import annotations

import os
from collections import Counter, defaultdict

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import Call, VirtualVariable
from angr.ailment.statement import Assignment, Return, SideEffectStatement
from angr.analyses.analysis import Analysis, register_analysis
from angr.calling_conventions import SimRegArg, default_cc
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.key_definitions.constants import ObservationPointType
from angr.utils.ssa import get_tmp_deflocs, get_tmp_uselocs, get_vvar_deflocs, get_vvar_uselocs

from .s_rda_model import SRDAModel
from .s_rda_view import SRDAView

# When enabled (env var VERIFY_BLOCK_DEFUSES_CACHE), every cache-served per-block def/use collection is checked against
# a fresh whole-graph scan. Used to validate the cache; off by default because the fresh scan defeats its purpose.
_VERIFY_BLOCK_DEFUSES_CACHE = os.environ.get("VERIFY_BLOCK_DEFUSES_CACHE", "").lower() not in {"", "0", "no", "false"}


class SReachingDefinitionsAnalysis(Analysis):
    """
    Constant and expression propagation that only supports SSA AIL graphs.
    """

    def __init__(  # pylint: disable=too-many-positional-arguments
        self,
        subject,
        func_addr: int | None = None,
        func_graph: networkx.DiGraph[Block] | None = None,
        func_args: set[VirtualVariable] | None = None,
        use_callee_saved_regs_at_return: bool = False,
        track_tmps: bool = False,
        variable_map=None,
        block_defuses_cache=None,
    ):
        if isinstance(subject, Block):
            self.block = subject
            self.func = None
            self.mode = "block"
        elif isinstance(subject, Function):
            self.block = None
            self.func = subject
            self.mode = "function"
        else:
            raise TypeError(f"Unsupported subject type {type(subject)}")

        self.func_graph = func_graph
        self.func_addr = func_addr if func_addr is not None else self.func.addr if self.func is not None else None
        self.func_args = func_args
        self._track_tmps = track_tmps
        self._use_callee_saved_regs_at_return = use_callee_saved_regs_at_return
        # The per-block def/use cache is only consulted in function mode (the per-block scan does not depend on
        # func_args/use_callee_saved_regs_at_return, so a single cache is valid across all function-mode call sites).
        # Temporaries are never cached, so it is not used when tmps are tracked.
        self._block_defuses_cache = block_defuses_cache if self.mode == "function" and not track_tmps else None

        self._bp_as_gpr = False
        if self.func is not None:
            self._bp_as_gpr = self.func.info.get("bp_as_gpr", False)

        self.model = SRDAModel(
            func_graph,
            func_args,
            self.project.arch,
            variable_map=variable_map,
            block_defuses_cache=self._block_defuses_cache,
        )

        self._analyze()

    def _collect_vvar_defuses(self, blocks):
        """
        Collect per-block vvar definitions, explicit uses, and phi sources for ``blocks``.

        When a BlockDefUsesCache is available (function mode), unchanged blocks are served from the cache instead of
        being re-scanned; otherwise the whole-graph scan is used. The two paths are equivalent: the merged result is
        order-insensitively identical to a fresh scan (verified when VERIFY_BLOCK_DEFUSES_CACHE is set).

        :return: a tuple of (vvar_deflocs, vvar_uselocs, phi_vvars), matching ``get_vvar_deflocs``/``get_vvar_uselocs``.
        """
        if self._block_defuses_cache is None:
            phi_vvars: dict[int, set[int | None]] = {}
            vvar_deflocs = get_vvar_deflocs(blocks, phi_vvars=phi_vvars)
            vvar_uselocs = get_vvar_uselocs(blocks)
            return vvar_deflocs, vvar_uselocs, phi_vvars

        cache = self._block_defuses_cache
        vvar_deflocs = {}
        phi_vvars = {}
        vvar_uselocs = defaultdict(list)
        # Merge per-block results in func_graph iteration order, matching the whole-graph scan (later definitions
        # overwrite earlier ones; uses are concatenated in block order). vvar definitions are unique per varid in SSA,
        # so the merge order only matters for the rare extra-def overwrite and for deterministic use ordering.
        for block in blocks:
            bdu = cache.get(block)
            vvar_deflocs.update(bdu.vvar_deflocs)
            phi_vvars.update(bdu.phi_vvars)
            for varid, uses in bdu.vvar_uselocs.items():
                vvar_uselocs[varid].extend(uses)

        if _VERIFY_BLOCK_DEFUSES_CACHE:
            self._verify_block_defuses(blocks, vvar_deflocs, vvar_uselocs, phi_vvars)
        return vvar_deflocs, vvar_uselocs, phi_vvars

    @staticmethod
    def _verify_block_defuses(blocks, vvar_deflocs, vvar_uselocs, phi_vvars) -> None:
        # Debug-only (env var VERIFY_BLOCK_DEFUSES_CACHE): assert the cache-served collection matches a fresh scan.
        ref_phi: dict[int, set[int | None]] = {}
        ref_deflocs = get_vvar_deflocs(blocks, phi_vvars=ref_phi)
        ref_uselocs = get_vvar_uselocs(blocks)

        def canon_defs(d):
            return {vid: loc for vid, (_vvar, loc) in d.items()}

        def canon_uses(d):
            return {
                vid: Counter((e.varid if e is not None else None, loc) for e, loc in lst)
                for vid, lst in d.items()
                if lst
            }

        if canon_defs(vvar_deflocs) != canon_defs(ref_deflocs):
            raise AssertionError("BlockDefUsesCache: vvar definitions diverged from a fresh scan")
        if canon_uses(vvar_uselocs) != canon_uses(ref_uselocs):
            raise AssertionError("BlockDefUsesCache: vvar uses diverged from a fresh scan")
        if {k: frozenset(v) for k, v in phi_vvars.items()} != {k: frozenset(v) for k, v in ref_phi.items()}:
            raise AssertionError("BlockDefUsesCache: phi sources diverged from a fresh scan")

    def _analyze(self):
        match self.mode:
            case "block":
                assert self.block is not None
                blocks = {(self.block.addr, self.block.idx): self.block}
            case "function":
                assert self.func_graph is not None
                blocks = {(block.addr, block.idx): block for block in self.func_graph}
            case _:
                raise NotImplementedError

        # find all vvar definitions, explicit uses, and phi sources (served from the per-block cache when available)
        vvar_deflocs, vvar_uselocs, phi_vvars = self._collect_vvar_defuses(blocks.values())

        # update vvar definitions using function arguments
        if self.func_args:
            for vvar in self.func_args:
                if vvar.varid not in vvar_deflocs:
                    vvar_deflocs[vvar.varid] = vvar, AILCodeLocation.make_extern(vvar.varid)
            self.model.func_args = self.func_args

        # update model
        for vvar_id, (vvar, defloc) in vvar_deflocs.items():
            self.model.varid_to_vvar[vvar_id] = vvar
            self.model.all_vvar_definitions[vvar_id] = defloc
            if vvar_id in vvar_uselocs:
                for useloc in vvar_uselocs[vvar_id]:
                    self.model.add_vvar_use(vvar_id, *useloc)

        self.model.phi_vvar_ids = set(phi_vvars)
        self.model.phivarid_to_varids = {}
        for vvar_id, src_vvars in phi_vvars.items():
            self.model.phivarid_to_varids_with_unknown[vvar_id] = src_vvars
            self.model.phivarid_to_varids[vvar_id] = (  # type: ignore
                {vvar_id for vvar_id in src_vvars if vvar_id is not None} if None in src_vvars else src_vvars
            )

        if self.mode == "function":
            assert self.func is not None

            # fix register definitions for arguments
            defined_vvarids = set(vvar_deflocs)
            undefined_vvarids = set(vvar_uselocs.keys()).difference(defined_vvarids)
            for vvar_id in undefined_vvarids:
                used_vvar = next(iter(vvar_uselocs[vvar_id]))[0]
                self.model.varid_to_vvar[vvar_id] = used_vvar
                self.model.all_vvar_definitions[vvar_id] = AILCodeLocation.make_extern(vvar_id)
                if vvar_id in vvar_uselocs:
                    for vvar_useloc in vvar_uselocs[vvar_id]:
                        self.model.add_vvar_use(vvar_id, *vvar_useloc)

            srda_view = SRDAView(self.model)

            # fix register uses at call sites

            # find all implicit vvar uses
            call_stmt_ids = []
            for block in blocks.values():
                for stmt_idx, stmt in enumerate(block.statements):
                    if (  # pylint:disable=too-many-boolean-expressions
                        (isinstance(stmt, SideEffectStatement) and stmt.expr.args is None)
                        or (isinstance(stmt, Assignment) and isinstance(stmt.src, Call) and stmt.src.args is None)
                        or (isinstance(stmt, Return) and stmt.ret_exprs and isinstance(stmt.ret_exprs[0], Call))
                    ):
                        call_stmt_ids.append(((block.addr, block.idx), stmt_idx))

            observations = srda_view.observe(
                [("stmt", insn_stmt_id, ObservationPointType.OP_BEFORE) for insn_stmt_id in call_stmt_ids]
            )
            for key, reg_to_vvarids in observations.items():
                _, ((block_addr, block_idx), stmt_idx), _ = key

                block = blocks[(block_addr, block_idx)]
                stmt = block.statements[stmt_idx]
                assert isinstance(stmt, (SideEffectStatement, Assignment, Return))

                call = (
                    stmt.expr
                    if isinstance(stmt, SideEffectStatement)
                    else stmt.src
                    if isinstance(stmt, Assignment)
                    else stmt.ret_exprs[0]
                )
                assert isinstance(call, Call)

                # conservatively add uses to all registers that are potentially used here
                call_cc = (
                    self.model.variable_map.calling_convention(call) if self.model.variable_map is not None else None
                )
                if call_cc is not None:
                    cc = call_cc
                else:
                    # just use all registers in the default calling convention because we don't know anything about
                    # the calling convention yet
                    cc_cls = default_cc(self.project.arch.name)
                    assert cc_cls is not None
                    cc = cc_cls(self.project.arch)

                codeloc = AILCodeLocation(block_addr, block_idx, stmt_idx, stmt.tags.get("ins_addr"))
                arg_locs = list(cc.ARG_REGS)
                if cc.FP_ARG_REGS:
                    arg_locs += [r_name for r_name in cc.FP_ARG_REGS if r_name not in arg_locs]

                for arg_reg_name in arg_locs:
                    reg_offset, reg_size = self.project.arch.registers[arg_reg_name]
                    if reg_offset in reg_to_vvarids:
                        for vvar_size in reg_to_vvarids[reg_offset]:
                            if vvar_size >= reg_size:
                                vvarid = reg_to_vvarids[reg_offset][vvar_size]
                                self.model.add_vvar_use(vvarid, None, codeloc)

            if self._use_callee_saved_regs_at_return:
                # handle callee-saved registers: add uses for these registers so that the restoration statements are not
                # considered dead assignments.
                cc = self.func.calling_convention
                if cc is None:
                    cc_cls = default_cc(
                        self.project.arch.name,
                        platform=self.project.simos.name if self.project.simos is not None else None,
                    )
                    assert cc_cls is not None
                    cc = cc_cls(self.project.arch)

                arch = self.project.arch
                ob_points = []
                endpoint_addrs = {end_point.addr for end_point in self.func.endpoints}
                for block in blocks.values():
                    if block.addr in endpoint_addrs:
                        ob_points.append(("node", (block.addr, block.idx), ObservationPointType.OP_AFTER))
                func_end_observations = srda_view.observe(ob_points)
                ignore_reg_offsets = {arch.sp_offset, arch.ip_offset}
                if not self._bp_as_gpr:
                    ignore_reg_offsets.add(arch.bp_offset)
                for key, reg_to_vvarids in func_end_observations.items():
                    _, (block_addr, block_idx), _ = key
                    block = blocks[(block_addr, block_idx)]
                    if not block.statements:
                        # totally unexpected
                        continue
                    stmt = block.statements[-1]
                    codeloc = AILCodeLocation(
                        block_addr, block_idx, len(block.statements) - 1, stmt.tags.get("ins_addr")
                    )
                    for reg in arch.register_list:
                        if (
                            reg.general_purpose
                            and reg.name not in cc.CALLER_SAVED_REGS
                            and reg.name not in cc.ARG_REGS
                            and reg.vex_offset not in ignore_reg_offsets
                            and (isinstance(cc.RETURN_VAL, SimRegArg) and reg.name != cc.RETURN_VAL.reg_name)
                        ):
                            reg_offset = self.project.arch.registers[reg.name][0]
                            if reg_offset in reg_to_vvarids:
                                max_vvar_size = max(reg_to_vvarids[reg_offset])
                                vvarid = reg_to_vvarids[reg_offset][max_vvar_size]
                                self.model.add_vvar_use(vvarid, None, codeloc)

        if self._track_tmps:
            # track tmps
            tmp_deflocs = get_tmp_deflocs(blocks.values())
            # find all vvar uses
            tmp_uselocs = get_tmp_uselocs(blocks.values())

            # update model
            for block_loc, d in tmp_deflocs.items():
                for tmp_atom, stmt_idx in d.items():
                    self.model.all_tmp_definitions[block_loc][tmp_atom] = stmt_idx

                    if tmp_atom in tmp_uselocs[block_loc]:
                        for tmp_at_use, use_stmt_idx in tmp_uselocs[block_loc][tmp_atom]:
                            if tmp_atom not in self.model.all_tmp_uses[block_loc]:
                                self.model.all_tmp_uses[block_loc][tmp_atom] = set()
                            self.model.all_tmp_uses[block_loc][tmp_atom].add((tmp_at_use, use_stmt_idx))


register_analysis(SReachingDefinitionsAnalysis, "SReachingDefinitions")
