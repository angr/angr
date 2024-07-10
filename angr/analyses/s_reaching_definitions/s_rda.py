from __future__ import annotations
from typing import Any
from collections.abc import Generator
from collections import defaultdict
import logging

from ailment.block import Block
from ailment.statement import Assignment, Call
from ailment.expression import VirtualVariable, Tmp, Expression

from angr.utils.graph import GraphUtils
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.key_definitions import atoms, Definition
from angr.knowledge_plugins.key_definitions.constants import ObservationPointType, ObservationPoint
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.analyses import Analysis, register_analysis
from angr.utils.ssa import get_vvar_uselocs, get_vvar_deflocs, get_tmp_deflocs, get_tmp_uselocs, get_reg_offset_base
from angr.calling_conventions import SimRegArg, default_cc


_l = logging.getLogger(__name__)


class SRDAModel:
    def __init__(self, func_graph, arch):
        self.func_graph = func_graph
        self.arch = arch
        self.all_vvar_definitions: dict[VirtualVariable, CodeLocation] = {}
        self.all_vvar_uses: dict[VirtualVariable, set[tuple[VirtualVariable | None, CodeLocation]]] = defaultdict(set)
        self.all_tmp_definitions: dict[CodeLocation, dict[atoms.Tmp, int]] = defaultdict(dict)
        self.all_tmp_uses: dict[CodeLocation, dict[atoms.Tmp, set[tuple[Tmp, int]]]] = defaultdict(dict)

    @property
    def all_definitions(self) -> Generator[Definition, None, None]:
        for vvar, defloc in self.all_vvar_definitions.items():
            yield Definition(atoms.VirtualVariable(vvar.varid, vvar.size, vvar.category, vvar.oident), defloc)

    def get_all_tmp_definitions(self, block_loc: CodeLocation) -> set[Definition]:
        s = set()
        for tmp_atom, stmt_idx in self.all_tmp_definitions[block_loc].items():
            s.add(Definition(tmp_atom, CodeLocation(block_loc.block_addr, stmt_idx, block_idx=block_loc.block_idx)))
        return s

    def get_uses_by_location(
        self, loc: CodeLocation, exprs: bool = False
    ) -> set[Definition] | set[tuple[Definition, Any | None]]:
        """
        Retrieve all definitions that are used at a given location.

        :param loc:     The code location.
        :return:        A set of definitions that are used at the given location.
        """
        if exprs:
            defs: set[tuple[Definition, Any]] = set()
            for vvar, uses in self.all_vvar_uses.items():
                for expr, loc_ in uses:
                    if loc_ == loc:
                        defs.add(
                            (
                                Definition(
                                    atoms.VirtualVariable(vvar.varid, vvar.size, vvar.category, vvar.oident),
                                    self.all_vvar_definitions[vvar],
                                ),
                                expr,
                            )
                        )
            return defs

        defs: set[Definition] = set()
        for vvar, uses in self.all_vvar_uses.items():
            for _, loc_ in uses:
                if loc_ == loc:
                    defs.add(
                        Definition(
                            atoms.VirtualVariable(vvar.varid, vvar.size, vvar.category, vvar.oident),
                            self.all_vvar_definitions[vvar],
                        )
                    )
        return defs

    def get_vvar_uses(self, obj: atoms.VirtualVariable) -> set[CodeLocation]:
        the_vvar = next(iter(v for v in self.all_vvar_uses if v.varid == obj.varid), None)
        if the_vvar is not None:
            return {loc for _, loc in self.all_vvar_uses[the_vvar]}
        return set()

    def get_vvar_uses_with_expr(self, obj: atoms.VirtualVariable) -> set[tuple[CodeLocation, VirtualVariable]]:
        the_vvar = next(iter(v for v in self.all_vvar_uses if v.varid == obj.varid), None)
        if the_vvar is not None:
            return {(loc, expr) for expr, loc in self.all_vvar_uses[the_vvar]}
        return set()

    def get_tmp_uses(self, obj: atoms.Tmp, block_loc: CodeLocation) -> set[CodeLocation]:
        if block_loc not in self.all_tmp_uses:
            return set()
        if obj not in self.all_tmp_uses[block_loc]:
            return set()
        s = set()
        for _, stmt_idx in self.all_tmp_uses[block_loc][obj]:
            s.add(CodeLocation(block_loc.block_addr, stmt_idx, block_idx=block_loc.block_idx))
        return s


class SRDAView:
    def __init__(self, model: SRDAModel):
        self.model = model

    def _get_call_clobbered_regs(self, stmt: Call) -> set[int]:
        cc = stmt.calling_convention
        if cc is None:
            # get the default calling convention
            cc = default_cc(self.model.arch)  # TODO: platform and language
        if cc is not None:
            reg_list = stmt.calling_convention.CALLER_SAVED_REGS
            if isinstance(stmt.calling_convention.RETURN_VAL, SimRegArg):
                reg_list.append(stmt.calling_convention.RETURN_VAL.reg_name)
            return {self.model.arch.registers[reg_name][0] for reg_name in reg_list}
        _l.warning("Cannot determine registers that are clobbered by call statement %r.", stmt)
        return set()

    def get_reg_vvar_by_insn(
        self, reg_offset: int, addr: int, op_type: ObservationPointType, block_idx: int | None = None
    ) -> VirtualVariable | None:
        reg_offset = get_reg_offset_base(reg_offset, self.model.arch)

        # find the starting block
        for block in self.model.func_graph:
            if block.idx == block_idx and block.addr <= addr < block.addr + block.original_size:
                the_block = block
                break
        else:
            return None

        starting_stmt_idx = len(the_block.statements) if op_type == ObservationPointType.OP_AFTER else 0
        for stmt_idx, stmt in enumerate(the_block.statements):
            if op_type == ObservationPointType.OP_BEFORE and stmt.ins_addr == addr:
                starting_stmt_idx = stmt_idx
                break
            elif op_type == ObservationPointType.OP_AFTER and stmt.ins_addr > addr:
                starting_stmt_idx = stmt_idx
                break

        vvars = set()
        traversed = set()
        queue = [(the_block, starting_stmt_idx)]
        while queue:
            block, start_stmt_idx = queue.pop(0)
            traversed.add(block)

            if start_stmt_idx is not None:
                stmts = block.statements[:start_stmt_idx]
            else:
                stmts = block.statements

            for stmt in reversed(stmts):
                if (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and stmt.dst.was_reg
                    and stmt.dst.reg_offset == reg_offset
                ):
                    vvars.add(stmt.dst)
                    break
                elif isinstance(stmt, Call):
                    if (
                        isinstance(stmt.ret_expr, VirtualVariable)
                        and stmt.ret_expr.was_reg
                        and stmt.ret_expr.reg_offset == reg_offset
                    ):
                        vvars.add(stmt.ret_expr)
                        break
                    # is it clobbered maybe?
                    clobbered_regs = self._get_call_clobbered_regs(stmt)
                    if reg_offset in clobbered_regs:
                        break
            else:
                # not found
                for pred in self.model.func_graph.predecessors(block):
                    if pred not in traversed:
                        traversed.add(pred)
                        queue.append((pred, None))

        assert len(vvars) <= 1
        return next(iter(vvars), None)

    def get_vvar_value(self, vvar: VirtualVariable) -> Expression | None:
        if vvar not in self.model.all_vvar_definitions:
            return None
        codeloc = self.model.all_vvar_definitions[vvar]

        for block in self.model.func_graph:
            if block.addr == codeloc.block_addr and block.idx == codeloc.block_idx:
                if codeloc.stmt_idx < len(block.statements):
                    stmt = block.statements[codeloc.stmt_idx]
                    if isinstance(stmt, Assignment) and stmt.dst.likes(vvar):
                        return stmt.src
                break
        return None

    def observe(self, observation_points: list[ObservationPoint]):

        insn_ops: dict[int, ObservationPointType] = {op[1]: op[2] for op in observation_points if op[0] == "insn"}
        stmt_ops: dict[tuple[tuple[int, int | None], int], ObservationPointType] = {
            op[1]: op[2] for op in observation_points if op[0] == "stmt"
        }
        node_ops: dict[tuple[int, int | None], ObservationPointType] = {
            op[1]: op[2] for op in observation_points if op[0] == "node"
        }
        # TODO: Other types

        traversal_order = GraphUtils.quasi_topological_sort_nodes(self.model.func_graph)
        live_register_to_vvarid: dict[int, int] = {}

        observations = {}
        for block in traversal_order:
            if (block.addr, block.idx) in node_ops and node_ops[
                (block.addr, block.idx)
            ] == ObservationPointType.OP_BEFORE:
                observations[("block", (block.addr, block.idx), ObservationPointType.OP_BEFORE)] = (
                    live_register_to_vvarid.copy()
                )

            last_insn_addr = None
            for stmt_idx, stmt in enumerate(block.statements):
                if last_insn_addr != stmt.ins_addr:
                    # observe
                    if last_insn_addr in insn_ops and insn_ops[last_insn_addr] == ObservationPointType.OP_AFTER:
                        observations[("insn", last_insn_addr, ObservationPointType.OP_AFTER)] = (
                            live_register_to_vvarid.copy()
                        )
                    if stmt.ins_addr in insn_ops and insn_ops[stmt.ins_addr] == ObservationPointType.OP_BEFORE:
                        observations[("insn", last_insn_addr, ObservationPointType.OP_BEFORE)] = (
                            live_register_to_vvarid.copy()
                        )
                    last_insn_addr = stmt.ins_addr

                stmt_key = (block.addr, block.idx), stmt_idx
                if stmt_key in stmt_ops and stmt_ops[stmt_key] == ObservationPointType.OP_BEFORE:
                    observations[("stmt", stmt_key, ObservationPointType.OP_BEFORE)] = live_register_to_vvarid.copy()

                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_reg:
                    base_offset = get_reg_offset_base(stmt.dst.reg_offset, self.model.arch)
                    live_register_to_vvarid[base_offset] = stmt.dst.varid
                elif isinstance(stmt, Call) and isinstance(stmt.ret_expr, VirtualVariable) and stmt.ret_expr.was_reg:
                    base_offset = get_reg_offset_base(stmt.ret_expr.reg_offset, self.model.arch)
                    live_register_to_vvarid[base_offset] = stmt.ret_expr.varid

                if stmt_key in stmt_ops and stmt_ops[stmt_key] == ObservationPointType.OP_AFTER:
                    observations[("stmt", stmt_key, ObservationPointType.OP_AFTER)] = live_register_to_vvarid.copy()

            if (block.addr, block.idx) in node_ops and node_ops[
                (block.addr, block.idx)
            ] == ObservationPointType.OP_AFTER:
                observations[("block", (block.addr, block.idx), ObservationPointType.OP_AFTER)] = (
                    live_register_to_vvarid.copy()
                )

        return observations


class SReachingDefinitionsAnalysis(Analysis):
    """
    Constant and expression propagation that only supports SSA AIL graphs.
    """

    def __init__(
        self, subject, func_graph=None, func_addr: int = None, track_tmps: bool = False, stack_pointer_tracker=None
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
        self.func_addr = func_addr
        self._track_tmps = track_tmps
        self._sp_tracker = stack_pointer_tracker  # FIXME: Is it still used?

        self._bp_as_gpr = False
        if self.func is not None:
            self._bp_as_gpr = self.func.info.get("bp_as_gpr", False)

        self.model = SRDAModel(func_graph, self.project.arch)

        self._analyze()

    def _analyze(self):

        match self.mode:
            case "block":
                blocks = {(self.block.addr, self.block.idx): self.block}
            case "function":
                blocks = {(block.addr, block.idx): block for block in self.func_graph}
            case _:
                raise NotImplementedError()

        # find all vvar definitions
        vvar_deflocs = get_vvar_deflocs(blocks.values())
        # find all explicit vvar uses
        vvar_uselocs = get_vvar_uselocs(blocks.values())

        # update model
        for vvar, defloc in vvar_deflocs.items():
            self.model.all_vvar_definitions[vvar] = defloc

            for vvar_at_use, useloc in vvar_uselocs[vvar.varid]:
                self.model.all_vvar_uses[vvar].add((vvar_at_use, useloc))

        if self.mode == "function":
            # fix register definitions for arguments
            defined_vvarids = {vvar.varid for vvar in vvar_deflocs}
            undefined_vvarids = set(vvar_uselocs.keys()).difference(defined_vvarids)
            for vvar_id in undefined_vvarids:
                used_vvar = next(iter(vvar_uselocs[vvar_id]))[0]
                self.model.all_vvar_definitions[used_vvar] = ExternalCodeLocation()
                self.model.all_vvar_uses[used_vvar] |= vvar_uselocs[vvar_id]

            srda_view = SRDAView(self.model)

            # fix register uses at call sites

            # find all implicit vvar uses
            call_stmt_ids = []
            for block in blocks.values():
                for stmt_idx, stmt in enumerate(block.statements):
                    if isinstance(stmt, Call) and stmt.args is None:
                        call_stmt_ids.append(((block.addr, block.idx), stmt_idx))

            observations = srda_view.observe(
                [("stmt", insn_stmt_id, ObservationPointType.OP_BEFORE) for insn_stmt_id in call_stmt_ids]
            )
            for key, reg_to_vvarids in observations.items():
                _, ((block_addr, block_idx), stmt_idx), _ = key
                block = blocks[(block_addr, block_idx)]
                stmt = block.statements[stmt_idx]

                # just use all registers because we don't know anything about the calling convention
                codeloc = CodeLocation(block_addr, stmt_idx, block_idx=block_idx, ins_addr=stmt.ins_addr)
                for reg_offset, vvar_id in reg_to_vvarids.items():
                    vvar = next(
                        iter(vvar for vvar in self.model.all_vvar_definitions if vvar.varid == vvar_id)
                    )  # TODO: optimize it with a lookup
                    self.model.all_vvar_uses[vvar].add((None, codeloc))

            # fix register uses at return sites
            # ret_site_addrs = {ret_site.addr for ret_site in self.func.ret_sites}
            # if ret_site_addrs:
            #     observations = srda_view.observe(
            #         [
            #             ("node", (block.addr, block.idx), ObservationPointType.OP_AFTER)
            #             for block in blocks.values()
            #             if block.addr in ret_site_addrs
            #         ]
            #     )
            #     for key, reg_to_vvarids in observations.items():
            #         _, (block_addr, block_idx), _ = key
            #         block = blocks[(block_addr, block_idx)]
            #         if not block.statements:
            #             continue
            #         last_stmt = block.statements[-1]
            #         if not isinstance(last_stmt, Return):
            #             continue
        #
        #         if self.project.arch.bp_offset in reg_to_vvarids:
        #             vvar_id = reg_to_vvarids[self.project.arch.bp_offset]
        #             codeloc = CodeLocation(
        #                 block_addr, len(block.statements) - 1, block_idx=block_idx, ins_addr=last_stmt.ins_addr
        #             )
        #             if not self._bp_as_gpr:
        #                 # use bp
        #                 vvar = next(
        #                     iter(vvar for vvar in self.model.all_vvar_definitions if vvar.varid == vvar_id)
        #                 )  # TODO: optimize it with a lookup
        #                 self.model.all_vvar_uses[vvar].add((None, codeloc))

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
