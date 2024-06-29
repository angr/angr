from __future__ import annotations
from collections import defaultdict

from ailment.block import Block
from ailment.expression import Const, VirtualVariable, VirtualVariableCategory, StackBaseOffset, Load
from ailment.statement import Assignment, Store

from angr.knowledge_plugins.functions import Function
from angr.code_location import CodeLocation
from angr.analyses import Analysis, register_analysis
from angr.utils.ssa import (
    get_vvar_uselocs,
    get_vvar_deflocs,
    is_phi_assignment,
    is_const_assignment,
    is_const_and_vvar_assignment,
    is_const_vvar_load_assignment,
    get_tmp_uselocs,
    get_tmp_deflocs,
)


class SPropagatorModel:
    def __init__(self):
        self.replacements = {}

        self.equivalence = {}


class SPropagatorAnalysis(Analysis):
    """
    Constant and expression propagation that only supports SSA AIL graphs.
    """

    def __init__(
        self,
        subject,
        func_graph=None,
        only_consts: bool = True,
        immediate_stmt_removal: bool = False,
        stack_pointer_tracker=None,
        func_addr: int | None = None,
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
        self.only_consts = only_consts
        self.immediate_stmt_removal = immediate_stmt_removal
        self._sp_tracker = stack_pointer_tracker

        bp_as_gpr = False
        the_func = None
        if self.func is not None:
            the_func = self.func
        else:
            if self.func_addr is not None:
                try:
                    the_func = self.kb.functions.get_by_addr(self.func_addr)
                except KeyError:
                    pass
        if the_func is not None:
            bp_as_gpr = the_func.info.get("bp_as_gpr", False)
        self._bp_as_gpr = bp_as_gpr

        self.model = SPropagatorModel()

        self._analyze()

    @property
    def replacements(self):
        return self.model.replacements

    def _analyze(self):
        match self.mode:
            case "block":
                blocks = {(self.block.addr, self.block.idx): self.block}
            case "function":
                blocks = dict(((block.addr, block.idx), block) for block in self.func_graph)
            case _:
                raise NotImplementedError()

        # find all vvar definitions
        vvar_deflocs = get_vvar_deflocs(blocks.values())
        # find all vvar uses
        vvar_uselocs = get_vvar_uselocs(blocks.values())

        replacements = defaultdict(dict)

        # find constant assignments
        vvarid_to_vvar = {}
        const_vvars: dict[int, Const] = {}
        for vvar, defloc in vvar_deflocs.items():
            vvarid_to_vvar[vvar.varid] = vvar
            defloc = vvar_deflocs[vvar]
            block = blocks[(defloc.block_addr, defloc.block_idx)]
            stmt = block.statements[defloc.stmt_idx]
            r, v = is_const_assignment(stmt)
            if r:
                # replace wherever it's used
                const_vvars[vvar.varid] = v
                for vvar_at_use, useloc in vvar_uselocs[vvar.varid]:
                    replacements[useloc][vvar_at_use] = v
                continue

            r, v = is_phi_assignment(stmt)
            if r:
                src_varids = {vvar.varid for _, vvar in v.src_and_vvars if vvar is not None}
                if all(varid in const_vvars for varid in src_varids):
                    src_values = {
                        (
                            (const_vvars[varid].value, const_vvars[varid].bits)
                            if isinstance(const_vvars[varid], Const)
                            else const_vvars[varid]
                        )
                        for varid in src_varids
                    }
                    if len(src_values) == 1:
                        # replace it!
                        const_vvars[vvar.varid] = const_vvars[next(iter(src_varids))]
                        for vvar_at_use, useloc in vvar_uselocs[vvar.varid]:
                            replacements[useloc][vvar_at_use] = v

            if vvar.varid in vvar_uselocs and len(vvar_uselocs[vvar.varid]) == 1:
                vvar_used, vvar_useloc = next(iter(vvar_uselocs[vvar.varid]))
                if (
                    vvar_useloc.block_addr == defloc.block_addr
                    and vvar_useloc.block_idx == defloc.block_idx
                    and is_const_vvar_load_assignment(stmt)
                    and not any(
                        isinstance(stmt_, Store)
                        for stmt_ in block.statements[defloc.stmt_idx + 1 : vvar_useloc.stmt_idx - 1]
                    )
                ):
                    # we can propagate this load because there is no store between its def and use
                    replacements[vvar_useloc][vvar_used] = stmt.src
                    continue

        for vvar_id, uselocs in vvar_uselocs.items():
            if vvar_id not in vvarid_to_vvar:
                vvar = next(iter(uselocs))[0]
            else:
                vvar = vvarid_to_vvar[vvar_id]

            if self._sp_tracker is not None:
                if vvar.category == VirtualVariableCategory.REGISTER:
                    if vvar.oident == self.project.arch.sp_offset:
                        for vvar_at_use, useloc in vvar_uselocs[vvar.varid]:
                            sb_offset = self._sp_tracker.offset_before(useloc.ins_addr, self.project.arch.sp_offset)
                            if sb_offset is not None:
                                replacements[useloc][vvar_at_use] = StackBaseOffset(
                                    None, self.project.arch.bits, sb_offset
                                )
                        continue
                    elif not self._bp_as_gpr and vvar.oident == self.project.arch.bp_offset:
                        for vvar_at_use, useloc in vvar_uselocs[vvar.varid]:
                            sb_offset = self._sp_tracker.offset_before(useloc.ins_addr, self.project.arch.bp_offset)
                            if sb_offset is not None:
                                replacements[useloc][vvar_at_use] = StackBaseOffset(
                                    None, self.project.arch.bits, sb_offset
                                )
                        continue

        # find all tmp definitions
        tmp_deflocs = get_tmp_deflocs(blocks.values())
        # find all tmp uses
        tmp_uselocs = get_tmp_uselocs(blocks.values())

        for block_loc, tmp_and_uses in tmp_uselocs.items():
            for tmp_atom, tmp_uses in tmp_and_uses.items():
                # take a look at the definition and propagate the definition if supported
                block = blocks[(block_loc.block_addr, block_loc.block_idx)]
                tmp_def_stmtidx = tmp_deflocs[block_loc][tmp_atom]

                stmt = block.statements[tmp_def_stmtidx]
                if isinstance(stmt, Assignment):
                    r, v = is_const_assignment(stmt)
                    if r:
                        # we can propagate it!
                        for tmp_used, tmp_use_stmtidx in tmp_uses:
                            replacements[
                                CodeLocation(block_loc.block_addr, tmp_use_stmtidx, block_idx=block_loc.block_idx)
                            ][tmp_used] = stmt.src
                        continue

                    r = is_const_and_vvar_assignment(stmt)
                    if r:
                        # we can propagate it!
                        if isinstance(stmt.src, VirtualVariable):
                            v = stmt.src if stmt.src.varid not in const_vvars else const_vvars[stmt.src.varid]
                        else:
                            v = stmt.src

                        for tmp_used, tmp_use_stmtidx in tmp_uses:
                            replacements[
                                CodeLocation(block_loc.block_addr, tmp_use_stmtidx, block_idx=block_loc.block_idx)
                            ][tmp_used] = v
                        continue

                    if len(tmp_uses) == 1:
                        tmp_used, tmp_use_stmtidx = next(iter(tmp_uses))
                        if is_const_vvar_load_assignment(stmt) and not any(
                            isinstance(stmt_, Store)
                            for stmt_ in block.statements[tmp_def_stmtidx + 1 : tmp_use_stmtidx - 1]
                        ):
                            # we can propagate this load because there is no store between its def and use
                            replacements[
                                CodeLocation(block_loc.block_addr, tmp_use_stmtidx, block_idx=block_loc.block_idx)
                            ][tmp_used] = stmt.src
                            continue

        self.model.replacements = replacements


register_analysis(SPropagatorAnalysis, "SPropagator")
