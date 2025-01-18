from __future__ import annotations

import contextlib
from collections.abc import Mapping
from collections import defaultdict

import networkx

from ailment.block import Block
from ailment.expression import (
    Const,
    VirtualVariable,
    VirtualVariableCategory,
    StackBaseOffset,
    Load,
    Convert,
    Expression,
)
from ailment.statement import Assignment, Store, Return, Jump

from angr.knowledge_plugins.functions import Function
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.analyses import Analysis, register_analysis
from angr.utils.ssa import (
    get_vvar_uselocs,
    get_vvar_deflocs,
    has_ite_expr,
    has_ite_stmt,
    is_phi_assignment,
    is_const_assignment,
    is_const_and_vvar_assignment,
    is_const_vvar_load_assignment,
    is_const_vvar_load_dirty_assignment,
    is_const_vvar_tmp_assignment,
    get_tmp_uselocs,
    get_tmp_deflocs,
    phi_assignment_get_src,
)


class SPropagatorModel:
    """
    The SPropagator model that stores replacements for virtual variables.
    """

    def __init__(self):
        self.replacements: Mapping[CodeLocation, Mapping[Expression, Expression]] = {}


class SPropagatorAnalysis(Analysis):
    """
    Constant and expression propagation that only supports SSA AIL graphs.
    """

    def __init__(  # pylint: disable=too-many-positional-arguments
        self,
        subject: Block | Function,
        func_graph: networkx.DiGraph | None = None,
        only_consts: bool = True,
        stack_pointer_tracker=None,
        func_args: set[VirtualVariable] | None = None,
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
        self.func_args = func_args
        self.only_consts = only_consts
        self._sp_tracker = stack_pointer_tracker

        bp_as_gpr = False
        the_func = None
        if self.func is not None:
            the_func = self.func
        else:
            if self.func_addr is not None:
                with contextlib.suppress(KeyError):
                    the_func = self.kb.functions.get_by_addr(self.func_addr)
        if the_func is not None:
            bp_as_gpr = the_func.info.get("bp_as_gpr", False)
        self._bp_as_gpr = bp_as_gpr

        self.model = SPropagatorModel()

        self._analyze()

    @property
    def replacements(self):
        return self.model.replacements

    def _analyze(self):
        blocks: dict[tuple[int, int | None], Block]
        match self.mode:
            case "block":
                assert self.block is not None
                blocks = {(self.block.addr, self.block.idx): self.block}
            case "function":
                assert self.func_graph is not None
                blocks = {(block.addr, block.idx): block for block in self.func_graph}
            case _:
                raise NotImplementedError

        # find all vvar definitions
        vvar_deflocs = get_vvar_deflocs(blocks.values())
        # find all vvar uses
        vvar_uselocs = get_vvar_uselocs(blocks.values())

        # update vvar_deflocs using function arguments
        if self.func_args:
            for func_arg in self.func_args:
                vvar_deflocs[func_arg] = ExternalCodeLocation()

        # find all ret sites and indirect jump sites
        retsites: set[tuple[int, int | None, int]] = set()
        jumpsites: set[tuple[int, int | None, int]] = set()
        for bb in blocks.values():
            if bb.statements:
                if isinstance(bb.statements[-1], Return):
                    retsites.add((bb.addr, bb.idx, len(bb.statements) - 1))
                elif isinstance(bb.statements[-1], Jump):
                    jumpsites.add((bb.addr, bb.idx, len(bb.statements) - 1))

        replacements = defaultdict(dict)

        # find constant assignments
        vvarid_to_vvar = {}
        const_vvars: dict[int, Const] = {}
        for vvar, defloc in vvar_deflocs.items():
            if not vvar.was_reg and not vvar.was_parameter:
                continue

            vvarid_to_vvar[vvar.varid] = vvar
            defloc = vvar_deflocs[vvar]
            if isinstance(defloc, ExternalCodeLocation):
                continue

            assert defloc.block_addr is not None
            assert defloc.stmt_idx is not None

            block = blocks[(defloc.block_addr, defloc.block_idx)]
            stmt = block.statements[defloc.stmt_idx]
            r, v = is_const_assignment(stmt)
            if r:
                # replace wherever it's used
                assert v is not None
                const_vvars[vvar.varid] = v
                for vvar_at_use, useloc in vvar_uselocs[vvar.varid]:
                    replacements[useloc][vvar_at_use] = v
                continue

            v = phi_assignment_get_src(stmt)
            if v is not None:
                src_varids = {vvar.varid if vvar is not None else None for _, vvar in v.src_and_vvars}
                if None not in src_varids and all(varid in const_vvars for varid in src_varids):
                    all_int_src_varids: set[int] = {varid for varid in src_varids if varid is not None}
                    src_values = {
                        (
                            (const_vvars[varid].value, const_vvars[varid].bits)
                            if isinstance(const_vvars[varid], Const)
                            else const_vvars[varid]
                        )
                        for varid in all_int_src_varids
                    }
                    if len(src_values) == 1:
                        # replace it!
                        const_value = const_vvars[next(iter(all_int_src_varids))]
                        const_vvars[vvar.varid] = const_value
                        for vvar_at_use, useloc in vvar_uselocs[vvar.varid]:
                            replacements[useloc][vvar_at_use] = const_value

            if self.mode == "function" and vvar.varid in vvar_uselocs:
                if len(vvar_uselocs[vvar.varid]) <= 2 and isinstance(stmt, Assignment) and isinstance(stmt.src, Load):
                    # do we want to propagate this Load expression if it's used for less than twice?
                    # it's often seen in the following pattern, where propagation will be beneficial:
                    #    v0 = Load(...)
                    #    if (!v0) {
                    #       v1 = v0 + 1;
                    #    }
                    can_replace = True
                    for _, vvar_useloc in vvar_uselocs[vvar.varid]:
                        if self.has_store_stmt_in_between(blocks, defloc, vvar_useloc):
                            can_replace = False

                    if can_replace:
                        # we can propagate this load because there is no store between its def and use
                        for vvar_used, vvar_useloc in vvar_uselocs[vvar.varid]:
                            replacements[vvar_useloc][vvar_used] = stmt.src
                        continue

                if len(vvar_uselocs[vvar.varid]) == 1:
                    vvar_used, vvar_useloc = next(iter(vvar_uselocs[vvar.varid]))
                    if is_const_vvar_load_assignment(stmt) and not self.has_store_stmt_in_between(
                        blocks, defloc, vvar_useloc
                    ):
                        # we can propagate this load because there is no store between its def and use
                        replacements[vvar_useloc][vvar_used] = stmt.src
                        continue

                    if is_const_and_vvar_assignment(stmt):
                        # if the useloc is a phi assignment statement, ensure that stmt.src is the same as the phi
                        # variable
                        assert vvar_useloc.block_addr is not None
                        assert vvar_useloc.stmt_idx is not None
                        useloc_stmt = blocks[(vvar_useloc.block_addr, vvar_useloc.block_idx)].statements[
                            vvar_useloc.stmt_idx
                        ]
                        if is_phi_assignment(useloc_stmt):
                            if (
                                isinstance(stmt.src, VirtualVariable)
                                and stmt.src.oident == useloc_stmt.dst.oident
                                and stmt.src.category == useloc_stmt.dst.category
                            ):
                                replacements[vvar_useloc][vvar_used] = stmt.src
                        else:
                            replacements[vvar_useloc][vvar_used] = stmt.src
                        continue

                else:
                    non_exitsite_uselocs = [
                        loc
                        for _, loc in vvar_uselocs[vvar.varid]
                        if (loc.block_addr, loc.block_idx, loc.stmt_idx) not in (retsites | jumpsites)
                    ]
                    if is_const_and_vvar_assignment(stmt):
                        if len(non_exitsite_uselocs) == 1:
                            # this vvar is used once if we exclude its uses at ret sites or jump sites. we can
                            # propagate it
                            for vvar_used, vvar_useloc in vvar_uselocs[vvar.varid]:
                                replacements[vvar_useloc][vvar_used] = stmt.src
                            continue

                        if len(set(non_exitsite_uselocs)) == 1 and not has_ite_expr(stmt.src):
                            useloc = non_exitsite_uselocs[0]
                            assert useloc.block_addr is not None
                            assert useloc.stmt_idx is not None
                            useloc_stmt = blocks[(useloc.block_addr, useloc.block_idx)].statements[useloc.stmt_idx]
                            if stmt.src.depth <= 3 and not has_ite_stmt(useloc_stmt):
                                # remove duplicate use locs (e.g., if the variable is used multiple times by the same
                                # statement) - but ensure stmt is simple enough
                                for vvar_used, vvar_useloc in vvar_uselocs[vvar.varid]:
                                    replacements[vvar_useloc][vvar_used] = stmt.src
                                continue

                # special logic for global variables: if it's used once or multiple times, and the variable is never
                # updated before it's used, we will propagate the load
                if isinstance(stmt, Assignment):
                    stmt_src = stmt.src
                    # unpack conversions
                    while isinstance(stmt_src, Convert):
                        stmt_src = stmt_src.operand
                    if (
                        isinstance(stmt_src, Load)
                        and isinstance(stmt_src.addr, Const)
                        and isinstance(stmt_src.addr.value, int)
                    ):
                        gv_updated = False
                        for _vvar_used, vvar_useloc in vvar_uselocs[vvar.varid]:
                            gv_updated |= self.is_global_variable_updated(
                                self.func_graph,
                                blocks,
                                vvar.varid,
                                stmt_src.addr.value,
                                stmt_src.size,
                                defloc,
                                vvar_useloc,
                            )
                        if not gv_updated:
                            for vvar_used, vvar_useloc in vvar_uselocs[vvar.varid]:
                                replacements[vvar_useloc][vvar_used] = stmt.src
                            continue

        for vvar_id, uselocs in vvar_uselocs.items():
            vvar = next(iter(uselocs))[0] if vvar_id not in vvarid_to_vvar else vvarid_to_vvar[vvar_id]

            if self._sp_tracker is not None and vvar.category == VirtualVariableCategory.REGISTER:
                if vvar.oident == self.project.arch.sp_offset:
                    sp_bits = (
                        (self.project.arch.registers["sp"][1] * self.project.arch.byte_width)
                        if "sp" in self.project.arch.registers
                        else None
                    )
                    for vvar_at_use, useloc in vvar_uselocs[vvar.varid]:
                        sb_offset = self._sp_tracker.offset_before(useloc.ins_addr, self.project.arch.sp_offset)
                        if sb_offset is not None:
                            v = StackBaseOffset(None, self.project.arch.bits, sb_offset)
                            if sp_bits is not None and vvar.bits < sp_bits:
                                # truncation needed
                                v = Convert(None, sp_bits, vvar.bits, False, v)
                            replacements[useloc][vvar_at_use] = v
                    continue
                if not self._bp_as_gpr and vvar.oident == self.project.arch.bp_offset:
                    bp_bits = (
                        (self.project.arch.registers["bp"][1] * self.project.arch.byte_width)
                        if "bp" in self.project.arch.registers
                        else None
                    )
                    for vvar_at_use, useloc in vvar_uselocs[vvar.varid]:
                        sb_offset = self._sp_tracker.offset_before(useloc.ins_addr, self.project.arch.bp_offset)
                        if sb_offset is not None:
                            v = StackBaseOffset(None, self.project.arch.bits, sb_offset)
                            if bp_bits is not None and vvar.bits < bp_bits:
                                # truncation needed
                                v = Convert(None, bp_bits, vvar.bits, False, v)
                            replacements[useloc][vvar_at_use] = v
                    continue

        # find all tmp definitions
        tmp_deflocs = get_tmp_deflocs(blocks.values())
        # find all tmp uses
        tmp_uselocs = get_tmp_uselocs(blocks.values())

        for block_loc, tmp_and_uses in tmp_uselocs.items():
            for tmp_atom, tmp_uses in tmp_and_uses.items():
                # take a look at the definition and propagate the definition if supported
                assert block_loc.block_addr is not None

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

                    r = is_const_vvar_tmp_assignment(stmt)
                    if r:
                        # we can propagate it!
                        if isinstance(stmt.src, VirtualVariable):
                            v = const_vvars.get(stmt.src.varid, stmt.src)
                        else:
                            v = stmt.src

                        for tmp_used, tmp_use_stmtidx in tmp_uses:
                            replacements[
                                CodeLocation(block_loc.block_addr, tmp_use_stmtidx, block_idx=block_loc.block_idx)
                            ][tmp_used] = v
                        continue

                    if len(tmp_uses) <= 2:
                        tmp_used, tmp_use_stmtidx = next(iter(tmp_uses))
                        if is_const_vvar_load_dirty_assignment(stmt):
                            same_inst = (
                                block.statements[tmp_def_stmtidx].ins_addr == block.statements[tmp_use_stmtidx].ins_addr
                            )
                            has_store = any(
                                isinstance(stmt_, Store)
                                for stmt_ in block.statements[tmp_def_stmtidx + 1 : tmp_use_stmtidx]
                            )
                            if same_inst or not has_store:
                                # we can propagate this load because either we do not consider memory aliasing problem
                                # within the same instruction (blocks must be originally lifted with
                                # CROSS_INSN_OPT=False), or there is no store between its def and use.
                                replacements[
                                    CodeLocation(block_loc.block_addr, tmp_use_stmtidx, block_idx=block_loc.block_idx)
                                ][tmp_used] = stmt.src
                                continue

        self.model.replacements = replacements

    @staticmethod
    def is_global_variable_updated(
        func_graph, block_dict, varid: int, gv_addr: int, gv_size: int, defloc: CodeLocation, useloc: CodeLocation
    ) -> bool:
        defblock = block_dict[(defloc.block_addr, defloc.block_idx)]
        useblock = block_dict[(useloc.block_addr, useloc.block_idx)]

        # traverse a graph slice from the def block to the use block and check if the global variable is updated
        seen = {defblock}
        queue = [defblock]
        while queue:
            block = queue.pop(0)

            start_stmt_idx = defloc.stmt_idx if block is defblock else 0  # inclusive
            end_stmt_idx = useloc.stmt_idx if block is useblock else len(block.statements)  # exclusive
            assert start_stmt_idx is not None
            assert end_stmt_idx is not None

            for idx in range(start_stmt_idx, end_stmt_idx):
                stmt = block.statements[idx]
                if isinstance(stmt, Store) and isinstance(stmt.addr, Const):
                    store_addr = stmt.addr.value
                    store_size = stmt.size
                    if gv_addr <= store_addr < gv_addr + gv_size or store_addr <= gv_addr < store_addr + store_size:
                        return True

            if block is useblock:
                continue

            for succ in func_graph.successors(block):
                if succ not in seen:
                    abort_path = False
                    for stmt in succ.statements:
                        if is_phi_assignment(stmt) and any(
                            vvar.varid == varid for _, vvar in stmt.src.src_and_vvars if vvar is not None
                        ):
                            # the virtual variable is no longer live after this point
                            abort_path = True
                            break
                    if abort_path:
                        continue

                    seen.add(succ)
                    queue.append(succ)

        return False

    def has_store_stmt_in_between(
        self, blocks: dict[tuple[int, int | None], Block], defloc: CodeLocation, useloc: CodeLocation
    ) -> bool:
        assert defloc.block_addr is not None
        assert defloc.stmt_idx is not None
        assert useloc.block_addr is not None
        assert useloc.stmt_idx is not None
        assert self.func_graph is not None

        use_block = blocks[(useloc.block_addr, useloc.block_idx)]
        def_block = blocks[(defloc.block_addr, defloc.block_idx)]

        # traverse the graph, go from use_block until we reach def_block, and look for Store statements
        seen = {use_block}
        queue = [use_block]
        while queue:
            block = queue.pop(0)

            starting_stmt_idx, ending_stmt_idx = 0, len(block.statements)
            if block is def_block:
                starting_stmt_idx = defloc.stmt_idx + 1
            if block is use_block:
                ending_stmt_idx = useloc.stmt_idx + 1

            for i in range(starting_stmt_idx, ending_stmt_idx):
                if isinstance(block.statements[i], Store):
                    return True

            if block is def_block:
                continue

            for pred in self.func_graph.predecessors(block):
                if pred not in seen:
                    seen.add(pred)
                    queue.append(pred)

        return False


register_analysis(SPropagatorAnalysis, "SPropagator")
