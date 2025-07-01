from __future__ import annotations
from typing import TYPE_CHECKING
import logging

import claripy
import pyvex

from angr.knowledge_plugins.propagations import PropagationModel
from angr.utils.constants import DEFAULT_STATEMENT
from angr.code_location import CodeLocation
from angr.blade import Blade
from angr.analyses.propagator import vex_vars
from angr.utils.vex import get_tmp_def_stmt
from .resolver import IndirectJumpResolver
from .propagator_utils import PropagatorLoadCallback

if TYPE_CHECKING:
    from angr import Block

_l = logging.getLogger(name=__name__)


def exists_in_replacements(replacements, block_loc, tmp_var):
    exists = False
    for rep in replacements:
        if rep == block_loc:
            exists = True
            break

    if not exists:
        return False

    exists = False
    for var in replacements[block_loc]:
        if var == tmp_var:
            exists = True
            break

    return exists


class ConstantResolver(IndirectJumpResolver):
    """
    Resolve an indirect jump by running a constant propagation on the entire function and check if the indirect jump can
    be resolved to a constant value. This resolver must be run after all other more specific resolvers.
    """

    def __init__(self, project, max_func_nodes: int = 512):
        super().__init__(project, timeless=False)
        self.max_func_nodes = max_func_nodes

        # stats
        self._resolved = 0
        self._unresolved = 0
        self._cache_hits = 0
        self._props_saved = 0

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        if not cfg.functions.contains_addr(func_addr):
            # the function does not exist
            return False

        # for performance, we don't run constant resolver if the function is too large
        func = cfg.functions.get_by_addr(func_addr)
        if len(func.block_addrs_set) > self.max_func_nodes:
            return False

        # we support both an indirect call and jump since the value can be resolved

        return jumpkind in {"Ijk_Boring", "Ijk_Call"}

    def resolve(  # pylint:disable=unused-argument
        self, cfg, addr: int, func_addr: int, block: Block, jumpkind: str, func_graph_complete: bool = True, **kwargs
    ):
        """
        This function does the actual resolve. Our process is easy:
        Propagate all values inside the function specified, then extract
        the tmp_var used for the indirect jump from the basic block.
        Use the tmp var to locate the constant value stored in the replacements.
        If not present, returns False tuple.

        :param cfg:         CFG with specified function
        :param addr:        Address of indirect jump
        :param func_addr:   Address of function of indirect jump
        :param block:       Block of indirect jump (Block object)
        :param jumpkind:    VEX jumpkind (Ijk_Boring or Ijk_Call)
        :return:            Bool tuple with replacement address
        """
        if not cfg.functions.contains_addr(func_addr):
            #  the function does not exist
            return False, []

        func = cfg.functions.get_by_addr(func_addr)

        vex_block = block.vex
        if isinstance(vex_block.next, pyvex.expr.RdTmp):
            tmp_stmt_idx, tmp_ins_addr = self._find_tmp_write_stmt_and_ins(vex_block, vex_block.next.tmp)
            if tmp_stmt_idx is None or tmp_ins_addr is None:
                return False, []

            # first check: is it jumping to a target loaded from memory? if so, it should have been resolved by
            # MemoryLoadResolver.
            stmt = vex_block.statements[tmp_stmt_idx]
            assert isinstance(stmt, pyvex.IRStmt.WrTmp)
            if (
                isinstance(stmt.data, pyvex.IRExpr.Load)
                and isinstance(stmt.data.addr, pyvex.IRExpr.Const)
                and stmt.data.result_size(vex_block.tyenv) == self.project.arch.bits
            ):
                # well, if MemoryLoadResolver hasn't resolved it, we can try to resolve it here, or bail early because
                # ConstantResolver won't help.
                load_addr = stmt.data.addr.con.value
                try:
                    value = self.project.loader.memory.unpack_word(load_addr, size=self.project.arch.bytes)
                    if isinstance(value, int) and self._is_target_valid(cfg, value):
                        return True, [value]
                except KeyError:
                    pass
                return False, []

            # second check: what does the jump rely on? slice it back and see
            b = Blade(
                cfg.graph,
                addr,
                -1,
                cfg=cfg,
                project=self.project,
                ignore_bp=False,
                ignore_sp=False,
                max_level=3,
                stop_at_calls=True,
                cross_insn_opt=True,
                control_dependence=False,
            )
            stmt_loc = addr, DEFAULT_STATEMENT
            if self._check_jump_target_is_loaded_from_dynamic_addr(b, stmt_loc):
                # loading from memory - unsupported
                return False, []
            if self._check_jump_target_is_compared_against(b, stmt_loc):
                # the jump/call target is compared against another value, which means it's not deterministic
                # ConstantResolver does not support such cases by design
                return False, []

            # first check the replacements cache
            resolved_tmp = None
            is_full_func_prop = None
            block_loc = CodeLocation(block.addr, tmp_stmt_idx, ins_addr=tmp_ins_addr)
            tmp_var = vex_vars.VEXTmp(vex_block.next.tmp)
            prop_key = "FCP", func_addr
            cached_prop = cfg.kb.propagations.get(prop_key)
            if cached_prop is not None:
                is_full_func_prop = len(func.block_addrs_set) == cached_prop.function_block_count
                replacements = cached_prop.replacements
                if exists_in_replacements(replacements, block_loc, tmp_var):
                    self._cache_hits += 1
                    resolved_tmp = replacements[block_loc][tmp_var]

            if resolved_tmp is None and is_full_func_prop:
                self._props_saved += 1

            if resolved_tmp is None and not is_full_func_prop:
                _l.debug("ConstantResolver: Propagating for %r at %#x.", func, addr)
                prop = self.project.analyses.FastConstantPropagation(
                    func,
                    vex_cross_insn_opt=False,
                    load_callback=PropagatorLoadCallback(self.project).propagator_load_callback,
                )
                # update the cache
                model = PropagationModel(
                    prop_key, replacements=prop.replacements, function_block_count=len(func.block_addrs_set)
                )
                cfg.kb.propagations.update(prop_key, model)

                replacements = prop.replacements
                if replacements and exists_in_replacements(replacements, block_loc, tmp_var):
                    resolved_tmp = replacements[block_loc][tmp_var]

            if resolved_tmp is not None:
                if (
                    isinstance(resolved_tmp, claripy.ast.Base)
                    and resolved_tmp.op == "BVV"
                    and self._is_target_valid(cfg, resolved_tmp.args[0])
                ):
                    self._resolved += 1
                    # print(f"{self._resolved} ({self._props_saved} saved, {self._cache_hits} cached) / "
                    #       f"{self._resolved + self._unresolved}")
                    # print(f"+ Function: {func_addr:#x}, block {addr:#x}, target {resolved_tmp.args[0]:#x}")
                    return True, [resolved_tmp.args[0]]
                if isinstance(resolved_tmp, int) and self._is_target_valid(cfg, resolved_tmp):
                    self._resolved += 1
                    # print(f"{self._resolved} ({self._props_saved} saved, {self._cache_hits} cached) / "
                    #       f"{self._resolved + self._unresolved}")
                    # print(f"+ Function: {func_addr:#x}, block {addr:#x}, target {resolved_tmp:#x}")
                    return True, [resolved_tmp]

        self._unresolved += 1
        # print(f"{RESOLVED} ({SAVED_PROPS} saved, {HIT_CACHE} cached) / {RESOLVED + UNRESOLVED}")
        # print(f"- Function: {func_addr:#x}, block {addr:#x}, FAILED")
        return False, []

    def _check_jump_target_is_loaded_from_dynamic_addr(self, b, stmt_loc) -> bool:
        queue: list[tuple[int, int, int]] = []  # depth, block_addr, stmt_idx
        seen_locs: set[tuple[int, int]] = set()
        for block_addr, stmt_idx in b.slice.predecessors(stmt_loc):
            if (block_addr, stmt_idx) in seen_locs:
                continue
            seen_locs.add((block_addr, stmt_idx))
            queue.append((0, block_addr, stmt_idx))
        while queue:
            depth, pred_addr, stmt_idx = queue.pop(0)
            if depth >= 3:
                break

            # skip all IMarks
            if stmt_idx != DEFAULT_STATEMENT:
                block = self.project.factory.block(pred_addr, cross_insn_opt=True).vex
                stmt = block.statements[stmt_idx]
                if isinstance(stmt, pyvex.IRStmt.IMark):
                    for succ_addr, succ_stmt_idx in b.slice.predecessors((pred_addr, stmt_idx)):
                        if (succ_addr, succ_stmt_idx) in seen_locs:
                            continue
                        seen_locs.add((succ_addr, succ_stmt_idx))
                        queue.append((depth + 1 if succ_addr != pred_addr else depth, succ_addr, succ_stmt_idx))
                    continue

                if (
                    isinstance(stmt, pyvex.IRStmt.WrTmp)
                    and isinstance(stmt.data, pyvex.IRExpr.Load)
                    and not isinstance(stmt.data.addr, pyvex.IRExpr.Const)
                ):
                    # loading from memory
                    return True

            for succ_addr, succ_stmt_idx in b.slice.predecessors((pred_addr, stmt_idx)):
                if (succ_addr, succ_stmt_idx) in seen_locs:
                    continue
                seen_locs.add((succ_addr, succ_stmt_idx))
                queue.append((depth + 1 if succ_addr != pred_addr else depth, succ_addr, succ_stmt_idx))

        return False

    def _check_jump_target_is_compared_against(self, b, stmt_loc) -> bool:
        # let's find which register the jump uses
        jump_site = self.project.factory.block(stmt_loc[0], cross_insn_opt=True).vex
        if not isinstance(jump_site.next, pyvex.IRExpr.RdTmp):
            return False
        next_tmp = jump_site.next.tmp
        # find its definition
        next_tmp_def = get_tmp_def_stmt(jump_site, next_tmp)
        if next_tmp_def is None:
            return False
        next_tmp_def_stmt = jump_site.statements[next_tmp_def]
        if not (
            isinstance(next_tmp_def_stmt, pyvex.IRStmt.WrTmp) and isinstance(next_tmp_def_stmt.data, pyvex.IRExpr.Get)
        ):
            return False
        next_reg = next_tmp_def_stmt.data.offset

        # traverse back at most one level and check:
        # - this register has never been updated
        # - a comparison is conducted on this register (via a tmp, most likely)
        queue = []
        seen = set()
        for block_addr, stmt_idx in b.slice.predecessors(stmt_loc):
            if (block_addr, stmt_idx) in seen:
                continue
            seen.add((block_addr, stmt_idx))
            queue.append((0, block_addr, stmt_idx))
        while queue:
            depth, pred_addr, stmt_idx = queue.pop(0)
            if depth > 1:
                continue

            # skip all IMarks
            pred = pred_addr, stmt_idx
            if stmt_idx != DEFAULT_STATEMENT:
                block = self.project.factory.block(pred_addr, cross_insn_opt=True).vex
                stmt = block.statements[stmt_idx]
                if isinstance(stmt, pyvex.IRStmt.IMark):
                    for succ_addr, succ_stmt_idx in b.slice.predecessors(pred):
                        if (succ_addr, succ_stmt_idx) in seen:
                            continue
                        seen.add((succ_addr, succ_stmt_idx))
                        queue.append((depth + 1 if succ_addr != pred_addr else depth, succ_addr, succ_stmt_idx))
                    continue

                if isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == next_reg:
                    # this register has been updated before we find a comparison; do not continue along this path
                    continue

                if (
                    isinstance(stmt, pyvex.IRStmt.WrTmp)
                    and isinstance(stmt.data, pyvex.IRExpr.Binop)
                    and stmt.data.op.startswith("Iop_Cmp")
                ):
                    # what is it comparing against?
                    for arg in stmt.data.args:
                        if isinstance(arg, pyvex.IRExpr.RdTmp):
                            arg_tmp_def = get_tmp_def_stmt(block, arg.tmp)
                            if arg_tmp_def is not None:
                                arg_tmp_def_stmt = block.statements[arg_tmp_def]
                                if (
                                    isinstance(arg_tmp_def_stmt, pyvex.IRStmt.WrTmp)
                                    and isinstance(arg_tmp_def_stmt.data, pyvex.IRExpr.Get)
                                    and arg_tmp_def_stmt.data.offset == next_reg
                                ):
                                    # the jump target is compared against this register
                                    return True
                                # another case: VEX optimization may have caused the tmp to be stored in the target
                                # register. we need handle this case as well.
                                if any(
                                    isinstance(stmt_, pyvex.IRStmt.Put)
                                    and stmt_.offset == next_reg
                                    and isinstance(stmt_.data, pyvex.IRExpr.RdTmp)
                                    and stmt_.data.tmp == arg.tmp
                                    for stmt_ in block.statements[arg_tmp_def + 1 : stmt_idx]
                                ):
                                    # the jump target is compared against this register
                                    return True

            # continue traversing predecessors
            for succ_addr, succ_stmt_idx in b.slice.predecessors(pred):
                if (succ_addr, succ_stmt_idx) in seen:
                    continue
                seen.add((succ_addr, succ_stmt_idx))
                queue.append((depth + 1 if succ_addr != pred_addr else depth, succ_addr, succ_stmt_idx))

        return False

    @staticmethod
    def _find_tmp_write_stmt_and_ins(vex_block, tmp: int) -> tuple[int | None, int | None]:
        stmt_idx = None
        for idx, stmt in enumerate(reversed(vex_block.statements)):
            if isinstance(stmt, pyvex.IRStmt.IMark) and stmt_idx is not None:
                ins_addr = stmt.addr + stmt.delta
                return stmt_idx, ins_addr
            if isinstance(stmt, pyvex.IRStmt.WrTmp) and stmt.tmp == tmp:
                stmt_idx = len(vex_block.statements) - idx - 1
        return None, None
