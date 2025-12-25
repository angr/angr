# pylint:disable=too-many-boolean-expressions,unused-argument
from __future__ import annotations
import logging
from collections import defaultdict

from archinfo import Endness

from angr.ailment import Block
from angr.ailment.statement import WeakAssignment
from angr.ailment.expression import VirtualVariable, BinaryOp, Const, Load
from angr.sim_type import SimType, SimTypePointer, SimTypeChar

from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(name=__name__)


class EagerStdStringConcatenationPass(OptimizationPass):
    """
    Concatenate multiple constant std::string creation calls into one when possible.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Condense multiple constant std::string creation calls into one when possible"
    DESCRIPTION = __doc__.strip()  # type: ignore

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        callgraph = self.kb.functions.callgraph
        if self._func.addr not in callgraph:
            # this is a manually created function - always run this optimization pass
            return True, {}
        callees = set(callgraph.successors(self._func.addr))
        string_construction_calls_found = False
        for callee_addr in callees:
            if not self.kb.functions.contains_addr(callee_addr):
                continue
            callee_func = self.kb.functions.get_by_addr(callee_addr)
            demangled_name = callee_func.demangled_name
            if "std::basic_string" in demangled_name and (
                "operator+" in demangled_name or "operator=" in demangled_name
            ):
                string_construction_calls_found = True
                break

        return string_construction_calls_found, {}

    def _analyze(self, cache=None):
        cfg = self.kb.cfgs.get_most_accurate()
        assert cfg is not None

        # iterate over all blocks and look for the following patterns
        # Pattern 1:
        # 00 | LABEL_4025fd:
        # 01 | vvar_21619{s-128|1b} =W Load(addr=0x4511f0<32>, size=222, endness=Iend_BE)
        #
        # 00 | LABEL_40265d:
        # 01 | vvar_21619{s-128|1b} =W (vvar_21619{s-128|1b} + Load(addr=0x451110<32>, size=222, endness=Iend_BE))
        #
        # Pattern 2:
        #
        # 00 | LABEL_40265d:
        # 01 | vvar_21619{s-128|1b} =W (vvar_21619{s-128|1b} + Load(addr=0x451110<32>, size=222, endness=Iend_BE))
        #
        # 00 | LABEL_40268c:
        # 01 | vvar_21619{s-128|1b} =W (vvar_21619{s-128|1b} + Load(addr=0x451030<32>, size=222, endness=Iend_BE))

        entry_block = self._get_block(self.entry_node_addr[0], idx=self.entry_node_addr[1])
        assert entry_block is not None

        traversed = set()
        queue = [entry_block]
        while queue:
            block = queue.pop(0)
            key = block.addr, block.idx
            if key in traversed:
                continue
            traversed.add(key)

            succs = list(self._graph.successors(block))
            for succ in succs:
                succ_key = succ.addr, succ.idx
                if succ_key in traversed:
                    continue
                sub_traversed, new_exits = self._traverse_linear(succ, cfg)
                traversed |= sub_traversed
                queue.extend(new_exits)

    def _traverse_linear(self, start_block: Block, cfg) -> tuple[set[tuple[int, int | None]], list[Block]]:
        traversed = set()
        last_block = start_block

        str_defs: dict[int, bytes] = {}
        succs = []
        stmts_to_remove: dict[int, list[tuple[tuple[int, int | None], int]]] = defaultdict(list)
        while True:
            key = last_block.addr, last_block.idx
            if key in traversed:
                break
            traversed.add(key)

            succs = list(self._graph.successors(last_block))
            if len(succs) > 1 or not succs:
                # this is where the linear traversal ends
                break

            succ = succs[0]

            # find both patterns
            for stmt_idx, stmt in enumerate(succ.statements):
                if isinstance(stmt, WeakAssignment):
                    # pattern 1
                    is_std_string_assign, assigned_str = self._match_std_string_assignment(stmt, cfg)
                    if is_std_string_assign:
                        assert assigned_str is not None
                        # found a std::string assignment
                        str_defs[stmt.dst.varid] = assigned_str
                        stmts_to_remove[stmt.dst.varid].append(((succ.addr, succ.idx), stmt_idx))
                        continue

                    # pattern 2
                    is_std_string_concat, concatenated_str = self._match_std_string_concatenation(stmt, cfg, str_defs)
                    if is_std_string_concat:
                        assert concatenated_str is not None
                        # found a std::string concatenation
                        str_defs[stmt.dst.varid] = concatenated_str
                        stmts_to_remove[stmt.dst.varid].append(((succ.addr, succ.idx), stmt_idx))
                        continue

            last_block = succ

        # process the blocks
        for varid, stmt_locs in stmts_to_remove.items():
            final_str = str_defs[varid]
            str_id = self.kb.custom_strings.allocate(final_str)

            # replace the very last statement with the final string assignment
            last_stmt_block_loc, last_stmt_idx = stmt_locs[-1]
            old_block = self._get_block(last_stmt_block_loc[0], idx=last_stmt_block_loc[1])
            assert old_block is not None
            block = old_block.copy()
            old_stmt = block.statements[last_stmt_idx]
            block.statements[last_stmt_idx] = WeakAssignment(
                old_stmt.idx,
                old_stmt.dst,
                Load(
                    None,
                    Const(None, None, str_id, self.project.arch.bits, custom_string=True),
                    len(final_str),
                    Endness.BE,
                ),
                **old_stmt.tags,
            )
            self._update_block(old_block, block)

            # remove all other statements
            for stmt_block_loc, stmt_idx in reversed(stmt_locs[:-1]):
                old_block = self._get_block(stmt_block_loc[0], idx=stmt_block_loc[1])
                assert old_block is not None
                block = old_block.copy()
                del block.statements[stmt_idx]
                self._update_block(old_block, block)

        return traversed, succs

    def _match_std_string_assignment(self, stmt: WeakAssignment, cfg) -> tuple[bool, bytes | None]:
        if (
            "type" in stmt.tags
            and "dst" in stmt.tags["type"]
            and "src" in stmt.tags["type"]
            and isinstance(stmt.dst, VirtualVariable)
            and isinstance(stmt.src, Load)
            and isinstance(stmt.src.addr, Const)
        ):
            dst_ty, src_ty = stmt.tags["type"]["dst"], stmt.tags["type"]["src"]
            if (
                self._is_std_string_type(dst_ty)
                and self._is_std_string_type_or_charptr(src_ty)
                and isinstance(stmt.src.addr.value, int)
                and stmt.src.addr.value in cfg.memory_data
                and cfg.memory_data[stmt.src.addr.value_int].sort == "string"
            ):
                s = cfg.memory_data[stmt.src.addr.value_int].content
                return True, s
        return False, None

    def _match_std_string_concatenation(
        self, stmt: WeakAssignment, cfg, str_defs: dict[int, bytes]
    ) -> tuple[bool, bytes | None]:
        if (
            "type" in stmt.tags
            and "dst" in stmt.tags["type"]
            and "src" in stmt.tags["type"]
            and isinstance(stmt.dst, VirtualVariable)
            and isinstance(stmt.src, BinaryOp)
            and stmt.src.op == "Add"
        ):
            dst_ty, src_ty = stmt.tags["type"]["dst"], stmt.tags["type"]["src"]
            if self._is_std_string_type(dst_ty) and self._is_std_string_type_or_charptr(src_ty):
                op0, op1 = stmt.src.operands
                if isinstance(op1, VirtualVariable) and isinstance(op0, Load):
                    op0, op1 = op1, op0
                if (
                    isinstance(op0, VirtualVariable)
                    and op0.varid in str_defs
                    and isinstance(op1, Load)
                    and isinstance(op1.addr, Const)
                    and isinstance(op1.addr.value, int)
                    # is op1 a constant string?
                    and op1.addr.value in cfg.memory_data
                    and cfg.memory_data[op1.addr.value].sort == "string"
                ):
                    op1_str = cfg.memory_data[op1.addr.value].content
                    # is op0 also an std::string?
                    op0_str = str_defs[op0.varid]
                    if op0_str is not None and op1_str is not None:
                        final_str = op0_str + op1_str
                        return True, final_str
        return False, None

    @staticmethod
    def _is_std_string_type(t: SimType) -> bool:
        type_str = t.c_repr().removeprefix("const ").removesuffix("&").strip(" ")
        return type_str == "class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>"

    @staticmethod
    def _is_std_string_type_or_charptr(t: SimType) -> bool:
        if isinstance(t, SimTypePointer) and isinstance(t.pts_to, SimTypeChar):
            return True
        return EagerStdStringConcatenationPass._is_std_string_type(t)
