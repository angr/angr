from __future__ import annotations

from collections import deque

import pyvex

from angr.block import Block
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions import Function
from angr.utils.bits import u2s

KIND_SP = 0
KIND_REG = 1
KIND_CONST = 3
KIND_CANARY = 4
KIND_SAVED_CANARY = 5
KIND_CANARY_DIFFERENCE = 6
KIND_CANARY_GUARD = 7

SUBKIND_SP = 0
SUBKIND_BP = 1

type _CanaryFactData = (
    tuple[int, int, int]
    | tuple[int, int, int, BlockNode, int]
    | tuple[int, int, int, BlockNode, int, BlockNode, int]
    | tuple[int, int, int, BlockNode, int, BlockNode, int, bool]
    | None
)


class _CanaryState:
    __slots__ = ("bp_value", "regs", "sp_value", "stack", "stack_aliases", "tls_known")

    def __init__(
        self,
        sp_value: int | None,
        bp_value: int | None,
        regs: dict[tuple[int, int], _CanaryFactData] | None = None,
        stack: dict[int, int] | None = None,
        stack_aliases: dict[tuple[int, int], _CanaryFactData] | None = None,
        tls_known: bool = True,
    ):
        self.sp_value = sp_value
        self.bp_value = bp_value
        self.regs = {} if regs is None else regs
        self.stack = {} if stack is None else stack
        self.stack_aliases = {} if stack_aliases is None else stack_aliases
        self.tls_known = tls_known

    def copy(self) -> _CanaryState:
        return _CanaryState(
            self.sp_value,
            self.bp_value,
            self.regs.copy(),
            self.stack.copy(),
            self.stack_aliases.copy(),
            self.tls_known,
        )

    def merge(self, other: _CanaryState) -> _CanaryState:
        return _CanaryState(
            self.sp_value if self.sp_value == other.sp_value else None,
            self.bp_value if self.bp_value == other.bp_value else None,
            {key: value for key, value in self.regs.items() if other.regs.get(key) == value},
            {offset: size for offset, size in self.stack.items() if other.stack.get(offset) == size},
            {key: value for key, value in self.stack_aliases.items() if other.stack_aliases.get(key) == value},
            self.tls_known and other.tls_known,
        )

    def __eq__(self, other) -> bool:
        return (
            isinstance(other, _CanaryState)
            and self.sp_value == other.sp_value
            and self.bp_value == other.bp_value
            and self.regs == other.regs
            and self.stack == other.stack
            and self.stack_aliases == other.stack_aliases
            and self.tls_known == other.tls_known
        )


class _StackCanaryTracker:
    """
    Tracks stack slots that receive a direct TLS canary on every CFG path and
    are not overwritten through a statically resolved stack address. Unknown
    pointer writes are not must-overwrites: detecting those writes at runtime
    is the reason the compiler emits a canary check. This is intentionally
    smaller than a general reaching-definitions analysis because FactCollector
    runs on many functions.
    """

    def __init__(
        self,
        project,
        function: Function,
        retreg_offset: int,
        tls_reg_offset: int,
        canary_offset: int,
        failure_successors: dict[BlockNode, set[int]],
    ):
        self.project = project
        self.function = function
        self.retreg_offset = retreg_offset
        self.tls_reg_offset = tls_reg_offset
        self.canary_offset = canary_offset
        self.failure_successors = failure_successors
        self._blocks: dict[BlockNode, Block] = {}

    @staticmethod
    def _ranges_overlap(offset_0: int, size_0: int, offset_1: int, size_1: int) -> bool:
        return offset_0 < offset_1 + size_1 and offset_1 < offset_0 + size_0

    def _constant_delta(self, value: int) -> int:
        return u2s(value, self.project.arch.bits)

    def _eval_expr(
        self,
        expr: pyvex.IRExpr.IRExpr,
        state: _CanaryState,
        tmps: dict[int, _CanaryFactData],
        tyenv: pyvex.IRTypeEnv,
    ) -> _CanaryFactData:
        if isinstance(expr, pyvex.IRExpr.Const):
            return (KIND_CONST, 0, expr.con.value)
        if isinstance(expr, pyvex.IRExpr.RdTmp):
            return tmps.get(expr.tmp)
        if isinstance(expr, pyvex.IRExpr.Get):
            if expr.offset == self.project.arch.sp_offset:
                return None if state.sp_value is None else (KIND_SP, SUBKIND_SP, state.sp_value)
            if expr.offset == self.project.arch.bp_offset:
                return None if state.bp_value is None else (KIND_SP, SUBKIND_BP, state.bp_value)
            if expr.offset == self.tls_reg_offset:
                return (KIND_REG, self.tls_reg_offset, 0) if state.tls_known else None
            size = expr.result_size(tyenv) // self.project.arch.byte_width
            return state.regs.get((expr.offset, size))
        if isinstance(expr, pyvex.IRExpr.Load):
            address = self._eval_expr(expr.addr, state, tmps, tyenv)
            size = expr.result_size(tyenv) // self.project.arch.byte_width
            if address == (KIND_REG, self.tls_reg_offset, self.canary_offset) and size == self.project.arch.bytes:
                return (KIND_CANARY, 0, size)
            if address is not None and address[0] == KIND_SP and state.stack.get(address[2]) == size:
                return (KIND_SAVED_CANARY, address[2], size)
            if address is not None and address[0] == KIND_SP:
                return state.stack_aliases.get((address[2], size))
            return None
        if isinstance(expr, pyvex.IRExpr.Unop):
            operand = self._eval_expr(expr.args[0], state, tmps, tyenv)
            if (
                operand is not None
                and operand[0] == KIND_CANARY_GUARD
                and expr.op in {"Iop_1Uto32", "Iop_1Uto64", "Iop_32to1", "Iop_64to1"}
            ):
                return operand
            if (operand == (KIND_REG, self.tls_reg_offset, 0) and expr.op == "Iop_16Uto32") or (
                operand == (KIND_REG, self.tls_reg_offset, self.canary_offset) and expr.op == "Iop_64to32"
            ):
                return operand
            return None
        if isinstance(expr, pyvex.IRExpr.CCall):
            if expr.callee.name != "x86g_use_seg_selector" or len(expr.args) != 4:
                return None
            selector = self._eval_expr(expr.args[2], state, tmps, tyenv)
            offset = self._eval_expr(expr.args[3], state, tmps, tyenv)
            if (
                selector == (KIND_REG, self.tls_reg_offset, 0)
                and offset is not None
                and offset[0] == KIND_CONST
                and offset[2] == self.canary_offset
            ):
                return (KIND_REG, self.tls_reg_offset, self.canary_offset)
            return None
        if not isinstance(expr, pyvex.IRExpr.Binop):
            return None

        operand_0 = self._eval_expr(expr.args[0], state, tmps, tyenv)
        operand_1 = self._eval_expr(expr.args[1], state, tmps, tyenv)
        if expr.op.startswith("Iop_Add"):
            if operand_0 is not None and operand_1 is not None:
                if operand_0[0] in {KIND_SP, KIND_REG} and operand_1[0] == KIND_CONST:
                    return (operand_0[0], operand_0[1], operand_0[2] + self._constant_delta(operand_1[2]))
                if operand_1[0] in {KIND_SP, KIND_REG} and operand_0[0] == KIND_CONST:
                    return (operand_1[0], operand_1[1], operand_1[2] + self._constant_delta(operand_0[2]))
            return None
        if expr.op.startswith("Iop_Sub"):
            if (
                operand_0 is not None
                and operand_1 is not None
                and operand_0[0] in {KIND_SP, KIND_REG}
                and operand_1[0] == KIND_CONST
            ):
                return (operand_0[0], operand_0[1], operand_0[2] - self._constant_delta(operand_1[2]))
            canary_difference = self._canary_pair(operand_0, operand_1)
            if canary_difference is not None:
                return (KIND_CANARY_DIFFERENCE, *canary_difference)
            return None
        if expr.op.startswith("Iop_Xor"):
            canary_difference = self._canary_pair(operand_0, operand_1)
            if canary_difference is not None:
                return (KIND_CANARY_DIFFERENCE, *canary_difference)
            return None
        if expr.op.startswith(("Iop_CmpEQ", "Iop_CmpNE")):
            canary_pair = self._canary_pair(operand_0, operand_1)
            if canary_pair is not None:
                return (KIND_CANARY_GUARD, *canary_pair, expr.op.startswith("Iop_CmpNE"))
            for difference, constant in ((operand_0, operand_1), (operand_1, operand_0)):
                if (
                    difference is not None
                    and difference[0] == KIND_CANARY_DIFFERENCE
                    and len(difference) == 7
                    and constant is not None
                    and constant[0] == KIND_CONST
                    and constant[2] == 0
                ):
                    return (KIND_CANARY_GUARD, *difference[1:], expr.op.startswith("Iop_CmpNE"))
        return None

    @staticmethod
    def _canary_pair(
        operand_0: _CanaryFactData, operand_1: _CanaryFactData
    ) -> tuple[int, int, BlockNode, int, BlockNode, int] | None:
        if operand_0 is None or operand_1 is None:
            return None
        if (
            operand_0[0] == KIND_CANARY
            and len(operand_0) == 5
            and operand_1[0] == KIND_SAVED_CANARY
            and len(operand_1) == 5
        ):
            return operand_1[1], operand_1[2], operand_1[3], operand_1[4], operand_0[3], operand_0[4]
        if (
            operand_1[0] == KIND_CANARY
            and len(operand_1) == 5
            and operand_0[0] == KIND_SAVED_CANARY
            and len(operand_0) == 5
        ):
            return operand_0[1], operand_0[2], operand_0[3], operand_0[4], operand_1[3], operand_1[4]
        return None

    @staticmethod
    def _bind_canary_value(value: _CanaryFactData, node: BlockNode, stmt_idx: int) -> _CanaryFactData:
        if value is not None and value[0] in {KIND_CANARY, KIND_SAVED_CANARY} and len(value) == 3:
            return value[0], value[1], value[2], node, stmt_idx
        return value

    def _write_register(self, state: _CanaryState, offset: int, size: int, value: _CanaryFactData) -> None:
        for existing_offset, existing_size in list(state.regs):
            if self._ranges_overlap(offset, size, existing_offset, existing_size):
                del state.regs[existing_offset, existing_size]
        if value is not None and value[0] in {
            KIND_SP,
            KIND_REG,
            KIND_CANARY,
            KIND_SAVED_CANARY,
            KIND_CANARY_DIFFERENCE,
            KIND_CANARY_GUARD,
        }:
            state.regs[offset, size] = value

    def _kill_stack_range(self, state: _CanaryState, address: _CanaryFactData, size: int) -> None:
        if address is None or address[0] != KIND_SP:
            return
        for existing_offset, existing_size in list(state.stack.items()):
            if self._ranges_overlap(address[2], size, existing_offset, existing_size):
                del state.stack[existing_offset]
        for existing_offset, existing_size in list(state.stack_aliases):
            if self._ranges_overlap(address[2], size, existing_offset, existing_size):
                del state.stack_aliases[existing_offset, existing_size]

    def _kill_tls_canary_provenance(
        self,
        state: _CanaryState,
        tmps: dict[int, _CanaryFactData],
        address: _CanaryFactData,
        size: int,
    ) -> None:
        if (
            address is None
            or address[0] != KIND_REG
            or address[1] != self.tls_reg_offset
            or not self._ranges_overlap(address[2], size, self.canary_offset, self.project.arch.bytes)
        ):
            return
        state.tls_known = False
        for key, value in list(state.regs.items()):
            if value is None or value[0] != KIND_SP:
                del state.regs[key]
        state.stack.clear()
        tmps.clear()

    def _block(self, node: BlockNode) -> Block:
        block = self._blocks.get(node)
        if block is None:
            block = self.project.factory.block(node.addr, size=node.size)
            self._blocks[node] = block
        return block

    def _transfer(self, node: BlockNode, input_state: _CanaryState) -> tuple[_CanaryState, set[tuple[BlockNode, int]]]:
        state = input_state.copy()
        block = self._block(node)
        tyenv = block.vex.tyenv
        if tyenv is None:
            return _CanaryState(None, None, tls_known=False), set()
        tmps: dict[int, _CanaryFactData] = {}
        retval_writes: dict[tuple[int, int, BlockNode, int, BlockNode, int], tuple[BlockNode, int]] = {}
        recognized_writes: set[tuple[BlockNode, int]] = set()
        boring_exit_count = sum(
            isinstance(stmt, pyvex.IRStmt.Exit) and stmt.jumpkind == "Ijk_Boring" for stmt in block.vex.statements
        )
        next_expr = block.vex.next
        default_target = next_expr.con.value if isinstance(next_expr, pyvex.IRExpr.Const) else None
        failure_successors = self.failure_successors.get(node, set())
        saw_exit = False
        path_dependent_state = False

        for stmt_idx, stmt in enumerate(block.vex.statements):
            if saw_exit and (
                isinstance(
                    stmt,
                    (
                        pyvex.IRStmt.Store,
                        pyvex.IRStmt.StoreG,
                        pyvex.IRStmt.CAS,
                        pyvex.IRStmt.LLSC,
                        pyvex.IRStmt.Dirty,
                    ),
                )
                or (isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset != self.project.arch.ip_offset)
            ):
                path_dependent_state = True

            if isinstance(stmt, pyvex.IRStmt.WrTmp):
                tmps[stmt.tmp] = self._bind_canary_value(self._eval_expr(stmt.data, state, tmps, tyenv), node, stmt_idx)
            elif isinstance(stmt, pyvex.IRStmt.Store):
                address = self._eval_expr(stmt.addr, state, tmps, tyenv)
                data = self._eval_expr(stmt.data, state, tmps, tyenv)
                size = stmt.data.result_size(tyenv) // self.project.arch.byte_width
                self._kill_tls_canary_provenance(state, tmps, address, size)
                if address is not None and address[0] == KIND_SP:
                    self._kill_stack_range(state, address, size)
                    if (
                        data is not None
                        and data[0] == KIND_CANARY
                        and data[1] == 0
                        and data[2] == self.project.arch.bytes
                        and size == self.project.arch.bytes
                    ):
                        state.stack[address[2]] = size
                    elif data is not None and data[0] == KIND_SP and size == self.project.arch.bytes:
                        state.stack_aliases[address[2], size] = data
            elif isinstance(stmt, pyvex.IRStmt.StoreG):
                address = self._eval_expr(stmt.addr, state, tmps, tyenv)
                size = stmt.data.result_size(tyenv) // self.project.arch.byte_width
                self._kill_tls_canary_provenance(state, tmps, address, size)
                self._kill_stack_range(state, address, size)
            elif isinstance(stmt, pyvex.IRStmt.CAS):
                address = self._eval_expr(stmt.addr, state, tmps, tyenv)
                size = stmt.dataLo.result_size(tyenv) // self.project.arch.byte_width
                if stmt.dataHi is not None:
                    size += stmt.dataHi.result_size(tyenv) // self.project.arch.byte_width
                self._kill_tls_canary_provenance(state, tmps, address, size)
                self._kill_stack_range(state, address, size)
                tmps[stmt.oldLo] = None
                if stmt.oldHi is not None:
                    tmps[stmt.oldHi] = None
            elif isinstance(stmt, pyvex.IRStmt.LLSC):
                if stmt.storedata is not None:
                    address = self._eval_expr(stmt.addr, state, tmps, tyenv)
                    size = stmt.storedata.result_size(tyenv) // self.project.arch.byte_width
                    self._kill_tls_canary_provenance(state, tmps, address, size)
                    self._kill_stack_range(state, address, size)
                tmps[stmt.result] = None
            elif isinstance(stmt, pyvex.IRStmt.Dirty):
                if stmt.mFx in {"Ifx_Write", "Ifx_Modify"} and stmt.mAddr is not None:
                    address = self._eval_expr(stmt.mAddr, state, tmps, tyenv)
                    self._kill_tls_canary_provenance(state, tmps, address, stmt.mSize)
                    self._kill_stack_range(state, address, stmt.mSize)
                if stmt.nFxState:
                    state.regs.clear()
                if stmt.tmp not in {-1, 0xFFFFFFFF}:
                    tmps[stmt.tmp] = None
            elif isinstance(stmt, pyvex.IRStmt.Put):
                value = self._bind_canary_value(self._eval_expr(stmt.data, state, tmps, tyenv), node, stmt_idx)
                size = stmt.data.result_size(tyenv) // self.project.arch.byte_width
                if stmt.offset == self.project.arch.sp_offset:
                    state.sp_value = value[2] if value is not None and value[0] == KIND_SP else None
                elif stmt.offset == self.project.arch.bp_offset:
                    state.bp_value = value[2] if value is not None and value[0] == KIND_SP else None
                elif stmt.offset == self.tls_reg_offset:
                    state.tls_known = value == (KIND_REG, self.tls_reg_offset, 0)
                else:
                    self._write_register(state, stmt.offset, size, value)
                if (
                    stmt.offset == self.retreg_offset
                    and value is not None
                    and value[0] == KIND_CANARY_DIFFERENCE
                    and len(value) == 7
                ):
                    retval_writes[value[1:]] = node, stmt_idx
            elif isinstance(stmt, pyvex.IRStmt.Exit):
                guard = self._eval_expr(stmt.guard, state, tmps, tyenv)
                if (
                    stmt.jumpkind == "Ijk_Boring"
                    and guard is not None
                    and guard[0] == KIND_CANARY_GUARD
                    and len(guard) == 8
                    and (
                        (stmt.dst.value in failure_successors and guard[7])
                        or (boring_exit_count == 1 and default_target in failure_successors and not guard[7])
                    )
                ):
                    origin = guard[1:7]
                    if origin in retval_writes:
                        recognized_writes.add(retval_writes[origin])
                if stmt.jumpkind == "Ijk_Boring":
                    saw_exit = True

        jumpkind = block.vex.jumpkind
        if jumpkind == "Ijk_Call":
            path_dependent_state |= saw_exit
            state.regs.clear()
            if state.sp_value is None:
                state.stack.clear()
                state.stack_aliases.clear()
            elif self.project.arch.stack_change < 0:
                state.stack = {offset: size for offset, size in state.stack.items() if offset > state.sp_value}
                state.stack_aliases = {
                    key: value for key, value in state.stack_aliases.items() if key[0] > state.sp_value
                }
            else:
                state.stack = {offset: size for offset, size in state.stack.items() if offset < state.sp_value}
                state.stack_aliases = {
                    key: value for key, value in state.stack_aliases.items() if key[0] < state.sp_value
                }
            if self.project.arch.call_pushes_ret and state.sp_value is not None:
                state.sp_value += self.project.arch.bytes
        elif jumpkind is not None and jumpkind.startswith("Ijk_Sys"):
            path_dependent_state |= saw_exit
            state.regs.clear()
        if path_dependent_state:
            state = _CanaryState(None, None, tls_known=False)
        return state, recognized_writes

    def analyze(self) -> set[tuple[BlockNode, int]]:
        startpoint = self.function.startpoint
        if not isinstance(startpoint, BlockNode):
            return set()

        def is_local_block(node) -> bool:
            return isinstance(node, BlockNode) and self.function.get_node(node.addr) == node

        if any(
            is_local_block(target)
            and not data.get("outside", False)
            and (not is_local_block(source) or data.get("type") not in {"transition", "fake_return"})
            for source, target, data in self.function.transition_graph.edges(data=True)
        ):
            return set()
        initial_sp = self.project.arch.bytes if self.project.arch.call_pushes_ret else 0
        input_states = {startpoint: _CanaryState(initial_sp, None)}
        output_states: dict[BlockNode, _CanaryState] = {}
        recognized_by_node: dict[BlockNode, set[tuple[BlockNode, int]]] = {}
        queue = deque([startpoint])
        graph = self.function.transition_graph

        while queue:
            node = queue.popleft()
            output_state, node_writes = self._transfer(node, input_states[node])
            recognized_by_node[node] = node_writes
            if output_states.get(node) == output_state:
                continue
            output_states[node] = output_state
            for _, successor, data in graph.out_edges(node, data=True):
                if (
                    not isinstance(successor, BlockNode)
                    or data.get("outside", False)
                    or data.get("type") not in {"transition", "fake_return"}
                ):
                    continue
                old_input = input_states.get(successor)
                new_input = output_state.copy() if old_input is None else old_input.merge(output_state)
                if old_input != new_input:
                    input_states[successor] = new_input
                    queue.append(successor)

        return set().union(*recognized_by_node.values()) if recognized_by_node else set()
