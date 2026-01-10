from __future__ import annotations
from typing import TYPE_CHECKING, TypeAlias
import itertools
import logging

import claripy

import angr
from angr.engines.ail.callstack import AILCallStack
from angr.engines.light.engine import SimEngineLightAIL
from angr import ailment, errors
from angr.engines.successors import SimSuccessors
from angr.sim_state import SimState
from angr.engines.vex.claripy import ccall
from angr.storage.memory_mixins.memory_mixin import MemoryMixin
from angr.utils.constants import DEFAULT_STATEMENT

if TYPE_CHECKING:
    from angr.project import Project
    from angr.analyses.decompiler.clinic import Clinic

log = logging.getLogger(__name__)

StateType: TypeAlias = SimState[ailment.Address, ailment.Address]
DataType: TypeAlias = claripy.ast.Bits | claripy.ast.Bool


class CallReached(Exception):
    """
    An exception to abort executing a block if we need to restart it with a call result
    """


class SimEngineAILSimState(SimEngineLightAIL[StateType, DataType, bool, None]):
    """
    A light engine for symbolically executing AIL
    """

    def __init__(
        self,
        project: Project,
        successors: SimSuccessors,
    ):
        self.successors = successors
        self.ret_idx = 0
        super().__init__(project)

    def process(
        self, state: StateType, *, block: ailment.Block | None = None, whitelist: set[int] | None = None, **kwargs
    ) -> None:
        self.state = state
        self.state.bbl_addr = state.addr[0]
        # if there is a function parameter handoff waiting, process that asap
        if self.frame.passed_args is not None:
            clinic = self.lift_addr(state.addr)
            assert clinic.arg_vvars is not None
            expected = len(clinic.arg_vvars)
            got = len(self.frame.passed_args)
            if got < expected:
                raise errors.AngrRuntimeError(
                    f"Function entry missing args: expected={expected} got={got} at {state.addr}"
                )
            if got > expected:
                log.debug("Function entry extra args: expected=%d got=%d at %s", expected, got, state.addr)
            for idx, value in enumerate(self.frame.passed_args):
                if idx >= len(clinic.arg_vvars):
                    break
                vvar, _ = clinic.arg_vvars[idx]
                self._do_assign(vvar, value, auto_narrow=True)
            self.frame.passed_args = None

        if self.frame.resume_at is not None:
            if block is None:
                block = self.lift(state)
            whitelist2 = set(range(self.frame.resume_at, len(block.statements)))
            if whitelist is None:
                whitelist = whitelist2
            else:
                whitelist.intersection_update(whitelist2)
        super().process(state, block=block, whitelist=whitelist, **kwargs)

    @property
    def frame(self) -> AILCallStack:
        callstack = self.state.callstack
        assert isinstance(callstack, AILCallStack)
        return callstack

    def lift_addr(self, addr: ailment.Address) -> Clinic:
        result = self.state.globals["ail_lifter"]  # type: ignore
        assert callable(result)
        return result(addr[0])  # type: ignore

    def lift(self, state: StateType | int | ailment.Address) -> ailment.Block:
        addr = (state, None) if isinstance(state, int) else state if isinstance(state, tuple) else state.addr
        clinic = self.lift_addr(addr)
        assert clinic.cc_graph is not None
        blocks = [blk for blk in clinic.cc_graph if (blk.addr, blk.idx) == addr]
        if len(blocks) == 0:
            raise errors.AngrLifterError("Lifted graph does not have the needed block")
        if len(blocks) > 1:
            raise errors.AngrLifterError("Lifted graph contains more than one of the needed block")
        return blocks[0]

    def _top(self, bits):
        return claripy.BVS("ail_engine_top", bits)

    def _is_top(self, expr):
        return expr.op == "BVS" and expr.args[0].name.startswith("ail_engine_top")

    def _find_ptr_region(self, ptr: claripy.ast.BV) -> tuple[MemoryMixin, claripy.ast.BV | int]:
        region: MemoryMixin | None = None
        offset = 0
        queue = [ptr]
        while queue:
            node = queue.pop()
            if node.op == "__add__":
                queue.extend(node.args)  # type: ignore
            elif node.op == "__sub__":
                queue.append(node.args[0])  # type: ignore
                queue.extend(-x for x in node.args[1:])  # type: ignore
            elif node.op == "BVS":
                frame = self.frame
                while frame is not None:
                    referred = frame.var_refs.get(node, None)
                    if referred is None:
                        frame = frame.next
                        continue
                    if region is None:
                        _region = frame.vars[referred]
                        assert isinstance(_region, MemoryMixin)
                        region = _region
                    else:
                        log.warning("Emulation is adding together two pointers")
                        return self.state.memory, ptr
                    break
                else:
                    offset += node
            else:
                offset += node

        if region is None:
            return self.state.memory, ptr
        return region, offset

    def _stmt_diverges(self, result):
        return not result

    def _process_block_end(self, block: ailment.Block, stmt_data: list[bool], whitelist: set[int] | None) -> None:
        if all(stmt_data):
            # this is a block lifted such that we don't have explicit gotos. Find one from the graph
            clinic = self.lift_addr(self.state.addr)
            assert clinic.cc_graph is not None
            if len(clinic.cc_graph.succ[block]) > 1:
                raise errors.AngrRuntimeError(
                    f"Reached default exit of block with {len(clinic.cc_graph.succ[block])} successors"
                )
            if len(clinic.cc_graph.succ[block]) == 0:
                # deadend. add pathterminator
                self.successors.add_successor(
                    self.state,
                    self.state.addr,
                    claripy.true(),
                    "Ijk_Exit",
                    add_guard=False,
                    exit_ins_addr=self.ins_addr,
                    exit_stmt_idx=DEFAULT_STATEMENT,
                )
                return
            succ = next(iter(clinic.cc_graph.succ[block]))
            self.successors.add_successor(
                self.state,
                (succ.addr, succ.idx),
                claripy.true(),
                "Ijk_Boring",
                add_guard=False,
                exit_ins_addr=self.ins_addr,
                exit_stmt_idx=DEFAULT_STATEMENT,
            )

    def _stmt(self, stmt: ailment.statement.Statement, toplevel: bool = True) -> bool:
        if toplevel:
            self.ret_idx = 0
            self.state.scratch.stmt_idx = self.stmt_idx
            self.state.scratch.ins_addr = self.ins_addr
        try:
            result = super()._stmt(stmt)
        except CallReached as e:
            if not toplevel:
                raise errors.AngrRuntimeError(
                    "there is absolutely no good way to emulate this. generate better IR."
                ) from e
            # assume we've already pushed the callee frame
            # furthermore assume that it's okay to mutate callstack.next since it should be unique still...?
            assert self.frame.next is not None
            self.frame.next.resume_at = self.stmt_idx
            return False
        else:
            if toplevel:
                self.frame.passed_rets = ()
                self.frame.resume_at = None
            return result

    def _expr_bool(self, expr) -> claripy.ast.Bool:
        result = self._expr(expr)
        if isinstance(result, claripy.ast.BV) and len(result) == 1:
            result = result != 0
        assert isinstance(result, claripy.ast.Bool)
        return result

    def _expr_bits(self, expr) -> claripy.ast.Bits:
        result = self._expr(expr)
        assert isinstance(result, claripy.ast.Bits)
        return result

    def _expr_bv(self, expr) -> claripy.ast.BV:
        result = self._expr(expr)
        assert isinstance(result, claripy.ast.BV)
        return result

    def _expr_fp(self, expr) -> claripy.ast.FP:
        result = self._expr(expr)
        assert isinstance(result, claripy.ast.FP)
        return result

    def _do_call(self, call: ailment.statement.Call, is_expr: bool = False):
        arguments = tuple(self._expr_bits(e) for e in (call.args or []))

        if angr.options.CALLLESS in self.state.options:
            if is_expr:
                # ????? if doing ret emulation and this is an expr (no lvalue expression)
                # how do I tell if this is a float ret or not?
                return (claripy.BVS(f"callless_stub_{call.target}", call.bits),)
            if call.ret_expr is not None:
                return (claripy.BVS(f"callless_stub_{call.target}", call.ret_expr.bits),)
            if call.fp_ret_expr is not None:
                return (
                    claripy.FPS(
                        f"callless_stub_{call.target}",
                        claripy.FSORT_FLOAT if call.fp_ret_expr.bits == 32 else claripy.FSORT_DOUBLE,
                    ),
                )
            return ()
        target_addr = self._expr_bv(call.target)
        assert target_addr.concrete
        if self.ret_idx < len(self.frame.passed_rets):
            results = self.frame.passed_rets[self.ret_idx]
            self.ret_idx += 1
            return results
        target = (target_addr.concrete_value, None)

        new_frame = AILCallStack(func_addr=target)
        new_frame.passed_args = arguments
        new_frame.return_addr = self.state.addr
        self.frame.push(new_frame)

        self.successors.add_successor(
            self.state,
            target,
            claripy.true(),
            "Ijk_Call",
            add_guard=False,
            exit_ins_addr=self.ins_addr,
            exit_stmt_idx=self.stmt_idx,
        )
        raise CallReached

    def _do_assign(self, dst: ailment.Expression, val: claripy.ast.Bits, auto_narrow: bool = False):
        if len(val) != dst.bits:
            if auto_narrow and len(val) > dst.bits and isinstance(val, claripy.ast.BV):
                val = val[dst.bits - 1 : 0]
            else:
                raise errors.AngrRuntimeError(f"Bad-sized assignment: expected {dst.bits} bits, got {len(val)}")
        match dst:
            case ailment.expression.VirtualVariable():
                if isinstance((mem := self.frame.vars.get(dst.varid, None)), MemoryMixin):
                    mem.store(0, val, endness=self.state.arch.memory_endness)
                else:
                    self.frame.vars[dst.varid] = val
            case ailment.expression.Register():
                self.state.registers.store(dst.reg_offset, val)
            case ailment.expression.Tmp():
                self.tmps[dst.tmp_idx] = val
            case _:
                assert False, f"Unsupported type of assignemnt dst {type(dst)}"

    def _handle_stmt_Assignment(self, stmt) -> bool:
        val = self._expr_bits(stmt.src)
        self._do_assign(stmt.dst, val)
        return True

    def _handle_stmt_Store(self, stmt: ailment.statement.Store) -> bool:
        val = self._expr(stmt.data)
        ptr = self._expr_bv(stmt.addr)
        region, offset = self._find_ptr_region(ptr)
        region.store(offset, val, endness=stmt.endness)
        return True

    def _handle_stmt_WeakAssignment(self, stmt: ailment.statement.WeakAssignment) -> bool:
        raise NotImplementedError(ailment.statement.WeakAssignment)

    def _handle_stmt_CAS(self, stmt: ailment.statement.CAS) -> bool:
        raise NotImplementedError(ailment.statement.CAS)

    def _handle_stmt_Jump(self, stmt: ailment.statement.Jump) -> bool:
        target_addr = self._expr_bv(stmt.target)
        assert target_addr.concrete
        target = (target_addr.concrete_value, stmt.target_idx)
        self.successors.add_successor(
            self.state,
            target,
            claripy.true(),
            "Ijk_Boring",
            add_guard=False,
            exit_ins_addr=self.ins_addr,
            exit_stmt_idx=self.stmt_idx,
        )
        return False

    def _handle_stmt_ConditionalJump(self, stmt: ailment.statement.ConditionalJump) -> bool:
        condition = self._expr_bool(stmt.condition)
        state_true = self.state.copy()
        state_false = self.state
        target_true_addr = self._expr_bv(stmt.true_target)
        assert target_true_addr.concrete
        if stmt.false_target is None:
            target_false_addr = None
        else:
            target_false_addr = self._expr_bv(stmt.false_target)
            assert target_false_addr.concrete
        self.successors.add_successor(
            state_true,
            (target_true_addr.concrete_value, stmt.true_target_idx),
            condition,
            "Ijk_Boring",
            exit_stmt_idx=self.stmt_idx,
            exit_ins_addr=self.ins_addr,
        )
        if target_false_addr is not None:
            self.successors.add_successor(
                state_false,
                (target_false_addr.concrete_value, stmt.false_target_idx),
                ~condition,  # type: ignore
                "Ijk_Boring",
                exit_stmt_idx=self.stmt_idx,
                exit_ins_addr=self.ins_addr,
            )
            return False
        return True

    def _handle_stmt_Return(self, stmt: ailment.statement.Return) -> bool:
        ret_values = tuple(self._expr_bits(e) for e in stmt.ret_exprs)
        target = self.frame.return_addr
        this_frame = self.frame
        # store vvars if needed
        # TODO move this to the history plugin
        if this_frame.vars:
            if "vvars" not in self.state.globals:
                self.state.globals["vvars"] = {}
            if this_frame.func_addr not in self.state.globals["vvars"]:
                self.state.globals["vvars"][this_frame.func_addr] = []
            self.state.globals["vvars"][this_frame.func_addr].append(this_frame.vars)
        self.frame.pop()
        self.frame.passed_rets += (ret_values,)
        self.successors.add_successor(
            self.state,
            target if target is not None else self.state.addr,
            claripy.true(),
            "Ijk_Ret" if target is not None else "Ijk_Exit",
            add_guard=False,
            exit_ins_addr=self.ins_addr,
            exit_stmt_idx=self.stmt_idx,
        )
        return False

    def _handle_stmt_DirtyStatement(self, stmt: ailment.statement.DirtyStatement) -> bool:
        raise NotImplementedError(ailment.statement.DirtyStatement)

    def _handle_stmt_Label(self, stmt: ailment.statement.Label) -> bool:
        return True

    def _handle_stmt_Call(self, stmt: ailment.statement.Call) -> bool:
        results = self._do_call(stmt)
        ret_expr = stmt.ret_expr or stmt.fp_ret_expr
        ret_exprs = [] if ret_expr is None else [ret_expr]
        if len(results) < len(ret_exprs):
            raise errors.AngrRuntimeError(
                f"Call statement expects {len(ret_exprs)} return value(s) but called function provided {len(results)}"
            )
        for ret_expr, result in zip(ret_exprs, results):
            # these may be provided by misbehaving simprocedures. truncate the result as needed.
            self._do_assign(ret_expr, result, auto_narrow=True)
        return True

    ### Expressions

    def _handle_expr_Call(self, expr: ailment.statement.Call) -> DataType:
        results = self._do_call(expr, True)
        if len(results) != 1:
            raise errors.AngrRuntimeError(f"Call expression returned with {len(results)} return values, expected 1")
        # these may be provided by misbehaving simprocedures. truncate the result as needed.
        result = results[0]
        if len(result) > expr.bits:
            assert isinstance(result, claripy.ast.BV)
            result = result[expr.bits - 1 : 0]
        elif len(result) < expr.bits:
            raise errors.AngrRuntimeError("Function returned too-small value for lvalue expression")
        return result

    def _handle_expr_Const(self, expr: ailment.expression.Const) -> claripy.ast.Bits:
        if isinstance(expr.value, int):
            return claripy.BVV(expr.value, expr.bits)
        if isinstance(expr.value, float):
            if expr.bits == 32:
                return claripy.FPV(expr.value, claripy.FSORT_FLOAT)
            if expr.bits == 64:
                return claripy.FPV(expr.value, claripy.FSORT_DOUBLE)
            raise TypeError(f"Bad width of float const {expr.bits}")
        raise TypeError(f"Bad const value type {type(expr.value)}")

    def _handle_expr_Register(self, expr: ailment.expression.Register) -> claripy.ast.Bits:
        return self.state.registers.load(expr.reg_offset, expr.size)

    def _handle_expr_Load(self, expr: ailment.expression.Load) -> claripy.ast.Bits:
        ptr = self._expr_bv(expr.addr)
        size = expr.size if isinstance(expr.size, int) else self._expr(expr.size)
        region, offset = self._find_ptr_region(ptr)
        return region.load(offset, size, endness=expr.endness)

    def _handle_expr_VirtualVariable(self, expr: ailment.expression.VirtualVariable) -> DataType:
        if isinstance((val := self.frame.vars.get(expr.varid, None)), MemoryMixin):
            return val.load(0, expr.size, endness=self.state.arch.memory_endness)
        if val is None:
            # unconstrained
            if angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY in self.state.options:
                val = claripy.BVV(0, expr.bits)
            elif angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY in self.state.options:
                val = claripy.BVS(f"unconstrained_vvar_{expr.varid}", expr.bits)
            else:
                raise errors.AngrRuntimeError(f"Load of vvar_{expr.varid} but it has no assigned value")
            self.frame.vars[expr.varid] = val
        return val

    def _handle_expr_Tmp(self, expr: ailment.expression.Tmp) -> DataType:
        return self.tmps[expr.tmp_idx]

    def _handle_expr_Phi(self, expr: ailment.expression.Phi) -> DataType:
        parent = self.state.history.parent
        if parent is None or not parent.recent_bbl_addrs:
            return self._top(expr.bits)

        last_addr = parent.recent_bbl_addrs[-1]

        # If we're resuming execution inside the same block (e.g., after a call/return),
        # the immediate "previous block" in history may be the current block itself.
        # Phi semantics are based on the *CFG predecessor at block entry*.
        # Walk backwards until we find a different block address.
        if last_addr == self.state.addr:
            cur_hist = parent.parent
            while cur_hist is not None:
                if cur_hist.recent_bbl_addrs:
                    cand = cur_hist.recent_bbl_addrs[-1]
                    if cand != self.state.addr:
                        last_addr = cand
                        break
                cur_hist = cur_hist.parent

        for src, vvar in expr.src_and_vvars:
            if src != last_addr:
                continue
            if vvar is None:
                break
            return self._handle_expr_VirtualVariable(vvar)

        log.info("Cannot resolve Phi predecessor %s in %s at %s. Returning top.", last_addr, expr, self.state.addr)
        return self._top(expr.bits)

    def _handle_expr_Convert(self, expr: ailment.expression.Convert) -> DataType:
        child = self._expr(expr.operand)
        assert len(child) == expr.from_bits
        if expr.from_type == expr.TYPE_INT:
            if isinstance(child, claripy.ast.Bool):
                assert expr.from_bits == 1
                assert expr.to_type == expr.TYPE_INT
                return claripy.If(child, claripy.BVV(1, expr.to_bits), claripy.BVV(0, expr.to_bits))
            assert isinstance(child, claripy.ast.BV)
            if expr.to_type == expr.TYPE_INT:
                if expr.to_bits > expr.from_bits:
                    if expr.is_signed:
                        return child.sign_extend(expr.to_bits - expr.from_bits)
                    return child.zero_extend(expr.to_bits - expr.from_bits)
                return child[expr.to_bits - 1 : 0]
            if expr.to_type == expr.TYPE_FP:
                to_sort = claripy.FSORT_DOUBLE if expr.to_bits == 64 else claripy.FSORT_FLOAT
                return child.val_to_fp(to_sort, expr.is_signed, expr.rounding_mode)
            assert False
        elif expr.from_type == expr.TYPE_FP:
            assert isinstance(child, claripy.ast.FP)
            if expr.to_type == expr.TYPE_INT:
                return child.val_to_bv(expr.to_bits, expr.is_signed)
            if expr.to_type == expr.TYPE_FP:
                to_sort = claripy.FSORT_DOUBLE if expr.to_bits == 64 else claripy.FSORT_FLOAT
                return child.to_fp(to_sort, expr.rounding_mode)
            assert False
        else:
            assert False

    def _handle_expr_Reinterpret(self, expr: ailment.expression.Reinterpret) -> DataType:
        child = self._expr_bits(expr.operand)
        assert len(child) == expr.from_bits
        if expr.from_type == expr.TYPE_INT:
            assert isinstance(child, claripy.ast.BV)
            if expr.to_type == expr.TYPE_INT:
                assert False, "I think this is unreachable"
            elif expr.to_type == expr.TYPE_FP:
                assert expr.from_size == expr.to_size
                return child.raw_to_fp()
            else:
                assert False
        elif expr.from_type == expr.TYPE_FP:
            assert isinstance(child, claripy.ast.FP)
            if expr.to_type == expr.TYPE_INT:
                assert expr.from_size == expr.to_size
                return child.raw_to_bv()
            if expr.to_type == expr.TYPE_FP:
                assert False, "I think this is unreachable"
            else:
                assert False
        else:
            assert False

    def _handle_expr_ITE(self, expr: ailment.expression.ITE) -> DataType:
        cond = self._expr_bool(expr.cond)
        if cond.is_true():
            return self._expr_bits(expr.iftrue)
        if cond.is_false():
            return self._expr_bits(expr.iffalse)
        return claripy.If(cond, self._expr_bits(expr.iftrue), self._expr_bits(expr.iffalse))

    def _handle_expr_DirtyExpression(self, expr: ailment.expression.DirtyExpression) -> DataType:
        raise NotImplementedError(ailment.expression.DirtyExpression)

    def _handle_expr_VEXCCallExpression(self, expr: ailment.expression.VEXCCallExpression) -> DataType:
        handler = getattr(ccall, expr.callee, None)
        if handler is None:
            return self._top(expr.bits)
        args = tuple(self._expr_bits(arg) for arg in expr.operands)
        return handler(self.state, *args)

    def _handle_expr_MultiStatementExpression(self, expr: ailment.expression.MultiStatementExpression) -> DataType:
        for stmt in expr.stmts:
            self._stmt(stmt, False)
        return self._expr(expr.expr)

    def _handle_expr_BasePointerOffset(self, expr: ailment.expression.BasePointerOffset) -> DataType:
        return self._expr_bv(expr.base) + expr.offset

    def _handle_expr_StackBaseOffset(self, expr: ailment.expression.StackBaseOffset) -> DataType:
        assert self.frame.stack_ptr is not None
        return claripy.BVV(self.frame.stack_ptr + expr.offset, expr.bits)

    def _handle_unop_Neg(self, expr: ailment.UnaryOp):
        v = self._expr_bv(expr.operand)
        return -v

    def _handle_unop_Not(self, expr: ailment.UnaryOp):
        v = self._expr_bv(expr.operand)
        return ~v

    def _handle_unop_BitwiseNeg(self, expr: ailment.UnaryOp):
        v = self._expr_bv(expr.operand)
        return ~v

    def _handle_unop_Reference(self, expr: ailment.expression.UnaryOp) -> DataType:
        match expr.operand:
            case ailment.expression.VirtualVariable():
                curval = self.frame.vars.get(expr.operand.varid, None)
                if isinstance(curval, MemoryMixin):
                    return self.frame.var_refs_rev[expr.operand.varid]

                func_name = self.lift_addr(self.state.addr).function.name
                region_name = f"ail_engine_var_{func_name}_{expr.operand.varid}"

                # pick a class, any class...
                memory_cls = self.state.globals["ail_var_memory_cls"]  # type: ignore
                newval = memory_cls(memory_id=region_name)
                assert isinstance(newval, MemoryMixin)
                newval.set_state(self.state)
                if curval is not None:
                    newval.store(0, curval, endness=self.state.arch.memory_endness)
                newptr = claripy.BVS(region_name, expr.bits)
                self.frame.vars[expr.operand.varid] = newval
                self.frame.var_refs[newptr] = expr.operand.varid
                self.frame.var_refs_rev[expr.operand.varid] = newptr
                return newptr
            case _:
                raise errors.AngrRuntimeError(f"Can't handle reference to {expr.operand}")

    def _handle_unop_Dereference(self, expr: ailment.expression.UnaryOp) -> DataType:
        ptr = self._expr_bv(expr.operand)
        region, offset = self._find_ptr_region(ptr)
        return region.load(offset, expr.size, endness=expr.endness)

    def _handle_unop_Clz(self, expr: ailment.expression.UnaryOp) -> DataType:
        operand = self._expr(expr.operand)
        wtf_expr = claripy.BVV(expr.bits, expr.bits)
        for a in range(expr.bits):
            bit = claripy.Extract(a, a, operand)
            wtf_expr = claripy.If(bit == 1, claripy.BVV(expr.bits - a - 1, expr.bits), wtf_expr)
        return wtf_expr

    def _handle_unop_Ctz(self, expr: ailment.expression.UnaryOp) -> DataType:
        operand = self._expr(expr.operand)
        wtf_expr = claripy.BVV(expr.bits, expr.bits)
        for a in reversed(range(expr.bits)):
            bit = claripy.Extract(a, a, operand)
            wtf_expr = claripy.If(bit == 1, claripy.BVV(a, expr.bits), wtf_expr)
        return wtf_expr

    def _handle_unop_GetMSBs(self, expr: ailment.expression.UnaryOp) -> DataType:
        operand = self._expr(expr.operand)
        size = expr.bits
        bits = [claripy.Extract(i, i, operand) for i in range(size - 1, 6, -8)]
        return claripy.Concat(*bits)

    def _handle_unop_unpack(self, expr: ailment.expression.UnaryOp) -> DataType:
        raise NotImplementedError("Not sure what the semantics of this op are")

    def _handle_unop_Sqrt(self, expr: ailment.expression.UnaryOp) -> DataType:
        raise NotImplementedError("Not sure how to express this in claripy")

    def _handle_unop_RSqrtEst(self, expr: ailment.expression.UnaryOp) -> DataType:
        raise NotImplementedError("Not sure what the semantics of this op are")

    def _handle_binop_Add(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) + self._expr_bv(expr.operands[1])

    def _handle_binop_Sub(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) - self._expr_bv(expr.operands[1])

    def _handle_binop_Mul(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) * self._expr_bv(expr.operands[1])

    def _handle_binop_Div(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) / self._expr_bv(expr.operands[1])

    def _handle_binop_Mod(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) % self._expr_bv(expr.operands[1])

    def _handle_binop_AddF(self, expr: ailment.expression.BinaryOp) -> DataType:
        return claripy.ast.fp.fpAdd(
            expr.rounding_mode, self._expr_fp(expr.operands[0]), self._expr_fp(expr.operands[1])
        )

    def _handle_binop_SubF(self, expr: ailment.expression.BinaryOp) -> DataType:
        return claripy.ast.fp.fpSub(
            expr.rounding_mode, self._expr_fp(expr.operands[0]), self._expr_fp(expr.operands[1])
        )

    def _handle_binop_MulF(self, expr: ailment.expression.BinaryOp) -> DataType:
        return claripy.ast.fp.fpMul(
            expr.rounding_mode, self._expr_fp(expr.operands[0]), self._expr_fp(expr.operands[1])
        )

    def _handle_binop_DivF(self, expr: ailment.expression.BinaryOp) -> DataType:
        return claripy.ast.fp.fpDiv(
            expr.rounding_mode, self._expr_fp(expr.operands[0]), self._expr_fp(expr.operands[1])
        )

    def _handle_binop_AddV(self, expr: ailment.expression.BinaryOp) -> DataType:
        assert expr.vector_size is not None
        return claripy.Concat(
            *(
                a + b
                for a, b in zip(
                    self._expr_bv(expr.operands[0]).chop(expr.vector_size),
                    self._expr_bv(expr.operands[1]).chop(expr.vector_size),
                )
            )
        )

    def _handle_binop_SubV(self, expr: ailment.expression.BinaryOp) -> DataType:
        assert expr.vector_size is not None
        return claripy.Concat(
            *(
                a - b
                for a, b in zip(
                    self._expr_bv(expr.operands[0]).chop(expr.vector_size),
                    self._expr_bv(expr.operands[1]).chop(expr.vector_size),
                )
            )
        )

    def _handle_binop_MulV(self, expr: ailment.expression.BinaryOp) -> DataType:
        assert expr.vector_size is not None
        return claripy.Concat(
            *(
                a * b
                for a, b in zip(
                    self._expr_bv(expr.operands[0]).chop(expr.vector_size),
                    self._expr_bv(expr.operands[1]).chop(expr.vector_size),
                )
            )
        )

    def _handle_binop_DivV(self, expr: ailment.expression.BinaryOp) -> DataType:
        assert expr.vector_size is not None
        return claripy.Concat(
            *(
                a / b
                for a, b in zip(
                    self._expr_bv(expr.operands[0]).chop(expr.vector_size),
                    self._expr_bv(expr.operands[1]).chop(expr.vector_size),
                )
            )
        )

    def _handle_binop_Mull(self, expr: ailment.expression.BinaryOp) -> DataType:
        a = self._expr_bv(expr.operands[0])
        b = self._expr_bv(expr.operands[1])
        op = claripy.SignExt if expr.signed else claripy.ZeroExt
        return op(expr.bits - len(a), a) * op(expr.bits - len(b), b)

    def _handle_binop_MulHiV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure what the semantics of this op are")

    def _handle_binop_Xor(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) ^ self._expr_bv(expr.operands[1])

    def _handle_binop_And(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) & self._expr_bv(expr.operands[1])

    def _handle_binop_Or(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) | self._expr_bv(expr.operands[1])

    def _handle_binop_LogicalAnd(self, expr: ailment.expression.BinaryOp) -> DataType:
        a = self._expr_bv(expr.operands[0])
        if (a == 0).is_true():
            return a
        return claripy.If(a != 0, a, self._expr_bv(expr.operands[1]))

    def _handle_binop_LogicalOr(self, expr: ailment.expression.BinaryOp) -> DataType:
        a = self._expr_bv(expr.operands[0])
        if (a == 0).is_false():
            return a
        return claripy.If(a == 0, a, self._expr_bv(expr.operands[1]))

    def _handle_binop_Shl(self, expr: ailment.expression.BinaryOp) -> DataType:
        shift_amount = self._expr_bv(expr.operands[1])
        if shift_amount.size() < expr.bits:
            shift_amount = claripy.ZeroExt(expr.bits - shift_amount.size(), shift_amount)
        return self._expr_bv(expr.operands[0]) << shift_amount

    def _handle_binop_Shr(self, expr: ailment.expression.BinaryOp) -> DataType:
        shift_amount = self._expr_bv(expr.operands[1])
        if shift_amount.size() < expr.bits:
            shift_amount = claripy.ZeroExt(expr.bits - shift_amount.size(), shift_amount)
        return claripy.LShR(self._expr_bv(expr.operands[0]), shift_amount)

    def _handle_binop_Sar(self, expr: ailment.expression.BinaryOp) -> DataType:
        shift_amount = self._expr_bv(expr.operands[1])
        if shift_amount.size() < expr.bits:
            shift_amount = claripy.ZeroExt(expr.bits - shift_amount.size(), shift_amount)
        return self._expr_bv(expr.operands[0]) >> shift_amount

    def _handle_binop_CmpF(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure what the semantics of this op are")

    def _handle_binop_CmpEQ(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) == self._expr_bv(expr.operands[1])

    def _handle_binop_CmpNE(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) != self._expr_bv(expr.operands[1])

    def _handle_binop_CmpLT(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) < self._expr_bv(expr.operands[1])

    def _handle_binop_CmpLE(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) <= self._expr_bv(expr.operands[1])

    def _handle_binop_CmpGT(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) > self._expr_bv(expr.operands[1])

    def _handle_binop_CmpGE(self, expr: ailment.expression.BinaryOp) -> DataType:
        return self._expr_bv(expr.operands[0]) >= self._expr_bv(expr.operands[1])

    def _handle_binop_Concat(self, expr: ailment.expression.BinaryOp) -> DataType:
        return claripy.Concat(self._expr_bv(expr.operands[0]), self._expr_bv(expr.operands[1]))

    def _handle_binop_Rol(self, expr: ailment.expression.BinaryOp) -> DataType:
        shift_amount = self._expr_bv(expr.operands[1])
        if shift_amount.size() < expr.bits:
            shift_amount = claripy.ZeroExt(expr.bits - shift_amount.size(), shift_amount)
        return claripy.RotateLeft(self._expr_bv(expr.operands[0]), shift_amount)

    def _handle_binop_Ror(self, expr: ailment.expression.BinaryOp) -> DataType:
        shift_amount = self._expr_bv(expr.operands[1])
        if shift_amount.size() < expr.bits:
            shift_amount = claripy.ZeroExt(expr.bits - shift_amount.size(), shift_amount)
        return claripy.RotateRight(self._expr_bv(expr.operands[0]), shift_amount)

    def _handle_binop_Carry(self, expr: ailment.expression.BinaryOp) -> DataType:
        a = self._expr_bv(expr.operands[0])
        b = self._expr_bv(expr.operands[1])
        res = a + b
        return claripy.If(claripy.ULT(res, a), claripy.BVV(1, 1), claripy.BVV(0, 1))

    def _handle_binop_SCarry(self, expr: ailment.expression.BinaryOp) -> DataType:
        # TODO am I wrong here? why is this not just expr.signed??
        a = self._expr_bv(expr.operands[0])
        b = self._expr_bv(expr.operands[1])
        res = a + b
        return claripy.If(claripy.SLT(res, a), claripy.BVV(1, 1), claripy.BVV(0, 1))

    def _handle_binop_SBorrow(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_InterleaveLOV(self, expr: ailment.expression.BinaryOp) -> DataType:
        assert expr.vector_size is not None
        assert expr.vector_count is not None
        left_vector = [
            self._expr_bv(expr.operands[0])[(i + 1) * expr.vector_size - 1 : i * expr.vector_size]
            for i in range(expr.vector_count // 2)
        ]
        right_vector = [
            self._expr_bv(expr.operands[1])[(i + 1) * expr.vector_size - 1 : i * expr.vector_size]
            for i in range(expr.vector_count // 2)
        ]
        return claripy.Concat(*itertools.chain.from_iterable(zip(reversed(left_vector), reversed(right_vector))))

    def _handle_binop_InterleaveHIV(self, expr: ailment.expression.BinaryOp) -> DataType:
        assert expr.vector_size is not None
        assert expr.vector_count is not None
        left_vector = [
            self._expr_bv(expr.operands[0])[(i + 1) * expr.vector_size - 1 : i * expr.vector_size]
            for i in range(expr.vector_count // 2, expr.vector_count)
        ]
        right_vector = [
            self._expr_bv(expr.operands[1])[(i + 1) * expr.vector_size - 1 : i * expr.vector_size]
            for i in range(expr.vector_count // 2, expr.vector_count)
        ]
        return claripy.Concat(*itertools.chain.from_iterable(zip(reversed(left_vector), reversed(right_vector))))

    def _handle_binop_CasCmpEQ(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_CasCmpNE(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_ExpCmpNE(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_SarN(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_SarNV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_ShrNV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_ShlNV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_CmpEQV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_CmpNEV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_CmpGEV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_CmpGTV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_CmpLEV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_CmpLTV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_MinV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_MaxV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_QAddV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_QNarrowBin(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_QNarrowBinV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_PermV(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_Set(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")

    def _handle_binop_CmpORD(self, expr: ailment.expression.BinaryOp) -> DataType:
        raise NotImplementedError("Not sure of the semantics of this op")
