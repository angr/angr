# pylint:disable=missing-class-docstring,too-many-boolean-expressions
from __future__ import annotations

import logging
import operator
import struct
from collections.abc import Callable
from itertools import chain
from typing import cast

from archinfo.types import RegisterOffset

from angr import ailment, claripy
from angr.calling_conventions import SimRegArg, SimTypeBottom, default_cc_for_project
from angr.claripy.vsa import mv_eval
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.engines.light import SpOffset
from angr.engines.light.engine import SimEngineNostmtAIL
from angr.errors import SimEngineError, SimMemoryMissingError
from angr.knowledge_plugins.key_definitions.atoms import Atom, MemoryLocation, Register, Tmp
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.knowledge_plugins.key_definitions.live_definitions import Definition, LiveDefinitions

from .function_handler import FunctionCallData, FunctionHandler
from .rd_state import ReachingDefinitionsState, shift_amount
from .subject import SubjectType

l = logging.getLogger(name=__name__)


class SimEngineRDAIL(SimEngineNostmtAIL[ReachingDefinitionsState, claripy.ast.BV, None, ReachingDefinitionsState]):
    def __init__(
        self,
        project,
        function_handler: FunctionHandler,
        stack_pointer_tracker=None,
        use_callee_saved_regs_at_return=True,
        bp_as_gpr: bool = False,
        variable_map=None,
    ):
        super().__init__(project)
        self._function_handler = function_handler
        self._visited_blocks = None
        self._dep_graph = None
        self._stack_pointer_tracker = stack_pointer_tracker
        self._use_callee_saved_regs_at_return = use_callee_saved_regs_at_return
        self.bp_as_gpr = bp_as_gpr
        self._variable_map = variable_map

    def _is_top(self, expr):
        """
        Values with several alternatives are not really "top" in the stricter sense. They are just a collection of
        values, some of which might be top
        """
        return False

    def _top(self, bits) -> claripy.ast.BV:
        return self.state.top(bits)

    def process(
        self, state, *, dep_graph=None, visited_blocks=None, block=None, fail_fast=False, whitelist=None, **kwargs
    ):
        self._dep_graph = dep_graph
        self._visited_blocks = visited_blocks

        try:
            result_state = super().process(state, whitelist=whitelist, block=block)
        except SimEngineError:
            if fail_fast is True:
                raise
            result_state = state
        return result_state

    def _process_block_end(self, block, stmt_data, whitelist):
        return self.state

    #
    # Private methods
    #

    def _fp_op(self, bits: int, op: Callable[..., claripy.ast.FP], *operands: claripy.ast.BV) -> claripy.ast.BV:
        """
        Evaluate a floating-point operation. Values are stored as IEEE bit patterns, so they are reinterpreted as
        floats for the operation and back afterwards. Only single, concrete float or double operands are computed.
        """
        if bits not in (32, 64):
            return self._top(bits)
        fp_operands = []
        for v in operands:
            if v.symbolic or v.size() != bits:
                return self._top(bits)
            fp_operands.append(v.raw_to_fp())
        return op(*fp_operands).raw_to_bv()

    def _external_codeloc(self):
        return ExternalCodeLocation(self.state.codeloc.context)

    def _set_codeloc(self):
        # TODO do we want a better mechanism to specify context updates?
        new_codeloc = CodeLocation(
            self.block.addr,
            self.stmt_idx,
            ins_addr=self.ins_addr,
            block_idx=self.block.idx,
            context=self.state.codeloc.context,
        )
        self.state.move_codelocs(new_codeloc)
        self.state.analysis.model.at_new_stmt(new_codeloc)

    #
    # AIL statement handlers
    #

    def _stmt(self, stmt):
        if self.state.analysis:
            self.state.analysis.stmt_observe(self.stmt_idx, stmt, self.block, self.state, OP_BEFORE)
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

        self._set_codeloc()
        super()._stmt(stmt)

        if self.state.analysis:
            self.state.analysis.stmt_observe(self.stmt_idx, stmt, self.block, self.state, OP_AFTER)
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_AFTER)

    def _handle_stmt_Assignment(self, stmt):
        src = self._expr(stmt.src)
        dst = stmt.dst

        if isinstance(dst, ailment.Tmp):
            self.state.kill_and_add_definition(Tmp(dst.tmp_idx, dst.size), src)
            self.tmps[dst.tmp_idx] = src

        elif isinstance(dst, ailment.Register):
            reg = Register(RegisterOffset(dst.reg_offset), dst.size)
            self.state.kill_and_add_definition(reg, src)

            if dst.reg_offset == self.arch.sp_offset:
                self.state._sp_adjusted = True
                # TODO: Special logic that frees all definitions above the current stack pointer
        else:
            l.warning("Unsupported type of Assignment dst %s.", type(dst).__name__)

    def _handle_stmt_CAS(self, stmt: ailment.statement.CAS):
        addr = self._expr(stmt.addr)
        old_lo = stmt.old_lo
        old_hi = stmt.old_hi

        self._expr(stmt.data_lo)
        if stmt.data_hi is not None:
            self._expr(stmt.data_hi)
        self._expr(stmt.expd_lo)
        if stmt.expd_hi is not None:
            self._expr(stmt.expd_hi)

        if isinstance(old_lo, ailment.Tmp):
            self.state.kill_and_add_definition(Tmp(old_lo.tmp_idx, old_lo.size), addr)
            self.tmps[old_lo.tmp_idx] = self._top(old_lo.size)

        if isinstance(old_hi, ailment.Tmp):
            self.state.kill_and_add_definition(Tmp(old_hi.tmp_idx, old_hi.size), addr)
            self.tmps[old_hi.tmp_idx] = self._top(old_hi.size)

    def _handle_stmt_Store(self, stmt: ailment.Stmt.Store) -> None:
        data = self._expr(stmt.data)
        addr = self._expr(stmt.addr)
        size: int = stmt.size
        if stmt.guard is not None:
            self._expr(stmt.guard)

        memory_location = None
        if self.state.is_stack_address(addr):
            stack_offset = self.state.get_stack_offset(addr)
            if stack_offset is not None:
                memory_location = MemoryLocation(SpOffset(self.arch.bits, stack_offset), size, endness=stmt.endness)
        elif addr.concrete:
            memory_location = MemoryLocation(addr.concrete_value, size, endness=stmt.endness)

        if memory_location is not None:
            self.state.kill_and_add_definition(memory_location, data, endness=stmt.endness)

    def _handle_stmt_Jump(self, stmt):
        _ = self._expr(stmt.target)

    def _handle_stmt_ConditionalJump(self, stmt):
        _ = self._expr(stmt.condition)  # pylint:disable=unused-variable
        if stmt.true_target is not None:
            _ = self._expr(stmt.true_target)  # pylint:disable=unused-variable
        if stmt.false_target is not None:
            _ = self._expr(stmt.false_target)  # pylint:disable=unused-variable

        ip = Register(cast(RegisterOffset, self.arch.ip_offset), self.arch.bytes)
        self.state.kill_definitions(ip)

    def _handle_stmt_SideEffectStatement(self, stmt: ailment.Stmt.SideEffectStatement):
        data = self._handle_Call_base(stmt.expr, is_expr=False)
        src = data.ret_values
        if src is None:
            return

        dst = stmt.ret_expr
        if isinstance(dst, ailment.Tmp):
            _, defs = self.state.kill_and_add_definition(Tmp(dst.tmp_idx, dst.size), src, uses=data.ret_values_deps)
            self.tmps[dst.tmp_idx] = src

        elif isinstance(dst, ailment.Register):
            full_reg_offset, full_reg_size = self.arch.registers[
                self.arch.register_names[RegisterOffset(dst.reg_offset)]
            ]
            if dst.size != full_reg_size:
                # we need to extend the value to overwrite the entire register
                high_bytes = max(0, dst.reg_offset - full_reg_offset)
                pieces = [claripy.BVV(0, high_bytes * 8), src] if high_bytes else [src]
                low_bytes = full_reg_size - high_bytes - len(src) // 8
                if low_bytes > 0:
                    pieces.append(claripy.BVV(0, low_bytes * 8))
                src = claripy.Concat(*pieces)
            reg = Register(full_reg_offset, full_reg_size)
            _, defs = self.state.kill_and_add_definition(reg, src, uses=data.ret_values_deps)
        else:
            defs = set()

        if self.state.analysis:
            self.state.analysis.function_calls[data.callsite_codeloc].ret_defns.update(defs)

    def _handle_Call_base(self, call: ailment.Expr.Call, is_expr: bool = False) -> FunctionCallData:
        if isinstance(call.target, ailment.Expr.Expression):
            target = self._expr(call.target)  # pylint:disable=unused-variable
            func_name = None
        elif isinstance(call.target, str):
            func_name = call.target
            target = None
        else:
            target = call.target
            func_name = None

        ip = Register(cast(RegisterOffset, self.arch.ip_offset), self.arch.bytes)
        self.state.kill_definitions(ip)

        statement = self.block.statements[self.stmt_idx]
        caller_will_handle_single_ret = True
        ret_expr = getattr(call, "ret_expr", None)
        if hasattr(statement, "dst") and statement.dst != ret_expr:
            caller_will_handle_single_ret = False

        data = FunctionCallData(
            self.state.codeloc,
            self._function_handler.make_function_codeloc(
                target, self.state.codeloc, self.state.analysis.model.func_addr
            ),
            target,
            cc=self._variable_map.calling_convention(call) if self._variable_map is not None else None,
            prototype=self._variable_map.prototype(call) if self._variable_map is not None else None,
            name=func_name,
            args_values=[self._expr(arg) for arg in call.args] if call.args is not None else None,
            redefine_locals=call.args is None and not is_expr,
            caller_will_handle_single_ret=caller_will_handle_single_ret,
            ret_atoms=(
                {Atom.from_ail_expr(ret_expr, self.arch)}  # TODO: Support stack atoms in the future
                if isinstance(ret_expr, ailment.Expr.Register)
                else None
            ),
        )

        self._function_handler.handle_function(self.state, data)

        if hasattr(call, "arg_defs"):
            for arg_def in call.arg_defs:
                arg_def: Definition
                if arg_def in self.state.all_definitions:
                    self.state.kill_definitions(arg_def.atom)

        # kill all cc_ops
        if "cc_op" in self.arch.registers:

            def killreg(name: str):
                offset, size = self.arch.registers[name]
                self.state.kill_definitions(Register(offset, size))

            killreg("cc_op")
            killreg("cc_dep1")
            killreg("cc_dep2")
            killreg("cc_ndep")

        return data

    def _handle_stmt_Return(self, stmt: ailment.Stmt.Return):  # pylint:disable=unused-argument
        cc = None
        prototype = None
        if self.state.analysis.subject.type == SubjectType.Function:
            cc = self.state.analysis.subject.content.calling_convention
            prototype = self.state.analysis.subject.content.get_prototype(getattr(self.state.analysis, "flavor", None))

        if cc is None:
            # fall back to the default calling convention
            cc_cls = default_cc_for_project(self.project, default=None)
            if cc_cls is None:
                l.warning("Unknown default calling convention for architecture %s.", self.project.arch.name)
                cc = None
            else:
                cc = cc_cls(self.project.arch)

        if self._use_callee_saved_regs_at_return and cc is not None:
            # handle callee-saved registers: add uses for these registers so that the restoration statements are not
            # considered dead assignments.
            for reg in self.arch.register_list:
                if (
                    reg.general_purpose
                    and reg.name not in cc.CALLER_SAVED_REGS
                    and reg.name not in cc.ARG_REGS
                    and reg.vex_offset
                    not in {
                        self.arch.sp_offset,
                        self.arch.bp_offset,
                        self.arch.ip_offset,
                    }
                    and (isinstance(cc.RETURN_VAL, SimRegArg) and reg.name != cc.RETURN_VAL.reg_name)
                ):
                    self.state.add_register_use(reg.vex_offset, reg.size)

        if stmt.ret_exprs:
            # Handle return expressions
            for ret_expr in stmt.ret_exprs:
                self._expr(ret_expr)
            return

        # No return expressions are available.
        # consume registers that are potentially useful

        # return value
        if (
            cc is not None
            and prototype is not None
            and prototype.returnty is not None
            and not isinstance(prototype.returnty, SimTypeBottom)
        ):
            ret_val = cc.return_val(prototype.returnty)
            if isinstance(ret_val, SimRegArg):
                if ret_val.clear_entire_reg:
                    offset, size = cc.arch.registers[ret_val.reg_name]
                else:
                    offset = cc.arch.registers[ret_val.reg_name][0] + ret_val.reg_offset
                    size = ret_val.size
                self.state.add_register_use(offset, size)
            else:
                l.error("Cannot handle CC with non-register return value location")

        # base pointer
        # TODO: Check if the stack base pointer is used as a stack base pointer in this function or not
        self.state.add_register_use(self.project.arch.bp_offset, self.project.arch.bytes)
        # We don't add sp since stack pointers are supposed to be get rid of in AIL. this is definitely a hack though
        # self.state.add_use(Register(self.project.arch.sp_offset, self.project.arch.bits // 8))

    def _handle_stmt_DirtyStatement(self, stmt: ailment.Stmt.DirtyStatement):
        self._expr(stmt.dirty)

    #
    # AIL expression handlers
    #

    def _handle_expr_String(self, expr):
        return self._top(expr.bits)

    def _handle_expr_Struct(self, expr):
        return self._top(expr.bits)

    def _handle_expr_Array(self, expr):
        return self._top(expr.bits)

    def _handle_expr_Let(self, expr):
        return self._top(expr.bits)

    def _handle_expr_FunctionLikeMacro(self, expr):
        return self._top(expr.bits)

    def _handle_expr_Tmp(self, expr) -> claripy.ast.BV:
        self.state.add_tmp_use(expr.tmp_idx)

        try:
            return self.tmps[expr.tmp_idx]
        except KeyError:
            return self._top(expr.bits)

    def _handle_expr_Call(self, expr) -> claripy.ast.BV:
        data = self._handle_Call_base(expr, is_expr=True)
        result = data.ret_values

        if result is None:
            return self._top(expr.bits)

        # truncate result if needed
        if len(result) > expr.bits:
            result = claripy.Extract(expr.bits - 1, 0, result)

        if data.ret_values_deps is not None:
            for dep in data.ret_values_deps:
                result = self.state.annotate_with_def(result, dep)
        return result

    def _handle_expr_Register(self, expr) -> claripy.ast.BV:
        self.state: ReachingDefinitionsState

        reg_offset = expr.reg_offset
        size = expr.size
        # bits = size * 8

        # Special handling for SP and BP
        if self._stack_pointer_tracker is not None:
            if reg_offset == self.arch.sp_offset:
                sb_offset = self._stack_pointer_tracker.offset_before(self.ins_addr, self.arch.sp_offset)
                if sb_offset is not None:
                    return self.state._initial_stack_pointer() + sb_offset
            elif reg_offset == self.arch.bp_offset and not self.bp_as_gpr:
                sb_offset = self._stack_pointer_tracker.offset_before(self.ins_addr, self.arch.bp_offset)
                if sb_offset is not None:
                    return self.state._initial_stack_pointer() + sb_offset

        reg_atom = Register(RegisterOffset(reg_offset), size)

        # first check if it is ever defined
        try:
            value: claripy.ast.BV = self.state.registers.load(reg_offset, size=size)
        except SimMemoryMissingError as ex:
            # the full value does not exist, but we handle partial existence, too
            missing_defs = None
            if ex.missing_size != size:
                existing_values = []
                i = 0
                while i < size:
                    try:
                        value: claripy.ast.BV = self.state.registers.load(reg_offset + i, size=1)
                    except SimMemoryMissingError as ex_:
                        i += ex_.missing_size
                        continue
                    i += 1
                    existing_values.append(value)
                # extract existing definitions
                for existing_value in existing_values:
                    if missing_defs is None:
                        missing_defs = self.state.extract_defs(existing_value)
                    else:
                        missing_defs = chain(missing_defs, self.state.extract_defs(existing_value))

            if missing_defs is not None:
                self.state.add_register_use_by_defs(missing_defs, expr=expr)

            top = self.state.top(size * self.state.arch.byte_width)
            # annotate it
            extloc = self._external_codeloc()
            top = self.state.annotate_with_def(top, Definition(reg_atom, extloc))
            value = top
            # write it back
            self.state.kill_and_add_definition(reg_atom, value, override_codeloc=extloc)

        self.state.add_register_use_by_defs(self.state.extract_defs(value), expr=expr)

        return value

    def _handle_expr_Load(self, expr) -> claripy.ast.BV:
        addrs = self._expr(expr.addr)

        size = expr.size
        bits = expr.bits
        if expr.guard is not None:
            assert expr.alt is not None
            self._expr(expr.guard)
            self._expr(expr.alt)

        # load from every address
        if (addrs_v := mv_eval(addrs)) is None:
            top = self.state.top(bits)
            # annotate it
            extloc = self._external_codeloc()
            dummy_atom = MemoryLocation(0, size, endness=expr.endness)
            def_ = Definition(dummy_atom, extloc)
            top = self.state.annotate_with_def(top, def_)
            # add use
            self.state.add_memory_use_by_def(def_, expr=expr)
            return top

        result: claripy.ast.BV | None = None
        for addr in addrs_v:
            if not isinstance(addr, claripy.ast.Base):
                continue
            if addr.concrete:
                # a concrete address
                concrete_addr: int = addr.concrete_value
                try:
                    vs: claripy.ast.BV = self.state.memory.load(concrete_addr, size=size, endness=expr.endness)
                    defs = set(LiveDefinitions.extract_defs(vs))
                except SimMemoryMissingError:
                    continue

                self.state.add_memory_use_by_defs(defs, expr=expr)
                result = claripy.union(result, vs) if result is not None else vs
            elif self.state.is_stack_address(addr):
                stack_offset = self.state.get_stack_offset(addr)
                if stack_offset is not None:
                    stack_addr = self.state.live_definitions.stack_offset_to_stack_addr(stack_offset)
                    try:
                        vs: claripy.ast.BV = self.state.stack.load(stack_addr, size=size, endness=expr.endness)
                        defs = set(LiveDefinitions.extract_defs(vs))
                    except SimMemoryMissingError:
                        continue

                    # XXX should be add_stack_use_by_defs?
                    self.state.add_memory_use_by_defs(defs, expr=expr)
                    result = claripy.union(result, vs) if result is not None else vs
            else:
                # XXX does ail not support heap tracking?
                l.debug("Memory address %r undefined or unsupported at pc %#x.", addr, self.ins_addr)

        if result is None:
            top = self.state.top(bits)
            # TODO: Annotate top with a definition
            result = top

        return result

    def _handle_expr_Convert(self, expr) -> claripy.ast.BV:
        to_conv: claripy.ast.BV = self._expr(expr.operand)
        bits = expr.to_bits
        size = bits // self.arch.byte_width

        # Reject inconsistent analysis values before performing Claripy slicing or extension.
        if (
            (values := mv_eval(to_conv)) is None
            or expr.from_type != ailment.Expr.Convert.TYPE_INT
            or expr.to_type != ailment.Expr.Convert.TYPE_INT
            or any(len(value) != expr.from_bits for value in values)
        ):
            top = self.state.top(expr.to_bits)
            # annotate it
            dummy_atom = MemoryLocation(0, size, endness=self.arch.memory_endness)
            def_ = Definition(dummy_atom, self._external_codeloc())
            top = self.state.annotate_with_def(top, def_)
            # add use
            self.state.add_memory_use_by_def(def_, expr=expr)
            return top

        converted = set()
        for v in values:
            if expr.to_bits < expr.from_bits:
                conv = v[expr.to_bits - 1 : 0]
            elif expr.to_bits > expr.from_bits:
                conv = claripy.ZeroExt(expr.to_bits - expr.from_bits, v)
            else:
                conv = v
            converted.add(conv)

        return claripy.union(*converted)

    def _handle_expr_Reinterpret(self, expr) -> claripy.ast.BV:
        _: claripy.ast.BV = self._expr(expr.operand)
        bits = expr.to_bits

        # we currently do not support floating-point operations. therefore, we return TOP directly
        return self.state.top(bits)

    def _handle_unop_Default(self, expr):
        return self._top(expr.bits)

    def _handle_unop_Abs(self, expr):
        self._expr(expr.operand)
        return self._top(expr.bits)

    _handle_unop_Reference = _handle_unop_Default
    _handle_unop_Ctz = _handle_unop_Default
    _handle_unop_Dereference = _handle_unop_Default
    _handle_unop_GetMSBs = _handle_unop_Default
    _handle_unop_unpack = _handle_unop_Default
    _handle_unop_Sqrt = _handle_unop_Default
    _handle_unop_RSqrtEst = _handle_unop_Default

    def _handle_expr_ITE(self, expr) -> claripy.ast.BV:
        _: claripy.ast.BV = self._expr(expr.cond)
        iftrue: claripy.ast.BV = self._expr(expr.iftrue)
        _: claripy.ast.BV = self._expr(expr.iffalse)
        return self.state.top(len(iftrue))

    def _handle_expr_Extract(self, expr: ailment.expression.Extract) -> claripy.ast.BV:
        base = self._expr(expr.base)
        offset = self._expr(expr.offset)
        if offset.symbolic:
            return self._top(expr.bits)
        conc_offset = offset.concrete_value

        # offsets count bytes from the most significant end; a slice running past the end is cut short
        hi = len(base) - conc_offset * 8 - 1
        if hi < 0:
            return self._top(expr.bits)
        lo = max(0, len(base) - (conc_offset + expr.offset.size) * 8)
        return claripy.Extract(hi, lo, base)

    def _handle_expr_Insert(self, expr: ailment.expression.Insert):
        base = self._expr(expr.base)
        offset = self._expr(expr.offset)
        value = self._expr(expr.value)

        if offset.symbolic:
            return self._top(expr.bits)
        conc_offset = offset.concrete_value

        # offsets count bytes from the most significant end
        prefix_bits = conc_offset * 8
        if prefix_bits > len(base):
            return self._top(expr.bits)
        suffix_bits = len(base) - (conc_offset + expr.offset.size) * 8
        result = value
        if prefix_bits:
            result = claripy.Extract(len(base) - 1, len(base) - prefix_bits, base).concat(result)
        if suffix_bits > 0:
            result = result.concat(claripy.Extract(suffix_bits - 1, 0, base))
        return result

    def _handle_unop_Not(self, expr) -> claripy.ast.BV:
        operand = self._expr(expr.operand)
        bits = expr.bits

        if operand.concrete:
            return ~operand
        return self.state.top(bits)

    def _handle_unop_Neg(self, expr) -> claripy.ast.BV:
        operand: claripy.ast.BV = self._expr(expr.operand)
        bits = expr.bits
        if expr.floating_point:
            return self._fp_op(bits, operator.neg, operand)

        if operand.concrete:
            return -operand
        return self.state.top(bits)

    def _handle_unop_BitwiseNeg(self, expr) -> claripy.ast.BV:
        operand = self._expr(expr.operand)
        bits = expr.bits

        if operand.concrete:
            return ~operand
        return self.state.top(bits)

    def _handle_binop_Add(self, expr) -> claripy.ast.BV:
        expr0, expr1 = self._expr(expr.operands[0]), self._expr(expr.operands[1])
        bits = expr.bits
        if expr.floating_point:
            return self._fp_op(bits, operator.add, expr0, expr1)
        # constants and stack addresses, plus constants
        if set(expr0.variables) <= {"stack_base"} and not expr1.variables:
            return self.state.bounded(expr0 + expr1, expr0, expr1)
        return self.state.top(bits)

    def _handle_binop_Sub(self, expr) -> claripy.ast.BV:
        expr0, expr1 = self._expr(expr.operands[0]), self._expr(expr.operands[1])
        bits = expr.bits
        if expr.floating_point:
            return self._fp_op(bits, operator.sub, expr0, expr1)
        # constants and stack addresses, plus constants
        if set(expr0.variables) <= {"stack_base"} and not expr1.variables:
            return self.state.bounded(expr0 - expr1, expr0, expr1)
        return self.state.top(bits)

    def _handle_binop_Default(self, expr) -> claripy.ast.BV:
        arg0, arg1 = expr.operands

        self._expr(arg0)
        self._expr(arg1)
        bits = expr.bits

        return self.state.top(bits)

    _handle_binop_AddV = _handle_binop_Add
    _handle_binop_Div = _handle_binop_Default
    _handle_binop_MulV = _handle_binop_Default
    _handle_binop_MulHiV = _handle_binop_Default
    _handle_binop_Mod = _handle_binop_Default
    _handle_binop_AddF = _handle_binop_Default
    _handle_binop_DivF = _handle_binop_Default
    _handle_binop_DivV = _handle_binop_Default
    _handle_binop_MulF = _handle_binop_Default
    _handle_binop_SubF = _handle_binop_Default
    _handle_binop_SubV = _handle_binop_Default
    _handle_binop_InterleaveLOV = _handle_binop_Default
    _handle_binop_InterleaveHIV = _handle_binop_Default
    _handle_binop_CasCmpEQ = _handle_binop_Default
    _handle_binop_CasCmpNE = _handle_binop_Default
    _handle_binop_SarNV = _handle_binop_Default
    _handle_binop_ShrNV = _handle_binop_Default
    _handle_binop_ShlNV = _handle_binop_Default
    _handle_binop_CmpEQV = _handle_binop_Default
    _handle_binop_CmpNEV = _handle_binop_Default
    _handle_binop_CmpGEV = _handle_binop_Default
    _handle_binop_CmpGTV = _handle_binop_Default
    _handle_binop_CmpLEV = _handle_binop_Default
    _handle_binop_CmpLTV = _handle_binop_Default
    _handle_binop_MinV = _handle_binop_Default
    _handle_binop_MaxV = _handle_binop_Default
    _handle_binop_HAddV = _handle_binop_Default
    _handle_binop_QAddV = _handle_binop_Default
    _handle_binop_QSubV = _handle_binop_Default
    _handle_binop_QNarrowBinV = _handle_binop_Default
    _handle_binop_PermV = _handle_binop_Default
    _handle_binop_Set = _handle_binop_Default

    def _handle_binop_Mul(self, expr):
        expr0 = self._expr(expr.operands[0])
        expr1 = self._expr(expr.operands[1])
        bits = expr.bits
        if expr.floating_point:
            return self._fp_op(bits, operator.mul, expr0, expr1)
        if not expr0.variables and not expr1.variables:
            return self.state.bounded(expr0 * expr1, expr0, expr1)
        return self.state.top(bits)

    def _handle_binop_Mull(self, expr):
        expr0 = self._expr(expr.operands[0])
        expr1 = self._expr(expr.operands[1])
        bits = expr.bits
        if not expr0.variables and not expr1.variables:
            xt = bits // 2
            if expr.signed:
                return self.state.bounded(expr0.sign_extend(xt) * expr1.sign_extend(xt), expr0, expr1)
            return self.state.bounded(expr0.zero_extend(xt) * expr1.zero_extend(xt), expr0, expr1)
        return self.state.top(bits)

    def _shift(self, expr, op: Callable[[claripy.ast.BV, claripy.ast.BV], claripy.ast.BV]) -> claripy.ast.BV:
        """
        Shift constants by constants; the amount is resized to the width of the shifted value.
        """
        expr0, expr1 = self._expr(expr.operands[0]), self._expr(expr.operands[1])
        amount = shift_amount(expr1, len(expr0))
        if expr0.variables or expr1.variables or amount is None:
            return self.state.top(expr.bits)
        return self.state.bounded(op(expr0, amount), expr0, expr1)

    def _handle_binop_Shr(self, expr) -> claripy.ast.BV:
        return self._shift(expr, claripy.LShR)

    def _handle_binop_Sar(self, expr) -> claripy.ast.BV:
        return self._shift(expr, operator.rshift)

    def _handle_binop_Shl(self, expr):
        return self._shift(expr, operator.lshift)

    _handle_binop_Rol = _handle_binop_Default
    _handle_binop_Ror = _handle_binop_Default

    def _handle_binop_And(self, expr):
        expr0 = self._expr(expr.operands[0])
        expr1 = self._expr(expr.operands[1])
        bits = expr.bits
        # special handling for stack alignment
        if self.state.is_stack_address(expr0):
            return expr0
        if not expr0.variables and not expr1.variables:
            return self.state.bounded(expr0 & expr1, expr0, expr1)
        return self.state.top(bits)

    def _handle_binop_Or(self, expr):
        expr0: claripy.ast.BV = self._expr(expr.operands[0])
        expr1: claripy.ast.BV = self._expr(expr.operands[1])
        bits = expr.bits
        if not expr0.variables and not expr1.variables:
            return self.state.bounded(expr0 | expr1, expr0, expr1)
        return self.state.top(bits)

    def _handle_binop_LogicalAnd(self, expr) -> claripy.ast.BV:
        expr0: claripy.ast.BV = self._expr(expr.operands[0])
        expr1: claripy.ast.BV = self._expr(expr.operands[1])

        # TODO: can maybe be smarter about this. if we can determine that expr0 is never falsey, we can just return it,
        # TODO: or if it's always falsey we can return expr1 (did I get this backwards?)
        return self.state.bounded(claripy.If(expr0 == 0, expr0, expr1), expr0, expr1)

    def _handle_binop_LogicalOr(self, expr) -> claripy.ast.BV:
        expr0: claripy.ast.BV = self._expr(expr.operands[0])
        expr1: claripy.ast.BV = self._expr(expr.operands[1])
        return self.state.bounded(claripy.If(expr0 != 0, expr0, expr1), expr0, expr1)

    def _handle_binop_LogicalXor(self, expr) -> claripy.ast.BV:
        expr0: claripy.ast.BV = self._expr(expr.operands[0])
        expr1: claripy.ast.BV = self._expr(expr.operands[1])
        return self.state.bounded(claripy.If(expr0 != 0, expr1, expr0), expr0, expr1)

    def _handle_binop_Xor(self, expr):
        expr0: claripy.ast.BV = self._expr(expr.operands[0])
        expr1: claripy.ast.BV = self._expr(expr.operands[1])
        bits = expr.bits
        if not expr0.variables and not expr1.variables:
            return self.state.bounded(expr0 ^ expr1, expr0, expr1)
        return self.state.top(bits)

    def _handle_binop_Carry(self, expr) -> claripy.ast.BV:
        _ = self._expr(expr.operands[0])
        _ = self._expr(expr.operands[1])
        bits = expr.bits
        return self.state.top(bits)

    def _handle_binop_SCarry(self, expr) -> claripy.ast.BV:
        _ = self._expr(expr.operands[0])
        _ = self._expr(expr.operands[1])
        bits = expr.bits
        return self.state.top(bits)

    def _handle_binop_SBorrow(self, expr) -> claripy.ast.BV:
        _ = self._expr(expr.operands[0])
        _ = self._expr(expr.operands[1])
        bits = expr.bits
        return self.state.top(bits)

    def _handle_binop_Concat(self, expr) -> claripy.ast.BV:
        expr0 = self._expr(expr.operands[0])
        expr1 = self._expr(expr.operands[1])
        if not expr0.variables and not expr1.variables:
            return claripy.Concat(expr0, expr1)
        return self.state.top(expr.bits)

    def _handle_binop_Cmp(self, expr) -> claripy.ast.BV:
        op0 = self._expr(expr.operands[0])
        op1 = self._expr(expr.operands[1])

        if op0 is None:
            _ = expr.operands[0]
        if op1 is None:
            _ = expr.operands[1]

        return self.state.top(expr.bits)

    _handle_binop_CmpF = _handle_binop_Cmp
    _handle_binop_CmpEQ = _handle_binop_Cmp
    _handle_binop_CmpNE = _handle_binop_Cmp
    _handle_binop_CmpLE = _handle_binop_Cmp
    _handle_binop_CmpLEs = _handle_binop_Cmp
    _handle_binop_CmpLT = _handle_binop_Cmp
    _handle_binop_CmpLTs = _handle_binop_Cmp
    _handle_binop_CmpGE = _handle_binop_Cmp
    _handle_binop_CmpGEs = _handle_binop_Cmp
    _handle_binop_CmpGT = _handle_binop_Cmp
    _handle_binop_CmpGTs = _handle_binop_Cmp
    _handle_binop_CmpORD = _handle_binop_Cmp

    def _handle_binop_ExpCmpNE(self, expr) -> claripy.ast.BV:
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])

        return self.state.top(expr.bits)

    def _handle_unop_Clz(self, expr) -> claripy.ast.BV:
        self._expr(expr.operand)
        return self.state.top(expr.bits)

    def _handle_expr_Const(self, expr) -> claripy.ast.BV:
        self.state.mark_const(expr.value, expr.size)
        if isinstance(expr.value, float):
            if expr.bits == 64:
                return claripy.BVV(struct.pack(">d", expr.value))
            if expr.bits == 32:
                return claripy.BVV(struct.pack(">f", expr.value))
            return self._top(expr.bits)
        return claripy.BVV(expr.value, expr.bits)

    def _handle_expr_StackBaseOffset(self, expr) -> claripy.ast.BV:
        return self.state.stack_address(expr.offset)

    def _ail_handle_VEXCCallExpression(self, expr: ailment.Expr.VEXCCallExpression) -> claripy.ast.BV:
        for operand in expr.operands:
            self._expr(operand)

        return self.state.top(expr.bits)

    def _handle_expr_Phi(self, expr) -> claripy.ast.BV:
        return self._top(expr.bits)  # TODO

    def _handle_expr_VEXCCallExpression(self, expr) -> claripy.ast.BV:
        return self._top(expr.bits)  # TODO

    def _handle_expr_VirtualVariable(self, expr) -> claripy.ast.BV:
        return self._top(expr.bits)  # TODO

    def _handle_expr_DirtyExpression(self, expr) -> claripy.ast.BV:
        for operand in expr.operands:
            self._expr(operand)
        if expr.guard is not None:
            self._expr(expr.guard)
        if expr.maddr is not None:
            self._expr(expr.maddr)

        return self.state.top(expr.bits)

    def _handle_expr_BasePointerOffset(self, expr):
        return self._top(expr.bits)

    def _handle_expr_MultiStatementExpression(self, expr):
        return self._top(expr.bits)
