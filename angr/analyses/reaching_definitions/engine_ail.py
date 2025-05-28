# pylint:disable=missing-class-docstring,too-many-boolean-expressions
from __future__ import annotations
from itertools import chain
from collections.abc import Iterable
import logging
from typing import cast

from archinfo.types import RegisterOffset
import claripy
import angr.ailment as ailment
from claripy import FSORT_DOUBLE, FSORT_FLOAT

from angr.engines.light import SpOffset
from angr.engines.light.engine import SimEngineNostmtAIL
from angr.errors import SimEngineError, SimMemoryMissingError
from angr.calling_conventions import default_cc, SimRegArg, SimTypeBottom
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues, mv_is_bv
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register, Tmp, MemoryLocation
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from angr.knowledge_plugins.key_definitions.live_definitions import Definition, LiveDefinitions
from angr.code_location import CodeLocation, ExternalCodeLocation
from .subject import SubjectType
from .rd_state import ReachingDefinitionsState
from .function_handler import FunctionHandler, FunctionCallData

l = logging.getLogger(name=__name__)


class SimEngineRDAIL(
    SimEngineNostmtAIL[
        ReachingDefinitionsState, MultiValues[claripy.ast.BV | claripy.ast.FP], None, ReachingDefinitionsState
    ]
):
    def __init__(
        self,
        project,
        function_handler: FunctionHandler,
        stack_pointer_tracker=None,
        use_callee_saved_regs_at_return=True,
        bp_as_gpr: bool = False,
    ):
        super().__init__(project)
        self._function_handler = function_handler
        self._visited_blocks = None
        self._dep_graph = None
        self._stack_pointer_tracker = stack_pointer_tracker
        self._use_callee_saved_regs_at_return = use_callee_saved_regs_at_return
        self.bp_as_gpr = bp_as_gpr

    def _is_top(self, expr):
        """
        MultiValues are not really "top" in the stricter sense. They are just a collection of values,
        some of which might be top
        """
        return False

    def _top(self, bits) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        return MultiValues(self.state.top(bits))

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

    def _expr_bv(self, expr: ailment.expression.Expression) -> MultiValues[claripy.ast.BV]:
        result = self._expr(expr)
        assert mv_is_bv(result)
        return result

    def _expr_pair(
        self, arg0: ailment.expression.Expression, arg1: ailment.expression.Expression
    ) -> (
        tuple[MultiValues[claripy.ast.BV], MultiValues[claripy.ast.BV]]
        | tuple[MultiValues[claripy.ast.FP], MultiValues[claripy.ast.FP]]
    ):
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)
        assert type(r0) is type(r1)
        return r0, r1  # type: ignore

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
        addr = self._expr_bv(stmt.addr)
        size: int = stmt.size
        if stmt.guard is not None:
            self._expr(stmt.guard)

        addr_v = addr.one_value()
        if addr_v is not None and not self.state.is_top(addr_v):
            if self.state.is_stack_address(addr_v):
                stack_offset = self.state.get_stack_offset(addr_v)
                if stack_offset is not None:
                    memory_location = MemoryLocation(SpOffset(self.arch.bits, stack_offset), size, endness=stmt.endness)
                else:
                    memory_location = None
            elif self.state.is_heap_address(addr_v):
                memory_location = None
            else:
                memory_location = MemoryLocation(addr_v.concrete_value, size, endness=stmt.endness)

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

    def _handle_stmt_Call(self, stmt: ailment.Stmt.Call):
        data = self._handle_Call_base(stmt, is_expr=False)
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
                otv = {}
                next_off = 0
                if full_reg_offset < dst.reg_offset:
                    otv[0] = {claripy.BVV(0, (dst.reg_offset - full_reg_offset) * 8)}
                    next_off = dst.reg_offset - full_reg_offset
                for off, items in src.items():
                    otv[next_off + off] = set(items)
                next_off += len(src) // 8
                if next_off < full_reg_size:
                    otv[next_off] = {claripy.BVV(0, (full_reg_size - next_off) * 8)}
                src = MultiValues(offset_to_values=otv)
            reg = Register(full_reg_offset, full_reg_size)
            _, defs = self.state.kill_and_add_definition(reg, src, uses=data.ret_values_deps)
        else:
            defs = set()

        if self.state.analysis:
            self.state.analysis.function_calls[data.callsite_codeloc].ret_defns.update(defs)

    def _handle_Call_base(self, stmt: ailment.Stmt.Call, is_expr: bool = False) -> FunctionCallData:
        if isinstance(stmt.target, ailment.Expr.Expression):
            target = self._expr(stmt.target)  # pylint:disable=unused-variable
            func_name = None
        elif isinstance(stmt.target, str):
            func_name = stmt.target
            target = None
        else:
            target = stmt.target
            func_name = None

        ip = Register(cast(RegisterOffset, self.arch.ip_offset), self.arch.bytes)
        self.state.kill_definitions(ip)

        statement = self.block.statements[self.stmt_idx]
        caller_will_handle_single_ret = True
        if hasattr(statement, "dst") and statement.dst != stmt.ret_expr:
            caller_will_handle_single_ret = False

        data = FunctionCallData(
            self.state.codeloc,
            self._function_handler.make_function_codeloc(
                target, self.state.codeloc, self.state.analysis.model.func_addr
            ),
            target,
            cc=stmt.calling_convention,
            prototype=stmt.prototype,
            name=func_name,
            args_values=[self._expr(arg) for arg in stmt.args] if stmt.args is not None else None,
            redefine_locals=stmt.args is None and not is_expr,
            caller_will_handle_single_ret=caller_will_handle_single_ret,
            ret_atoms={Atom.from_ail_expr(stmt.ret_expr, self.arch)} if stmt.ret_expr is not None else None,
        )

        self._function_handler.handle_function(self.state, data)

        if hasattr(stmt, "arg_defs"):
            for arg_def in stmt.arg_defs:
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
            prototype = self.state.analysis.subject.content.prototype
            # import ipdb; ipdb.set_trace()

        if cc is None:
            # fall back to the default calling convention
            cc_cls = default_cc(
                self.project.arch.name,
                platform=self.project.simos.name if self.project.simos is not None else None,
                default=None,
            )
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

    def _handle_expr_Tmp(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        self.state.add_tmp_use(expr.tmp_idx)

        try:
            return self.tmps[expr.tmp_idx]
        except KeyError:
            return self._top(expr.bits)

    def _handle_expr_Call(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        data = self._handle_Call_base(expr, is_expr=True)
        result = data.ret_values

        if result is None:
            return self._top(expr.bits)

        # truncate result if needed
        if len(result) > expr.bits:
            assert mv_is_bv(result)
            result = cast(
                MultiValues[claripy.ast.BV | claripy.ast.FP],
                result.extract((len(result) - expr.bits) // 8, expr.bits // 8, "Iend_BE"),
            )

        if data.ret_values_deps is not None:
            for dep in data.ret_values_deps:
                result = self.state.annotate_mv_with_def(result, dep)
        return result

    def _handle_expr_Register(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        self.state: ReachingDefinitionsState

        reg_offset = expr.reg_offset
        size = expr.size
        # bits = size * 8

        # Special handling for SP and BP
        if self._stack_pointer_tracker is not None:
            if reg_offset == self.arch.sp_offset:
                sb_offset = self._stack_pointer_tracker.offset_before(self.ins_addr, self.arch.sp_offset)
                if sb_offset is not None:
                    return MultiValues(v=self.state._initial_stack_pointer() + sb_offset)
            elif reg_offset == self.arch.bp_offset and not self.bp_as_gpr:
                sb_offset = self._stack_pointer_tracker.offset_before(self.ins_addr, self.arch.bp_offset)
                if sb_offset is not None:
                    return MultiValues(v=self.state._initial_stack_pointer() + sb_offset)

        reg_atom = Register(RegisterOffset(reg_offset), size)

        # first check if it is ever defined
        try:
            value: MultiValues = self.state.registers.load(reg_offset, size=size)
        except SimMemoryMissingError as ex:
            # the full value does not exist, but we handle partial existence, too
            missing_defs = None
            if ex.missing_size != size:
                existing_values = []
                i = 0
                while i < size:
                    try:
                        value: MultiValues = self.state.registers.load(reg_offset + i, size=1)
                    except SimMemoryMissingError as ex_:
                        i += ex_.missing_size
                        continue
                    i += 1
                    existing_values.append(value)
                # extract existing definitions
                for existing_value in existing_values:
                    for vs in existing_value.values():
                        for v in vs:
                            if missing_defs is None:
                                missing_defs = self.state.extract_defs(v)
                            else:
                                missing_defs = chain(missing_defs, self.state.extract_defs(v))

            if missing_defs is not None:
                self.state.add_register_use_by_defs(missing_defs, expr=expr)

            top = self.state.top(size * self.state.arch.byte_width)
            # annotate it
            extloc = self._external_codeloc()
            top = self.state.annotate_with_def(top, Definition(reg_atom, extloc))
            value = MultiValues(top)
            # write it back
            self.state.kill_and_add_definition(reg_atom, value, override_codeloc=extloc)

        # extract Definitions
        defs: Iterable[Definition] | None = None
        for vs in value.values():
            for v in vs:
                defs = self.state.extract_defs(v) if defs is None else chain(defs, self.state.extract_defs(v))

        if defs is None:
            # define it right away as an external dependency
            self.state.kill_and_add_definition(reg_atom, value, override_codeloc=self._external_codeloc())
        else:
            self.state.add_register_use_by_defs(defs, expr=expr)

        return value

    def _handle_expr_Load(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        addrs = self._expr_bv(expr.addr)

        size = expr.size
        bits = expr.bits
        if expr.guard is not None:
            assert expr.alt is not None
            self._expr(expr.guard)
            self._expr(expr.alt)

        # convert addrs from MultiValues to a list of valid addresses
        if addrs.count() == 1:
            addrs_v = next(iter(addrs.values()))
        else:
            top = self.state.top(bits)
            # annotate it
            extloc = self._external_codeloc()
            dummy_atom = MemoryLocation(0, size, endness=expr.endness)
            def_ = Definition(dummy_atom, extloc)
            top = self.state.annotate_with_def(top, def_)
            # add use
            self.state.add_memory_use_by_def(def_, expr=expr)
            return MultiValues(top)

        result: MultiValues | None = None
        for addr in addrs_v:
            if not isinstance(addr, claripy.ast.Base):
                continue
            if addr.concrete:
                # a concrete address
                concrete_addr: int = addr.concrete_value
                try:
                    vs: MultiValues = self.state.memory.load(concrete_addr, size=size, endness=expr.endness)
                    defs = set(LiveDefinitions.extract_defs_from_mv(vs))
                except SimMemoryMissingError:
                    continue

                self.state.add_memory_use_by_defs(defs, expr=expr)
                result = result.merge(vs) if result is not None else vs
            elif self.state.is_stack_address(addr):
                stack_offset = self.state.get_stack_offset(addr)
                if stack_offset is not None:
                    stack_addr = self.state.live_definitions.stack_offset_to_stack_addr(stack_offset)
                    try:
                        vs: MultiValues = self.state.stack.load(stack_addr, size=size, endness=expr.endness)
                        defs = set(LiveDefinitions.extract_defs_from_mv(vs))
                    except SimMemoryMissingError:
                        continue

                    # XXX should be add_stack_use_by_defs?
                    self.state.add_memory_use_by_defs(defs, expr=expr)
                    result = result.merge(vs) if result is not None else vs
            else:
                # XXX does ail not support heap tracking?
                l.debug("Memory address %r undefined or unsupported at pc %#x.", addr, self.ins_addr)

        if result is None:
            top = self.state.top(bits)
            # TODO: Annotate top with a definition
            result = MultiValues(top)

        return result

    def _handle_expr_Convert(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        to_conv: MultiValues = self._expr(expr.operand)
        bits = expr.to_bits
        size = bits // self.arch.byte_width

        if (
            to_conv.count() == 1
            and 0 in to_conv
            and expr.from_type == ailment.Expr.Convert.TYPE_INT
            and expr.to_type == ailment.Expr.Convert.TYPE_INT
        ):
            values = to_conv[0]
        else:
            top = self.state.top(expr.to_bits)
            # annotate it
            dummy_atom = MemoryLocation(0, size, endness=self.arch.memory_endness)
            def_ = Definition(dummy_atom, self._external_codeloc())
            top = self.state.annotate_with_def(top, def_)
            # add use
            self.state.add_memory_use_by_def(def_, expr=expr)
            return MultiValues(top)

        converted = set()
        for v in values:
            if expr.to_bits < expr.from_bits:
                conv = v[expr.to_bits - 1 : 0]
            elif expr.to_bits > expr.from_bits:
                conv = claripy.ZeroExt(expr.to_bits - expr.from_bits, v)
            else:
                conv = v
            converted.add(conv)

        return MultiValues(offset_to_values={0: converted})

    def _handle_expr_Reinterpret(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        _: MultiValues = self._expr(expr.operand)
        bits = expr.to_bits

        # we currently do not support floating-point operations. therefore, we return TOP directly
        reinterpreted = self.state.top(bits)

        return MultiValues(reinterpreted)

    def _handle_unop_Default(self, expr):
        return self._top(expr.bits)

    _handle_unop_Reference = _handle_unop_Default
    _handle_unop_Clz = _handle_unop_Default
    _handle_unop_Ctz = _handle_unop_Default
    _handle_unop_Dereference = _handle_unop_Default
    _handle_unop_GetMSBs = _handle_unop_Default
    _handle_unop_unpack = _handle_unop_Default
    _handle_unop_Sqrt = _handle_unop_Default
    _handle_unop_RSqrtEst = _handle_unop_Default

    def _handle_expr_ITE(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        _: MultiValues = self._expr(expr.cond)
        iftrue: MultiValues = self._expr(expr.iftrue)
        _: MultiValues = self._expr(expr.iffalse)
        top = self.state.top(len(iftrue))
        return MultiValues(top)

    def _handle_unop_Not(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        operand = self._expr_bv(expr.operand)
        bits = expr.bits

        operand_v = operand.one_value()

        if operand_v is not None and operand_v.concrete:
            return MultiValues(~operand_v)  # pylint:disable=invalid-unary-operand-type
        return MultiValues(self.state.top(bits))

    def _handle_unop_Neg(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        operand: MultiValues = self._expr(expr.operand)
        bits = expr.bits

        operand_v = operand.one_value()

        if operand_v is not None and operand_v.concrete:
            return MultiValues(-operand_v)  # pylint:disable=invalid-unary-operand-type
        return MultiValues(self.state.top(bits))

    def _handle_unop_BitwiseNeg(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        operand = self._expr_bv(expr.operand)
        bits = expr.bits

        operand_v = operand.one_value()

        if operand_v is not None and operand_v.concrete:
            return MultiValues(offset_to_values={0: {~operand_v}})
        return MultiValues(offset_to_values={0: {self.state.top(bits)}})

    def _handle_binop_Add(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        expr0, expr1 = self._expr_pair(expr.operands[0], expr.operands[1])
        bits = expr.bits

        r: MultiValues[claripy.ast.BV | claripy.ast.FP] | None = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            # adding two single values together
            if (expr0_v.concrete or self.state.is_stack_address(expr0_v)) and expr1_v.concrete:
                r = MultiValues(expr0_v + expr1_v)  # type: ignore
        elif expr0_v is None and expr1_v is not None:
            # adding a single value to a multivalue
            if (
                expr0.count() == 1
                and 0 in expr0
                and all(v.concrete or self.state.is_stack_address(v) for v in expr0[0])
            ):
                vs = {v + expr1_v for v in expr0[0]}  # type: ignore
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # adding a single value to a multivalue
            if expr1.count() == 1 and 0 in expr1 and all(v.concrete for v in expr1[0]):
                vs = {v + expr0_v for v in expr1[0]}  # type: ignore
                r = MultiValues(offset_to_values={0: vs})
        else:
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_binop_Sub(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        expr0, expr1 = self._expr_pair(expr.operands[0], expr.operands[1])
        bits = expr.bits

        r: MultiValues[claripy.ast.BV | claripy.ast.FP] | None = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            if (expr0_v.concrete or self.state.is_stack_address(expr0_v)) and expr1_v.concrete:
                r = MultiValues(expr0_v - expr1_v)  # type: ignore
        elif expr0_v is None and expr1_v is not None:
            # subtracting a single value from a multivalue
            if (
                expr0.count() == 1
                and 0 in expr0
                and all(v.concrete or self.state.is_stack_address(v) for v in expr0[0])
            ):
                vs = {v - expr1_v for v in expr0[0]}  # type: ignore
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # subtracting a single value from a multivalue
            if expr1.count() == 1 and 0 in expr1 and all(v.concrete for v in expr1[0]):
                vs = {expr0_v - v for v in expr1[0]}  # type: ignore
                r = MultiValues(offset_to_values={0: vs})
        else:
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_binop_Default(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        arg0, arg1 = expr.operands

        self._expr(arg0)
        self._expr(arg1)
        bits = expr.bits

        return MultiValues(self.state.top(bits))

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
    _handle_binop_ExpCmpNE = _handle_binop_Default
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
    _handle_binop_QAddV = _handle_binop_Default
    _handle_binop_QNarrowBinV = _handle_binop_Default
    _handle_binop_PermV = _handle_binop_Default
    _handle_binop_Set = _handle_binop_Default

    def _handle_binop_Mul(self, expr):
        expr0 = self._expr(expr.operands[0])
        expr1 = self._expr(expr.operands[1])
        bits = expr.bits

        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None and expr0_v.concrete and expr1_v.concrete:
            r = MultiValues(offset_to_values={0: {expr0_v * expr1_v}})  # type: ignore
        else:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _handle_binop_Mull(self, expr):
        expr0 = self._expr(expr.operands[0])
        expr1 = self._expr(expr.operands[1])
        bits = expr.bits

        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None and expr0_v.concrete and expr1_v.concrete:
            xt = expr.bits // 2
            if expr.signed:
                r = MultiValues(
                    offset_to_values={0: {expr0_v.sign_extend(xt) * expr1_v.sign_extend(xt)}}  # type: ignore
                )
            else:
                r = MultiValues(
                    offset_to_values={0: {expr0_v.zero_extend(xt) * expr1_v.zero_extend(xt)}}  # type: ignore
                )
        else:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _handle_binop_Shr(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        expr0 = self._expr_bv(expr.operands[0])
        expr1 = self._expr_bv(expr.operands[1])
        bits = expr.bits

        r: MultiValues[claripy.ast.BV | claripy.ast.FP] | None = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(claripy.LShR(expr0_v, expr1_v.concrete_value))
        elif expr0_v is None and expr1_v is not None:
            # each value in expr0 >> expr1_v
            if expr0.count() == 1 and 0 in expr0 and all(v.concrete for v in expr0[0]) and expr1_v.concrete:
                vs = {
                    (claripy.LShR(v, expr1_v.concrete_value) if v.concrete else self.state.top(bits)) for v in expr0[0]
                }
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v >> each value in expr1
            if expr1.count() == 1 and 0 in expr1 and all(v.concrete for v in expr1[0]):
                vs = {
                    (claripy.LShR(expr0_v, v.concrete_value) if v.concrete else self.state.top(bits)) for v in expr1[0]
                }
                r = MultiValues(offset_to_values={0: vs})
        else:
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_binop_Sar(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        expr0 = self._expr_bv(expr.operands[0])
        expr1 = self._expr_bv(expr.operands[1])
        bits = expr.bits

        r: MultiValues[claripy.ast.BV | claripy.ast.FP] | None = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(expr0_v >> expr1_v.concrete_value)
        elif expr0_v is None and expr1_v is not None:
            # each value in expr0 >> expr1_v
            if expr0.count() == 1 and 0 in expr0 and all(v.concrete for v in expr0[0]) and expr1_v.concrete:
                vs = {
                    (claripy.LShR(v, expr1_v.concrete_value) if v.concrete else self.state.top(bits)) for v in expr0[0]
                }
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v >> each value in expr1
            if expr1.count() == 1 and 0 in expr1 and all(v.concrete for v in expr1[0]):
                vs = {
                    (claripy.LShR(expr0_v, v.concrete_value) if v.concrete else self.state.top(bits)) for v in expr1[0]
                }
                r = MultiValues(offset_to_values={0: vs})
        else:
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_binop_Shl(self, expr):
        expr0 = self._expr_bv(expr.operands[0])
        expr1 = self._expr_bv(expr.operands[1])
        bits = expr.bits

        r: MultiValues[claripy.ast.BV | claripy.ast.FP] | None = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(expr0_v << expr1_v.concrete_value)
        elif expr0_v is None and expr1_v is not None:
            # each value in expr0 << expr1_v
            if expr0.count() == 1 and 0 in expr0 and all(v.concrete for v in expr0[0]) and expr1_v.concrete:
                vs = {((v << expr1_v.concrete_value) if v.concrete else self.state.top(bits)) for v in expr0[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v >> each value in expr1
            if expr1.count() == 1 and 0 in expr1 and all(v.concrete for v in expr1[0]):
                vs = {((expr0_v << v.concrete_value) if v.concrete else self.state.top(bits)) for v in expr1[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    _handle_binop_Rol = _handle_binop_Default
    _handle_binop_Ror = _handle_binop_Default

    def _handle_binop_And(self, expr):
        expr0 = self._expr_bv(expr.operands[0])
        expr1 = self._expr_bv(expr.operands[1])
        bits = expr.bits

        r: MultiValues[claripy.ast.BV | claripy.ast.FP] | None = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            # special handling for stack alignment
            if self.state.is_stack_address(expr0_v):
                r = MultiValues(expr0_v)
            else:
                if expr0_v.concrete and expr1_v.concrete:
                    r = MultiValues(expr0_v & expr1_v)
        elif expr0_v is None and expr1_v is not None:
            # expr1_v & each value in expr0
            if expr0.count() == 1 and 0 in expr0 and all(v.concrete for v in expr0[0]):
                r = MultiValues(offset_to_values={0: {v & expr1_v for v in expr0[0]}})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v & each value in expr1
            if expr1.count() == 1 and 0 in expr1 and all(v.concrete for v in expr1[0]):
                r = MultiValues(offset_to_values={0: {expr0_v & v for v in expr1[0]}})
        else:
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_binop_Or(self, expr):
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r: MultiValues[claripy.ast.BV | claripy.ast.FP] | None = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(expr0_v | expr1_v)
        elif expr0_v is None and expr1_v is not None:
            # expr1_v | each value in expr0
            if expr0.count() == 1 and 0 in expr0 and all(v.concrete for v in expr0[0]):
                vs = {v | expr1_v for v in expr0[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v | each value in expr1
            if expr1.count() == 1 and 0 in expr1 and all(v.concrete for v in expr1[0]):
                vs = {expr0_v | v for v in expr1[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_binop_LogicalAnd(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        # TODO: can maybe be smarter about this. if we can determine that expr0 is never falsey, we can just return it,
        # TODO: or if it's always falsey we can return expr1 (did I get this backwards?)
        if expr0_v is None or expr1_v is None:
            return MultiValues(self.state.top(bits))

        return MultiValues(claripy.If(expr0_v == 0, expr0_v, expr1_v))

    def _handle_binop_LogicalOr(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None or expr1_v is None:
            return MultiValues(self.state.top(bits))

        return MultiValues(claripy.If(expr0_v != 0, expr0_v, expr1_v))

    def _handle_binop_LogicalXor(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None or expr1_v is None:
            return MultiValues(self.state.top(bits))

        return MultiValues(claripy.If(expr0_v != 0, expr1_v, expr0_v))

    def _handle_binop_Xor(self, expr):
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r: MultiValues[claripy.ast.BV | claripy.ast.FP] | None = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(expr0_v ^ expr1_v)
        elif expr0_v is None and expr1_v is not None:
            # expr1_v ^ each value in expr0
            if expr0.count() == 1 and 0 in expr0 and all(v.concrete for v in expr0[0]):
                vs = {v ^ expr1_v for v in expr0[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v ^ each value in expr1
            if expr1.count() == 1 and 0 in expr1 and all(v.concrete for v in expr1[0]):
                vs = {expr0_v ^ v for v in expr1[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_binop_Carry(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        _ = self._expr(expr.operands[0])
        _ = self._expr(expr.operands[1])
        bits = expr.bits
        return MultiValues(self.state.top(bits))

    def _handle_binop_SCarry(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        _ = self._expr(expr.operands[0])
        _ = self._expr(expr.operands[1])
        bits = expr.bits
        return MultiValues(self.state.top(bits))

    def _handle_binop_SBorrow(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        _ = self._expr(expr.operands[0])
        _ = self._expr(expr.operands[1])
        bits = expr.bits
        return MultiValues(self.state.top(bits))

    def _handle_binop_Concat(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        expr0 = self._expr_bv(expr.operands[0])
        expr1 = self._expr_bv(expr.operands[1])
        bits = expr.bits

        r: MultiValues[claripy.ast.BV | claripy.ast.FP] | None = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(claripy.Concat(expr0_v, expr1_v))
        elif expr0_v is None and expr1_v is not None:
            # concatenate expr1_v with each value in expr0
            if expr0.count() == 1 and 0 in expr0 and all(v.concrete for v in expr0[0]):
                r = MultiValues(offset_to_values={0: {claripy.Concat(v, expr1_v) for v in expr0[0]}})
        elif expr0_v is not None and expr1_v is None:
            # concatenate expr0_v with each value in expr1
            if expr1.count() == 1 and 0 in expr1 and all(v.concrete for v in expr1[0]):
                r = MultiValues(offset_to_values={0: {claripy.Concat(expr0_v, v) for v in expr1[0]}})
        else:
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_binop_Cmp(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        op0 = self._expr(expr.operands[0])
        op1 = self._expr(expr.operands[1])

        if op0 is None:
            _ = expr.operands[0]
        if op1 is None:
            _ = expr.operands[1]

        top = self.state.top(expr.bits)
        return MultiValues(top)

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

    def _handle_binop_ExpCmpNE(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])

        return MultiValues(self.state.top(expr.bits))

    def _handle_unop_Clz(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        self._expr(expr.operand)
        return MultiValues(self.state.top(expr.bits))

    def _handle_expr_Const(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        self.state.mark_const(expr.value, expr.size)
        if isinstance(expr.value, float):
            sort = None
            if expr.bits == 64:
                sort = FSORT_DOUBLE
            elif expr.bits == 32:
                sort = FSORT_FLOAT
            return MultiValues(claripy.FPV(expr.value, sort))
        return MultiValues(claripy.BVV(expr.value, expr.bits))

    def _handle_expr_StackBaseOffset(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        stack_addr = self.state.stack_address(expr.offset)
        return MultiValues(stack_addr)

    def _ail_handle_VEXCCallExpression(self, expr: ailment.Expr.VEXCCallExpression) -> MultiValues:
        for operand in expr.operands:
            self._expr(operand)

        top = self.state.top(expr.bits)
        return MultiValues(top)

    def _handle_expr_Phi(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        return self._top(expr.bits)  # TODO

    def _handle_expr_VEXCCallExpression(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        return self._top(expr.bits)  # TODO

    def _handle_expr_VirtualVariable(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        return self._top(expr.bits)  # TODO

    def _handle_expr_DirtyExpression(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        if isinstance(expr.dirty_expr, ailment.expression.VEXCCallExpression):
            for operand in expr.dirty_expr.operands:
                self._expr(operand)

        return MultiValues(self.state.top(expr.bits))

    def _handle_expr_BasePointerOffset(self, expr):
        return self._top(expr.bits)

    def _handle_expr_MultiStatementExpression(self, expr):
        return self._top(expr.bits)
