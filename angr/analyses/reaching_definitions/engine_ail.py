# pylint:disable=missing-class-docstring,too-many-boolean-expressions
from itertools import chain
from collections.abc import Iterable
import logging

import archinfo
import claripy
import ailment
import pyvex
from claripy import FSORT_DOUBLE, FSORT_FLOAT

from ...engines.light import SimEngineLight, SimEngineLightAILMixin, SpOffset
from ...errors import SimEngineError, SimMemoryMissingError
from ...calling_conventions import default_cc, SimRegArg, SimTypeBottom
from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ...knowledge_plugins.key_definitions.atoms import Atom, Register, Tmp, MemoryLocation
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from ...knowledge_plugins.key_definitions.live_definitions import Definition, LiveDefinitions
from ...code_location import CodeLocation, ExternalCodeLocation
from .subject import SubjectType
from .rd_state import ReachingDefinitionsState
from .function_handler import FunctionHandler, FunctionCallData

l = logging.getLogger(name=__name__)


class SimEngineRDAIL(
    SimEngineLightAILMixin,
    SimEngineLight,
):  # pylint:disable=abstract-method
    arch: archinfo.Arch
    state: ReachingDefinitionsState

    def __init__(
        self,
        project,
        function_handler: FunctionHandler | None = None,
        stack_pointer_tracker=None,
        use_callee_saved_regs_at_return=True,
        bp_as_gpr: bool = False,
    ):
        super().__init__()
        self.project = project
        self._function_handler = function_handler
        self._visited_blocks = None
        self._dep_graph = None
        self._stack_pointer_tracker = stack_pointer_tracker
        self._use_callee_saved_regs_at_return = use_callee_saved_regs_at_return
        self.bp_as_gpr = bp_as_gpr

        self._stmt_handlers = {
            ailment.Stmt.Assignment: self._ail_handle_Assignment,
            ailment.Stmt.Store: self._ail_handle_Store,
            ailment.Stmt.Jump: self._ail_handle_Jump,
            ailment.Stmt.ConditionalJump: self._ail_handle_ConditionalJump,
            ailment.Stmt.Call: self._ail_handle_Call,
            ailment.Stmt.Return: self._ail_handle_Return,
            ailment.Stmt.DirtyStatement: self._ail_handle_DirtyStatement,
            ailment.Stmt.Label: ...,
        }

        self._expr_handlers = {
            claripy.ast.BV: self._ail_handle_BV,
            ailment.Expr.Tmp: self._ail_handle_Tmp,
            ailment.Stmt.Call: self._ail_handle_CallExpr,
            ailment.Expr.Register: self._ail_handle_Register,
            ailment.Expr.Load: self._ail_handle_Load,
            ailment.Expr.Convert: self._ail_handle_Convert,
            ailment.Expr.Reinterpret: self._ail_handle_Reinterpret,
            ailment.Expr.ITE: self._ail_handle_ITE,
            ailment.Expr.UnaryOp: self._ail_handle_UnaryOp,
            ailment.Expr.BinaryOp: self._ail_handle_BinaryOp,
            ailment.Expr.Const: self._ail_handle_Const,
            ailment.Expr.StackBaseOffset: self._ail_handle_StackBaseOffset,
            ailment.Expr.DirtyExpression: self._ail_handle_DirtyExpression,
        }

    def process(self, state, *args, dep_graph=None, visited_blocks=None, block=None, fail_fast=False, **kwargs):
        self._dep_graph = dep_graph
        self._visited_blocks = visited_blocks

        # we are using a completely different state. Therefore, we directly call our _process() method before
        # SimEngine becomes flexible enough.
        try:
            self._process(
                state,
                None,
                block=block,
            )
        except SimEngineError as e:
            if fail_fast is True:
                raise e
        return self.state

    #
    # Private methods
    #

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

    def _process_Stmt(self, whitelist=None):
        super()._process_Stmt(whitelist=whitelist)

    def _handle_Stmt(self, stmt):
        if self.state.analysis:
            self.state.analysis.stmt_observe(self.stmt_idx, stmt, self.block, self.state, OP_BEFORE)
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

        self._set_codeloc()
        handler = self._stmt_handlers.get(type(stmt), None)
        if handler is not None:
            if handler is not ...:
                handler(stmt)
        else:
            self.l.warning("Unsupported statement type %s.", type(stmt).__name__)

        if self.state.analysis:
            self.state.analysis.stmt_observe(self.stmt_idx, stmt, self.block, self.state, OP_AFTER)
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_AFTER)

    def _expr(self, expr):
        handler = self._expr_handlers.get(type(expr), None)
        if handler is not None:
            return handler(expr)
        else:
            self.l.warning("Unsupported expression type %s.", type(expr).__name__)
            return MultiValues(self.state.top(self.arch.bits))

    def _ail_handle_Assignment(self, stmt):
        """

        :param ailment.Assignment stmt:
        :return:
        """

        src = self._expr(stmt.src)
        dst = stmt.dst

        if src is None:
            src = MultiValues(self.state.top(dst.bits))

        if isinstance(dst, ailment.Tmp):
            self.state.kill_and_add_definition(Tmp(dst.tmp_idx, dst.size), src)
            self.tmps[dst.tmp_idx] = src

        elif isinstance(dst, ailment.Register):
            reg = Register(dst.reg_offset, dst.size)
            self.state.kill_and_add_definition(reg, src)

            if dst.reg_offset == self.arch.sp_offset:
                self.state._sp_adjusted = True
                # TODO: Special logic that frees all definitions above the current stack pointer
        else:
            l.warning("Unsupported type of Assignment dst %s.", type(dst).__name__)

    def _ail_handle_Store(self, stmt: ailment.Stmt.Store) -> None:
        data: MultiValues = self._expr(stmt.data)
        addr: MultiValues = self._expr(stmt.addr)
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

    def _ail_handle_Jump(self, stmt):
        _ = self._expr(stmt.target)

    def _ail_handle_ConditionalJump(self, stmt):
        _ = self._expr(stmt.condition)  # pylint:disable=unused-variable
        if stmt.true_target is not None:
            _ = self._expr(stmt.true_target)  # pylint:disable=unused-variable
        if stmt.false_target is not None:
            _ = self._expr(stmt.false_target)  # pylint:disable=unused-variable

        ip = Register(self.arch.ip_offset, self.arch.bytes)
        self.state.kill_definitions(ip)

    def _ail_handle_Call(self, stmt: ailment.Stmt.Call):
        data = self._handle_Call_base(stmt, is_expr=False)
        src = data.ret_values
        if src is None:
            return

        dst = stmt.ret_expr
        if isinstance(dst, ailment.Tmp):
            _, defs = self.state.kill_and_add_definition(Tmp(dst.tmp_idx, dst.size), src, uses=data.ret_values_deps)
            self.tmps[dst.tmp_idx] = src

        elif isinstance(dst, ailment.Register):
            full_reg_offset, full_reg_size = self.arch.registers[self.arch.register_names[dst.reg_offset]]
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

        ip = Register(self.arch.ip_offset, self.arch.bytes)
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
            self.state.kill_definitions(Register(*self.arch.registers["cc_op"]))
            self.state.kill_definitions(Register(*self.arch.registers["cc_dep1"]))
            self.state.kill_definitions(Register(*self.arch.registers["cc_dep2"]))
            self.state.kill_definitions(Register(*self.arch.registers["cc_ndep"]))

        return data

    def _ail_handle_Return(self, stmt: ailment.Stmt.Return):  # pylint:disable=unused-argument
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

    def _ail_handle_DirtyStatement(self, stmt: ailment.Stmt.DirtyStatement):
        # TODO: The logic below is subject to change when ailment.Stmt.DirtyStatement is changed

        if isinstance(stmt.dirty_stmt, pyvex.stmt.Dirty):
            # TODO: We need dirty helpers for a more complete understanding of clobbered registers
            tmp = stmt.dirty_stmt.tmp
            if tmp in (-1, 0xFFFFFFFF):
                return
            size = 32  # FIXME: We don't know the size.
            self.state.kill_and_add_definition(Tmp(tmp, size), MultiValues(self.state.top(size)))
        else:
            l.warning("Unexpected type of dirty statement %s.", type(stmt.dirty_stmt))

    #
    # AIL expression handlers
    #

    def _ail_handle_BV(self, expr: claripy.ast.Base) -> MultiValues:
        return MultiValues(expr)

    def _ail_handle_Tmp(self, expr: ailment.Expr.Tmp) -> MultiValues:
        self.state.add_tmp_use(expr.tmp_idx)

        tmp = super()._ail_handle_Tmp(expr)
        if tmp is None:
            return MultiValues(self.state.top(expr.bits))
        return tmp

    def _ail_handle_CallExpr(self, expr: ailment.Stmt.Call) -> MultiValues:
        data = self._handle_Call_base(expr, is_expr=True)
        result = data.ret_values

        # truncate result if needed
        if result is not None:
            if len(result) > expr.bits:
                result = result.extract((len(result) - expr.bits) // 8, expr.bits // 8, "Iend_BE")

            if data.ret_values_deps is not None:
                for dep in data.ret_values_deps:
                    result = self.state.annotate_mv_with_def(result, dep)
        return result

    def _ail_handle_Register(self, expr: ailment.Expr.Register) -> MultiValues:
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

        reg_atom = Register(reg_offset, size)

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
                if defs is None:
                    defs = self.state.extract_defs(v)
                else:
                    defs = chain(defs, self.state.extract_defs(v))

        if defs is None:
            # define it right away as an external dependency
            self.state.kill_and_add_definition(reg_atom, value, override_codeloc=self._external_codeloc())
        else:
            self.state.add_register_use_by_defs(defs, expr=expr)

        return value

    def _ail_handle_Load(self, expr: ailment.Expr.Load) -> MultiValues:
        addrs: MultiValues = self._expr(expr.addr)

        size = expr.size
        bits = expr.bits
        if expr.guard is not None:
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

    def _ail_handle_Convert(self, expr: ailment.Expr.Convert) -> MultiValues:
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

    def _ail_handle_Reinterpret(self, expr: ailment.Expr.Reinterpret) -> MultiValues:
        _: MultiValues = self._expr(expr.operand)
        bits = expr.to_bits

        # we currently do not support floating-point operations. therefore, we return TOP directly
        reinterpreted = self.state.top(bits)

        return MultiValues(reinterpreted)

    def _ail_handle_ITE(self, expr: ailment.Expr.ITE) -> MultiValues:
        _: MultiValues = self._expr(expr.cond)
        iftrue: MultiValues = self._expr(expr.iftrue)
        _: MultiValues = self._expr(expr.iffalse)
        top = self.state.top(len(iftrue))
        return MultiValues(top)

    def _ail_handle_Not(self, expr: ailment.Expr.UnaryOp) -> MultiValues:
        operand: MultiValues = self._expr(expr.operand)
        bits = expr.bits

        if operand is None:
            return MultiValues(self.state.top(bits))

        operand_v = operand.one_value()

        if operand_v is not None and operand_v.concrete:
            r = MultiValues(~operand_v)  # pylint:disable=invalid-unary-operand-type
        else:
            r = MultiValues(self.state.top(bits))

        return r

    def _ail_handle_Neg(self, expr: ailment.Expr.UnaryOp) -> MultiValues:
        operand: MultiValues = self._expr(expr.operand)
        bits = expr.bits

        if operand is None:
            return MultiValues(self.state.top(bits))

        operand_v = operand.one_value()

        if operand_v is not None and operand_v.concrete:
            r = MultiValues(-operand_v)  # pylint:disable=invalid-unary-operand-type
        else:
            r = MultiValues(self.state.top(bits))

        return r

    def _ail_handle_BitwiseNeg(self, expr: ailment.Expr.UnaryOp) -> MultiValues:
        operand: MultiValues = self._expr(expr.operand)
        bits = expr.bits

        r = None
        operand_v = operand.one_value()

        if operand_v is not None and operand_v.concrete:
            r = MultiValues(offset_to_values={0: {~operand_v}})  # pylint:disable=invalid-unary-operand-type
        else:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _ail_handle_BinaryOp(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        r = super()._ail_handle_BinaryOp(expr)
        if isinstance(r, ailment.Expr.BinaryOp):
            l.warning("Unimplemented operation %s.", expr.op)
            top = self.state.top(expr.bits)
            return MultiValues(top)
        return r

    def _ail_handle_Add(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # adding a single value to a multivalue
            if expr0.count() == 1 and 0 in expr0:
                if all(v.concrete or self.state.is_stack_address(v) for v in expr0[0]):
                    vs = {v + expr1_v for v in expr0[0]}
                    r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # adding a single value to a multivalue
            if expr1.count() == 1 and 0 in expr1:
                if all(v.concrete for v in expr1[0]):
                    vs = {v + expr0_v for v in expr1[0]}
                    r = MultiValues(offset_to_values={0: vs})
        else:
            # adding two single values together
            if (expr0_v.concrete or self.state.is_stack_address(expr0_v)) and expr1_v.concrete:
                r = MultiValues(expr0_v + expr1_v)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _ail_handle_Sub(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # subtracting a single value from a multivalue
            if expr0.count() == 1 and 0 in expr0:
                if all(v.concrete or self.state.is_stack_address(v) for v in expr0[0]):
                    vs = {v - expr1_v for v in expr0[0]}
                    r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # subtracting a single value from a multivalue
            if expr1.count() == 1 and 0 in expr1:
                if all(v.concrete for v in expr1[0]):
                    vs = {expr0_v - v for v in expr1[0]}
                    r = MultiValues(offset_to_values={0: vs})
        else:
            if (expr0_v.concrete or self.state.is_stack_address(expr0_v)) and expr1_v.concrete:
                r = MultiValues(expr0_v - expr1_v)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _ail_handle_Div(self, expr):
        arg0, arg1 = expr.operands

        self._expr(arg0)
        self._expr(arg1)
        bits = expr.bits

        r = MultiValues(self.state.top(bits))
        return r

    def _ail_handle_DivMod(self, expr):
        return self._ail_handle_Div(expr)

    def _ail_handle_Mul(self, expr):
        arg0, arg1 = expr.operands

        self._expr(arg0)
        self._expr(arg1)
        bits = expr.bits

        r = MultiValues(self.state.top(bits))
        return r

    _ail_handle_AddV = _ail_handle_Add
    _ail_handle_MulV = _ail_handle_Mul

    def _ail_handle_Mull(self, expr):
        arg0, arg1 = expr.operands

        self._expr(arg0)
        self._expr(arg1)
        bits = expr.bits

        r = MultiValues(self.state.top(bits))
        return r

    def _ail_handle_Mod(self, expr):
        arg0, arg1 = expr.operands

        self._expr(arg0)
        self._expr(arg1)
        bits = expr.bits

        r = MultiValues(self.state.top(bits))
        return r

    def _ail_handle_Mul(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None and expr0_v.concrete and expr1_v.concrete:
            r = MultiValues(offset_to_values={0: {expr0_v * expr1_v}})
        else:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _ail_handle_Shr(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # each value in expr0 >> expr1_v
            if expr0.count() == 1 and 0 in expr0:
                if all(v.concrete for v in expr0[0]) and expr1_v.concrete:
                    vs = {
                        (claripy.LShR(v, expr1_v.concrete_value) if v.concrete else self.state.top(bits))
                        for v in expr0[0]
                    }
                    r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v >> each value in expr1
            if expr1.count() == 1 and 0 in expr1:
                if all(v.concrete for v in expr1[0]):
                    vs = {
                        (claripy.LShR(expr0_v, v.concrete_value) if v.concrete else self.state.top(bits))
                        for v in expr1[0]
                    }
                    r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(claripy.LShR(expr0_v, expr1_v.concrete_value))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _ail_handle_Sar(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # each value in expr0 >> expr1_v
            if expr0.count() == 1 and 0 in expr0:
                if all(v.concrete for v in expr0[0]) and expr1_v.concrete:
                    vs = {
                        (claripy.LShR(v, expr1_v.concrete_value) if v.concrete else self.state.top(bits))
                        for v in expr0[0]
                    }
                    r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v >> each value in expr1
            if expr1.count() == 1 and 0 in expr1:
                if all(v.concrete for v in expr1[0]):
                    vs = {
                        (claripy.LShR(expr0_v, v.concrete_value) if v.concrete else self.state.top(bits))
                        for v in expr1[0]
                    }
                    r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(expr0_v >> expr1_v.concrete_value)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _ail_handle_Shl(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # each value in expr0 << expr1_v
            if expr0.count() == 1 and 0 in expr0:
                if all(v.concrete for v in expr0[0]) and expr1_v.concrete:
                    vs = {((v << expr1_v.concrete_value) if v.concrete else self.state.top(bits)) for v in expr0[0]}
                    r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v >> each value in expr1
            if expr1.count() == 1 and 0 in expr1:
                if all(v.concrete for v in expr1[0]):
                    vs = {((expr0_v << v.concrete_value) if v.concrete else self.state.top(bits)) for v in expr1[0]}
                    r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(expr0_v << expr1_v.concrete_value)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _ail_handle_Rol(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])
        bits = expr.bits

        return MultiValues(self.state.top(bits))

    def _ail_handle_Ror(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])
        bits = expr.bits

        return MultiValues(self.state.top(bits))

    def _ail_handle_And(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(self.state.top(bits))
            return r

        if expr0_v is None and expr1_v is not None:
            # expr1_v & each value in expr0
            if expr0.count() == 1 and 0 in expr0:
                if all(v.concrete for v in expr0[0]):
                    vs = {v & expr1_v for v in expr0[0]}
                    r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v & each value in expr1
            if expr1.count() == 1 and 0 in expr1:
                if all(v.concrete for v in expr1[0]):
                    vs = {expr0_v & v for v in expr1[0]}
                    r = MultiValues(offset_to_values={0: vs})
        else:
            # special handling for stack alignment
            if self.state.is_stack_address(expr0_v):
                r = MultiValues(expr0_v)
            else:
                if expr0_v.concrete and expr1_v.concrete:
                    r = MultiValues(expr0_v & expr1_v)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _ail_handle_Or(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # expr1_v | each value in expr0
            if expr0.count() == 1 and 0 in expr0:
                if all(v.concrete for v in expr0[0]):
                    vs = {v | expr1_v for v in expr0[0]}
                    r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v | each value in expr1
            if expr1.count() == 1 and 0 in expr1:
                if all(v.concrete for v in expr1[0]):
                    vs = {expr0_v | v for v in expr1[0]}
                    r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(expr0_v | expr1_v)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _ail_handle_LogicalAnd(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        # TODO: can maybe be smarter about this. if we can determine that expr0 is never falsey, we can just return it,
        # TODO: or if it's always falsey we can return expr1 (did I get this backwards?)
        if expr0_v is None or expr1_v is None:
            r = MultiValues(self.state.top(bits))
            return r

        r = MultiValues(claripy.If(expr0_v == 0, expr0_v, expr1_v))
        return r

    def _ail_handle_LogicalOr(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None or expr1_v is None:
            r = MultiValues(self.state.top(bits))
            return r

        r = MultiValues(claripy.If(expr0_v != 0, expr0_v, expr1_v))
        return r

    def _ail_handle_LogicalXor(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None or expr1_v is None:
            r = MultiValues(self.state.top(bits))
            return r

        r = MultiValues(claripy.If(expr0_v != 0, expr1_v, expr0_v))
        return r

    def _ail_handle_Xor(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # expr1_v ^ each value in expr0
            if expr0.count() == 1 and 0 in expr0:
                if all(v.concrete for v in expr0[0]):
                    vs = {v ^ expr1_v for v in expr0[0]}
                    r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v ^ each value in expr1
            if expr1.count() == 1 and 0 in expr1:
                if all(v.concrete for v in expr1[0]):
                    vs = {expr0_v ^ v for v in expr1[0]}
                    r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(expr0_v ^ expr1_v)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _ail_handle_Carry(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        _ = self._expr(expr.operands[0])
        _ = self._expr(expr.operands[1])
        bits = expr.bits
        r = MultiValues(self.state.top(bits))
        return r

    def _ail_handle_SCarry(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        _ = self._expr(expr.operands[0])
        _ = self._expr(expr.operands[1])
        bits = expr.bits
        r = MultiValues(self.state.top(bits))
        return r

    def _ail_handle_SBorrow(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        _ = self._expr(expr.operands[0])
        _ = self._expr(expr.operands[1])
        bits = expr.bits
        r = MultiValues(self.state.top(bits))
        return r

    def _ail_handle_Concat(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # concatenate expr1_v with each value in expr0
            if expr0.count() == 1 and 0 in expr0:
                if all(v.concrete for v in expr0[0]):
                    vs = {claripy.Concat(v, expr1_v) for v in expr0[0]}
                    r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # concatenate expr0_v with each value in expr1
            if expr1.count() == 1 and 0 in expr1:
                if all(v.concrete for v in expr1[0]):
                    vs = {claripy.Concat(expr0_v, v) for v in expr1[0]}
                    r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(claripy.Concat(expr0_v, expr1_v))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _ail_handle_Cmp(self, expr) -> MultiValues:
        op0 = self._expr(expr.operands[0])
        op1 = self._expr(expr.operands[1])

        if op0 is None:
            _ = expr.operands[0]
        if op1 is None:
            _ = expr.operands[1]

        top = self.state.top(expr.bits)
        return MultiValues(top)

    _ail_handle_CmpF = _ail_handle_Cmp
    _ail_handle_CmpEQ = _ail_handle_Cmp
    _ail_handle_CmpNE = _ail_handle_Cmp
    _ail_handle_CmpLE = _ail_handle_Cmp
    _ail_handle_CmpLEs = _ail_handle_Cmp
    _ail_handle_CmpLT = _ail_handle_Cmp
    _ail_handle_CmpLTs = _ail_handle_Cmp
    _ail_handle_CmpGE = _ail_handle_Cmp
    _ail_handle_CmpGEs = _ail_handle_Cmp
    _ail_handle_CmpGT = _ail_handle_Cmp
    _ail_handle_CmpGTs = _ail_handle_Cmp
    _ail_handle_CmpORD = _ail_handle_Cmp

    def _ail_handle_TernaryOp(self, expr) -> MultiValues:
        _ = self._expr(expr.operands[0])
        _ = self._expr(expr.operands[1])
        _ = self._expr(expr.operands[2])

        top = self.state.top(expr.bits)
        return MultiValues(offset_to_values={0: {top}})

    def _ail_handle_ExpCmpNE(self, expr) -> MultiValues:
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])

        top = self.state.top(expr.bits)
        return MultiValues(offset_to_values={0: {top}})

    def _ail_handle_Clz(self, expr) -> MultiValues:
        self._expr(expr.operand)

        top = self.state.top(expr.bits)
        return MultiValues(offset_to_values={0: {top}})

    def _ail_handle_Const(self, expr) -> MultiValues:
        self.state.mark_const(expr.value, expr.size)
        if isinstance(expr.value, float):
            sort = None
            if expr.bits == 64:
                sort = FSORT_DOUBLE
            elif expr.bits == 32:
                sort = FSORT_FLOAT
            return MultiValues(claripy.FPV(expr.value, sort))
        else:
            return MultiValues(claripy.BVV(expr.value, expr.bits))

    def _ail_handle_StackBaseOffset(self, expr: ailment.Expr.StackBaseOffset) -> MultiValues:
        stack_addr = self.state.stack_address(expr.offset)
        return MultiValues(stack_addr)

    def _ail_handle_DirtyExpression(
        self, expr: ailment.Expr.DirtyExpression
    ) -> MultiValues:  # pylint:disable=no-self-use
        if isinstance(expr.dirty_expr, ailment.Expr.VEXCCallExpression):
            for operand in expr.dirty_expr.operands:
                self._expr(operand)

        top = self.state.top(expr.bits)
        return MultiValues(top)

    #
    # User defined high-level statement handlers
    #
