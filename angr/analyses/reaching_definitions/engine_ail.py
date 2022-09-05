from itertools import chain
from typing import Iterable, Optional
import logging

import archinfo
import claripy
import ailment
import pyvex
from claripy import FSORT_DOUBLE, FSORT_FLOAT

from ...engines.light import SimEngineLight, SimEngineLightAILMixin, SpOffset
from ...errors import SimEngineError, SimMemoryMissingError
from ...calling_conventions import DEFAULT_CC, SimRegArg, SimStackArg
from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ...knowledge_plugins.key_definitions.atoms import Register, Tmp, MemoryLocation
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from ...knowledge_plugins.key_definitions.live_definitions import Definition, LiveDefinitions
from .subject import SubjectType
from .external_codeloc import ExternalCodeLocation
from .rd_state import ReachingDefinitionsState
from .function_handler import FunctionHandler

l = logging.getLogger(name=__name__)


class SimEngineRDAIL(
    SimEngineLightAILMixin,
    SimEngineLight,
):  # pylint:disable=abstract-method

    arch: archinfo.Arch
    state: ReachingDefinitionsState

    def __init__(self, project, call_stack, maximum_local_call_depth,
                 function_handler: Optional[FunctionHandler] = None):
        super().__init__()
        self.project = project
        self._call_stack = call_stack
        self._maximum_local_call_depth = maximum_local_call_depth
        self._function_handler = function_handler
        self._visited_blocks = None
        self._dep_graph = None

        self._stmt_handlers = {
            ailment.Stmt.Assignment: self._ail_handle_Assignment,
            ailment.Stmt.Store: self._ail_handle_Store,
            ailment.Stmt.Jump: self._ail_handle_Jump,
            ailment.Stmt.ConditionalJump: self._ail_handle_ConditionalJump,
            ailment.Stmt.Call: self._ail_handle_Call,
            ailment.Stmt.Return: self._ail_handle_Return,
            ailment.Stmt.DirtyStatement: self._ail_handle_DirtyStatement,
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

    def process(self, state, *args, **kwargs):
        self._dep_graph = kwargs.pop('dep_graph', None)
        self._visited_blocks = kwargs.pop('visited_blocks', None)

        # we are using a completely different state. Therefore, we directly call our _process() method before
        # SimEngine becomes flexible enough.
        try:
            self._process(
                state,
                None,
                block=kwargs.pop('block', None),
            )
        except SimEngineError as e:
            if kwargs.pop('fail_fast', False) is True:
                raise e
        return self.state, self._visited_blocks, self._dep_graph

    def sp_offset(self, offset: int):
        return self.state.stack_address(offset)

    #
    # Private methods
    #

    @staticmethod
    def _external_codeloc():
        return ExternalCodeLocation()

    #
    # AIL statement handlers
    #

    def _handle_Stmt(self, stmt):

        if self.state.analysis:
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

        handler = self._stmt_handlers.get(type(stmt), None)
        if handler is not None:
            handler(stmt)
        else:
            self.l.warning('Unsupported statement type %s.', type(stmt).__name__)

        if self.state.analysis:
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_AFTER)

    def _expr(self, expr):
        handler = self._expr_handlers.get(type(expr), None)
        if handler is not None:
            return handler(expr)
        else:
            self.l.warning('Unsupported expression type %s.', type(expr).__name__)
            return None

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
            self.state.kill_and_add_definition(Tmp(dst.tmp_idx, dst.size), self._codeloc(), src)
            self.tmps[dst.tmp_idx] = src

        elif isinstance(dst, ailment.Register):
            reg = Register(dst.reg_offset, dst.size)
            self.state.kill_and_add_definition(reg, self._codeloc(), src)

            if dst.reg_offset == self.arch.sp_offset:
                # TODO: Special logic that frees all definitions above the current stack pointer
                pass

        else:
            l.warning('Unsupported type of Assignment dst %s.', type(dst).__name__)

    def _ail_handle_Store(self, stmt: ailment.Stmt.Store) -> None:
        data: MultiValues = self._expr(stmt.data)
        addr: MultiValues = self._expr(stmt.addr)
        size: int = stmt.size
        if stmt.guard is not None:
            guard = self._expr(stmt.guard)  # pylint:disable=unused-variable
        else:
            guard = None  # pylint:disable=unused-variable

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
                memory_location = MemoryLocation(addr_v._model_concrete.value, size, endness=stmt.endness)

            if memory_location is not None:
                self.state.kill_and_add_definition(memory_location,
                                                   self._codeloc(),
                                                   data,
                                                   endness=stmt.endness)

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
        self._handle_Call_base(stmt, is_expr=False)

    def _handle_Call_base(self, stmt: ailment.Stmt.Call, is_expr: bool=False):
        if isinstance(stmt.target, ailment.Expr.Expression):
            target = self._expr(stmt.target)  # pylint:disable=unused-variable
        else:
            target = stmt.target
        codeloc = self._codeloc()

        ip = Register(self.arch.ip_offset, self.arch.bytes)
        self.state.kill_definitions(ip)

        # When stmt.args are available, used registers/stack variables are decided by stmt.args. Otherwise we fall-back
        # to using all argument registers.
        if stmt.args is not None:
            # getting used expressions from stmt.args
            used_exprs = stmt.args
        elif stmt.calling_convention is not None and stmt.prototype is not None:
            # getting used expressions from the function prototype, its arguments, and the calling convention
            used_exprs = [ ]
            for arg_loc in stmt.calling_convention.arg_locs(stmt.prototype):
                if isinstance(arg_loc, SimRegArg):
                    used_exprs.append(Register(self.arch.registers[arg_loc.reg_name][0], arg_loc.size))
                elif isinstance(arg_loc, SimStackArg):
                    used_exprs.append(SpOffset(arg_loc.size * 8, arg_loc.stack_offset, is_base=False))
                else:
                    l.warning("_handle_Call(): Unsupported arg_loc %r.", arg_loc)
        else:
            used_exprs = None

        # All caller-saved registers will always be killed.
        if stmt.calling_convention is not None:
            cc = stmt.calling_convention
        else:
            # Fall back to the default calling convention
            l.debug("Unknown calling convention for function %s. Fall back to default calling convention.", target)
            cc = self.project.factory.cc()

        killed_vars = [ ailment.Expr.Register(None, None,
                                              self.arch.registers[reg_name][0],
                                              self.arch.registers[reg_name][1] * self.arch.byte_width)
                        for reg_name in cc.CALLER_SAVED_REGS ]

        # Add uses
        if used_exprs is None:
            used_exprs = [ ailment.Expr.Register(None, None,
                                                 self.arch.registers[reg_name][0],
                                                 self.arch.registers[reg_name][1] * self.arch.byte_width)
                           for reg_name in cc.ARG_REGS ]
        for expr in used_exprs:
            self._expr(expr)

        self.state.mark_call(codeloc, target)

        # Add definition
        return_reg_offset = None
        # TODO: Expose it as an option
        return_value_use_full_width_reg = True
        if not is_expr:
            if stmt.ret_expr is not None:
                if isinstance(stmt.ret_expr, ailment.Expr.Register):
                    return_reg_offset = stmt.ret_expr.reg_offset
                    return_reg_size = stmt.ret_expr.size if not return_value_use_full_width_reg else self.arch.bytes
                    reg_atom = Register(return_reg_offset, return_reg_size)
                    top = self.state.top(return_reg_size * self.arch.byte_width)
                    self.state.kill_and_add_definition(reg_atom, codeloc, MultiValues(top))
                elif isinstance(stmt.ret_expr, ailment.Expr.Tmp):
                    tmp_atom = Tmp(stmt.ret_expr.tmp_idx, stmt.ret_expr.size)
                    top = self.state.top(stmt.ret_expr.bits)
                    self.state.kill_and_add_definition(tmp_atom, codeloc, MultiValues(top))
                else:
                    l.warning("Unsupported ret_expr type %s. Please report to GitHub.", stmt.ret_expr.__class__)

            elif cc.RETURN_VAL is not None:
                # Return value is redefined here, so it is not a dummy value
                return_reg_offset, return_reg_size = self.arch.registers[cc.RETURN_VAL.reg_name]
                self.state.kill_definitions(Register(return_reg_offset, return_reg_size))

        # Kill those ones that should be killed
        for var in killed_vars:
            if var.reg_offset == return_reg_offset:
                # Skip the return variable
                continue
            self.state.kill_definitions(Register(var.reg_offset, var.size))

        # kill all cc_ops
        if 'cc_op' in self.arch.registers:
            self.state.kill_definitions(Register(*self.arch.registers['cc_op']))
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep1']))
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep2']))
            self.state.kill_definitions(Register(*self.arch.registers['cc_ndep']))

    def _ail_handle_Return(self, stmt: ailment.Stmt.Return):  # pylint:disable=unused-argument

        codeloc = self._codeloc()

        cc = None
        prototype = None
        if self.state.analysis.subject.type == SubjectType.Function:
            cc = self.state.analysis.subject.content.calling_convention
            prototype = self.state.analysis.subject.content.prototype
            # import ipdb; ipdb.set_trace()

        if cc is None:
            # fall back to the default calling convention
            cc_cls = DEFAULT_CC.get(self.project.arch.name, None)
            if cc_cls is None:
                l.warning("Unknown default calling convention for architecture %s.", self.project.arch.name)
                cc = None
            else:
                cc = cc_cls(self.project.arch)

        if cc is not None:
            # callee-saved args
            for reg in self.arch.register_list:
                if (reg.general_purpose
                        and reg.name not in cc.CALLER_SAVED_REGS
                        and reg.name not in cc.ARG_REGS
                        and reg.vex_offset not in {self.arch.sp_offset, self.arch.bp_offset, self.arch.ip_offset, }
                        and (isinstance(cc.RETURN_VAL, SimRegArg) and reg.name != cc.RETURN_VAL.reg_name)
                ):
                    self.state.add_register_use(reg.vex_offset, reg.size, codeloc)

        if stmt.ret_exprs:
            # Handle return expressions
            for ret_expr in stmt.ret_exprs:
                self._expr(ret_expr)
            return

        # No return expressions are available.
        # consume registers that are potentially useful

        # return value
        if cc is not None and prototype is not None and prototype.returnty is not None:
            ret_val = cc.return_val(prototype.returnty)
            if isinstance(ret_val, SimRegArg):
                if ret_val.clear_entire_reg:
                    offset, size = cc.arch.registers[ret_val.reg_name]
                else:
                    offset = cc.arch.registers[ret_val.reg_name][0] + ret_val.reg_offset
                    size = ret_val.size
                self.state.add_register_use(offset, size, codeloc)
            else:
                l.error("Cannot handle CC with non-register return value location")

        # base pointer
        # TODO: Check if the stack base pointer is used as a stack base pointer in this function or not
        self.state.add_register_use(self.project.arch.bp_offset, self.project.arch.bytes, codeloc)
        # We don't add sp since stack pointers are supposed to be get rid of in AIL. this is definitely a hack though
        # self.state.add_use(Register(self.project.arch.sp_offset, self.project.arch.bits // 8), codeloc)

    def _ail_handle_DirtyStatement(self, stmt: ailment.Stmt.DirtyStatement):
        # TODO: The logic below is subject to change when ailment.Stmt.DirtyStatement is changed

        if isinstance(stmt.dirty_stmt, pyvex.stmt.Dirty):
            # TODO: We need dirty helpers for a more complete understanding of clobbered registers
            tmp = stmt.dirty_stmt.tmp
            if tmp in (-1, 0xffffffff):
                return
            size = 32  # FIXME: We don't know the size.
            self.state.kill_and_add_definition(Tmp(tmp, size), self._codeloc(), None)
            self.tmps[tmp] = None
        else:
            l.warning("Unexpected type of dirty statement %s.", type(stmt.dirty_stmt))

    #
    # AIL expression handlers
    #

    def _ail_handle_BV(self, expr: claripy.ast.Base) -> MultiValues:
        return MultiValues(expr)

    def _ail_handle_Tmp(self, expr: ailment.Expr.Tmp) -> MultiValues:

        self.state.add_tmp_use(expr.tmp_idx, self._codeloc())

        tmp = super()._ail_handle_Tmp(expr)
        if tmp is None:
            return MultiValues(self.state.top(expr.bits))
        return tmp

    def _ail_handle_CallExpr(self, expr: ailment.Stmt.Call) -> MultiValues:
        self._handle_Call_base(expr, is_expr=True)
        return MultiValues(self.state.top(expr.bits))

    def _ail_handle_Register(self, expr: ailment.Expr.Register) -> MultiValues:

        self.state: ReachingDefinitionsState

        reg_offset = expr.reg_offset
        size = expr.size
        # bits = size * 8

        reg_atom = Register(reg_offset, size)

        # first check if it is ever defined
        try:
            value: MultiValues = self.state.register_definitions.load(reg_offset, size=size)
        except SimMemoryMissingError:
            # the value does not exist
            top = self.state.top(size * self.state.arch.byte_width)
            # annotate it
            top = self.state.annotate_with_def(top, Definition(reg_atom, ExternalCodeLocation()))
            value = MultiValues(top)
            # write it back
            self.state.kill_and_add_definition(reg_atom, self._external_codeloc(), value)

        # extract Definitions
        defs: Optional[Iterable[Definition]] = None
        for vs in value.values():
            for v in vs:
                if defs is None:
                    defs = self.state.extract_defs(v)
                else:
                    defs = chain(defs, self.state.extract_defs(v))

        if defs is None:
            # define it right away as an external dependency
            self.state.kill_and_add_definition(reg_atom, self._external_codeloc(), value)
        else:
            codeloc = self._codeloc()
            self.state.add_register_use_by_defs(defs, codeloc, expr=expr)

        return value

    def _ail_handle_Load(self, expr: ailment.Expr.Load) -> MultiValues:
        addrs: MultiValues = self._expr(expr.addr)

        size = expr.size
        bits = expr.bits
        if expr.guard is not None:
            guard = self._expr(expr.guard)  # pylint:disable=unused-variable
            alt = self._expr(expr.alt)  # pylint:disable=unused-variable
        else:
            guard = None  # pylint:disable=unused-variable
            alt = None  # pylint:disable=unused-variable

        # convert addrs from MultiValues to a list of valid addresses
        if addrs.count() == 1:
            addrs_v = next(iter(addrs.values()))
        else:
            top = self.state.top(bits)
            # annotate it
            dummy_atom = MemoryLocation(0, size, endness=expr.endness)
            def_ = Definition(dummy_atom, ExternalCodeLocation())
            top = self.state.annotate_with_def(top, def_)
            # add use
            self.state.add_memory_use_by_def(def_, self._codeloc(), expr=expr)
            return MultiValues(top)

        result: Optional[MultiValues] = None
        for addr in addrs_v:
            if not isinstance(addr, claripy.ast.Base):
                continue
            if addr.concrete:
                # a concrete address
                concrete_addr: int = addr._model_concrete.value
                try:
                    vs: MultiValues = self.state.memory_definitions.load(concrete_addr, size=size, endness=expr.endness)
                    defs = set(LiveDefinitions.extract_defs_from_mv(vs))
                except SimMemoryMissingError:
                    continue

                self.state.add_memory_use_by_defs(defs, self._codeloc(), expr=expr)
                result = result.merge(vs) if result is not None else vs
            elif self.state.is_stack_address(addr):
                stack_offset = self.state.get_stack_offset(addr)
                if stack_offset is not None:
                    stack_addr = self.state.live_definitions.stack_offset_to_stack_addr(stack_offset)
                    try:
                        vs: MultiValues = self.state.stack_definitions.load(stack_addr, size=size, endness=expr.endness)
                        defs = set(LiveDefinitions.extract_defs_from_mv(vs))
                    except SimMemoryMissingError:
                        continue

                    self.state.add_memory_use_by_defs(defs, self._codeloc(), expr=expr)
                    result = result.merge(vs) if result is not None else vs
            else:
                l.debug('Memory address %r undefined or unsupported at pc %#x.', addr, self.ins_addr)

        if result is None:
            top = self.state.top(bits)
            # TODO: Annotate top with a definition
            result = MultiValues(top)

        return result

    def _ail_handle_Convert(self, expr: ailment.Expr.Convert) -> MultiValues:
        to_conv: MultiValues = self._expr(expr.operand)
        bits = expr.to_bits
        size = bits // self.arch.byte_width

        if to_conv.count() == 1 and 0 in to_conv:
            values = to_conv[0]
        else:
            top = self.state.top(expr.to_bits)
            # annotate it
            dummy_atom = MemoryLocation(0, size, endness=self.arch.memory_endness)
            def_ = Definition(dummy_atom, ExternalCodeLocation())
            top = self.state.annotate_with_def(top, def_)
            # add use
            self.state.add_memory_use_by_def(def_, self._codeloc(), expr=expr)
            return MultiValues(top)

        converted = set()
        for v in values:
            if expr.to_bits < expr.from_bits:
                conv = v[expr.to_bits - 1:0]
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
            r = MultiValues(~operand_v)
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
            r = MultiValues(-operand_v)
        else:
            r = MultiValues(self.state.top(bits))

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
                if all(v.concrete for v in expr0[0]):
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
            if expr0_v.concrete and expr1_v.concrete:
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
                if all(v.concrete for v in expr0[0]):
                    vs = {v - expr1_v for v in expr0[0]}
                    r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # subtracting a single value from a multivalue
            if expr1.count() == 1 and 0 in expr1:
                if all(v.concrete for v in expr1[0]):
                    vs = {expr0_v - v for v in expr1[0]}
                    r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
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
                if all(v.concrete for v in expr0[0]):
                    vs = {(claripy.LShR(v, expr1_v._model_concrete.value) if v.concrete else self.state.top(bits))
                          for v in expr0[0]}
                    r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v >> each value in expr1
            if expr1.count() == 1 and 0 in expr1:
                if all(v.concrete for v in expr1[0]):
                    vs = {(claripy.LShR(expr0_v, v._model_concrete.value) if v.concrete else self.state.top(bits))
                          for v in expr1[0]}
                    r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(claripy.LShR(expr0_v, expr1_v._model_concrete.value))

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
                if all(v.concrete for v in expr0[0]):
                    vs = {(claripy.LShR(v, expr1_v._model_concrete.value) if v.concrete else self.state.top(bits))
                          for v in expr0[0]}
                    r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v >> each value in expr1
            if expr1.count() == 1 and 0 in expr1:
                if all(v.concrete for v in expr1[0]):
                    vs = {(claripy.LShR(expr0_v, v._model_concrete.value) if v.concrete else self.state.top(bits))
                          for v in expr1[0]}
                    r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(expr0_v >> expr1_v._model_concrete.value)

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
                if all(v.concrete for v in expr0[0]):
                    vs = {((v << expr1_v._model_concrete.value) if v.concrete else self.state.top(bits))
                          for v in expr0[0]}
                    r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v >> each value in expr1
            if expr1.count() == 1 and 0 in expr1:
                if all(v.concrete for v in expr1[0]):
                    vs = {((expr0_v << v._model_concrete.value) if v.concrete else self.state.top(bits))
                          for v in expr1[0]}
                    r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                r = MultiValues(expr0_v << expr1_v._model_concrete.value)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

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

        r = None
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

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None or expr1_v is None:
            r = MultiValues(self.state.top(bits))
            return r

        r = MultiValues(claripy.If(expr0_v != 0, expr0_v, expr1_v))
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

        if op0 is None: op0 = expr.operands[0]
        if op1 is None: op1 = expr.operands[1]

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

    def _ail_handle_Const(self, expr) -> MultiValues:
        self.state.mark_const(self._codeloc(), expr)
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

    def _ail_handle_DirtyExpression(self,
                                    expr: ailment.Expr.DirtyExpression
                                    ) -> MultiValues:  # pylint:disable=no-self-use

        if isinstance(expr.dirty_expr, ailment.Expr.VEXCCallExpression):
            for operand in expr.dirty_expr.operands:
                self._expr(operand)

        top = self.state.top(expr.bits)
        return MultiValues(top)

    #
    # User defined high-level statement handlers
    #

    def _handle_function(self):
        if len(self._call_stack) + 1 > self._maximum_local_call_depth:
            l.warning('The analysis reached its maximum recursion depth.')
            return None

        defs_ip = self.state.register_definitions.get_objects_by_offset(self.arch.ip_offset)
        if len(defs_ip) != 1:
            l.error('Invalid definition(s) for IP.')
            return None

        ip_data = next(iter(defs_ip)).data
        if len(ip_data) != 1:
            l.error('Invalid number of values for IP.')
            return None

        ip_addr = ip_data.get_first_element()
        if not isinstance(ip_addr, int):
            l.error('Invalid type %s for IP.', type(ip_addr).__name__)
            return None

        is_internal = False
        ext_func_name: Optional[str] = None
        symbol = None
        if self.project.loader.main_object.contains_addr(ip_addr) is True:
            ext_func_name = self.project.loader.find_plt_stub_name(ip_addr)
            if ext_func_name is None:
                is_internal = True
        else:
            symbol = self.project.loader.find_symbol(ip_addr)
        if symbol is not None:
            self._function_handler.handle_external_function_symbol(self.state, symbol, self._codeloc())
        elif ext_func_name is not None:
            self._function_handler.handle_external_function_name(self.state, ext_func_name, self._codeloc())
        elif is_internal is True:
            is_updated, state, visited_blocks, dep_graph = self._function_handler.handle_local_function(
                self.state,
                ip_addr,
                self._call_stack,
                self._maximum_local_call_depth,
                self._visited_blocks,
                self._dep_graph,
            )

            if is_updated is True:
                self.state = state
                self._visited_blocks = visited_blocks
                self._dep_graph = dep_graph
        else:
            l.warning('Could not find function name for external function at address %#x.', ip_addr)
        return None
