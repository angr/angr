from itertools import chain
from typing import Iterable, Optional
import logging

import archinfo
import claripy
import ailment

from ...engines.light import SimEngineLight, SimEngineLightAILMixin, SpOffset
from ...errors import SimEngineError, SimMemoryMissingError
from ...calling_conventions import DEFAULT_CC, SimRegArg, SimStackArg
from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ...knowledge_plugins.key_definitions.atoms import Register, Tmp, MemoryLocation
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from ...knowledge_plugins.key_definitions.live_definitions import Definition
from .external_codeloc import ExternalCodeLocation
from .rd_state import ReachingDefinitionsState

l = logging.getLogger(name=__name__)


class SimEngineRDAIL(
    SimEngineLightAILMixin,
    SimEngineLight,
):  # pylint:disable=abstract-method

    arch: archinfo.Arch
    state: ReachingDefinitionsState

    def __init__(self, project, call_stack, maximum_local_call_depth, function_handler=None):
        super().__init__()
        self.project = project
        self._call_stack = call_stack
        self._maximum_local_call_depth = maximum_local_call_depth
        self._function_handler = function_handler
        self._visited_blocks = None
        self._dep_graph = None

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

        super()._handle_Stmt(stmt)

        if self.state.analysis:
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_AFTER)

    def _ail_handle_Assignment(self, stmt):
        """

        :param ailment.Assignment stmt:
        :return:
        """

        src = self._expr(stmt.src)
        dst = stmt.dst

        if src is None:
            src = self.state.top(dst.bits)

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

        cond = self._expr(stmt.condition)  # pylint:disable=unused-variable
        true_target = self._expr(stmt.true_target)  # pylint:disable=unused-variable
        false_target = self._expr(stmt.false_target)  # pylint:disable=unused-variable

        ip = Register(self.arch.ip_offset, self.arch.bytes)
        codeloc = self._codeloc()

        # Use the same annotated data for kill_definitions() to avoid creating ASTs multiple times
        # Note that the cached dummy definition is always the IP register. This is intentional.
        top_v = self.state.top(self.arch.bits)
        dummy_def = Definition(Register(self.arch.ip_offset, self.arch.bytes), codeloc, dummy=True)
        top_v = self.state.annotate_with_def(top_v, dummy_def)
        top_mv = MultiValues(offset_to_values={0: {top_v}})

        self.state.kill_definitions(ip, codeloc, data=top_mv, annotated=True)

        # kill all cc_ops
        if 'cc_op' in self.arch.registers:
            self.state.kill_definitions(Register(*self.arch.registers['cc_op']), codeloc, data=top_mv, annotated=True)
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep1']), codeloc, data=top_mv, annotated=True)
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep2']), codeloc, data=top_mv, annotated=True)
            self.state.kill_definitions(Register(*self.arch.registers['cc_ndep']), codeloc, data=top_mv, annotated=True)

    def _ail_handle_Call(self, stmt: ailment.Stmt.Call):
        self._handle_Call_base(stmt, is_expr=False)

    def _handle_Call_base(self, stmt: ailment.Stmt.Call, is_expr: bool=False):
        target = self._expr(stmt.target)  # pylint:disable=unused-variable
        codeloc = self._codeloc()

        # Use the same annotated data for kill_definitions() to avoid creating ASTs multiple times
        # Note that the cached dummy definition is always the IP register. This is intentional.
        top_v = self.state.top(self.arch.bits)
        dummy_def = Definition(Register(self.arch.ip_offset, self.arch.bytes), codeloc, dummy=True)
        top_v = self.state.annotate_with_def(top_v, dummy_def)
        top_mv = MultiValues(offset_to_values={0: {top_v}})

        ip = Register(self.arch.ip_offset, self.arch.bytes)
        self.state.kill_definitions(ip, codeloc, data=top_mv, annotated=True)

        # When stmt.args are available, used registers/stack variables are decided by stmt.args. Otherwise we fall-back
        # to using all argument registers.
        if stmt.args is not None:
            # getting used expressions from stmt.args
            used_exprs = stmt.args
        elif stmt.calling_convention is not None and (
                stmt.calling_convention.func_ty is not None or stmt.calling_convention.args is not None):
            # getting used expressions from the function prototype, its arguments, and the calling convention
            used_exprs = [ ]
            for arg_loc in stmt.calling_convention.arg_locs():
                if isinstance(arg_loc, SimRegArg):
                    used_exprs.append(Register(self.arch.registers[arg_loc.reg_name], arg_loc.size))
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

        killed_vars = [ Register(*self.arch.registers[reg_name]) for reg_name in cc.CALLER_SAVED_REGS ]

        # Add uses
        if used_exprs is None:
            used_exprs = [ Register(*self.arch.registers[reg_name]) for reg_name in cc.ARG_REGS ]
        for expr in used_exprs:
            self._expr(expr)

        # Add definition
        return_reg_offset = None
        if not is_expr:
            if stmt.ret_expr is not None:
                if isinstance(stmt.ret_expr, ailment.Expr.Register):
                    return_reg_offset = stmt.ret_expr.reg_offset
                    return_reg_size = stmt.ret_expr.size
                    reg_atom = Register(return_reg_offset, return_reg_size)
                    top = self.state.top(return_reg_size * self.arch.byte_width)
                    self.state.kill_and_add_definition(reg_atom, codeloc, MultiValues(offset_to_values={0: {top}}))
                else:
                    l.warning("Unsupported ret_expr type %s. Please report to GitHub.", stmt.ret_expr.__class__)

            else:
                # Return value is redefined here, so it is not a dummy value
                return_reg_offset, return_reg_size = self.arch.registers[cc.RETURN_VAL.reg_name]
                self.state.kill_definitions(Register(return_reg_offset, return_reg_size), codeloc, dummy=False)

        # Kill those ones that should be killed
        for var in killed_vars:
            if var.reg_offset == return_reg_offset:
                # Skip the return variable
                continue
            self.state.kill_definitions(var, codeloc, data=top_mv, annotated=True)

        # kill all cc_ops
        if 'cc_op' in self.arch.registers:
            self.state.kill_definitions(Register(*self.arch.registers['cc_op']), codeloc, data=top_mv, annotated=True)
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep1']), codeloc, data=top_mv, annotated=True)
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep2']), codeloc, data=top_mv, annotated=True)
            self.state.kill_definitions(Register(*self.arch.registers['cc_ndep']), codeloc, data=top_mv, annotated=True)

    def _ail_handle_Return(self, stmt: ailment.Stmt.Return):  # pylint:disable=unused-argument

        if stmt.ret_exprs:
            # Handle return expressions
            for ret_expr in stmt.ret_exprs:
                self._expr(ret_expr)

            return

        # No return expressions are available.
        # consume registers that are potentially useful
        # TODO: Consider the calling convention of the current function

        cc_cls = DEFAULT_CC.get(self.project.arch.name, None)
        if cc_cls is None:
            l.warning("Unknown default calling convention for architecture %s.", self.project.arch.name)
            return

        cc = cc_cls(self.project.arch)
        codeloc = self._codeloc()
        size = self.project.arch.bits // 8
        # return value
        if cc.RETURN_VAL is not None:
            if isinstance(cc.RETURN_VAL, SimRegArg):
                offset = cc.RETURN_VAL._fix_offset(None, size, arch=self.project.arch)
                self.state.add_use(Register(offset, size), codeloc)
        # base pointer
        # TODO: Check if the stack base pointer is used as a stack base pointer in this function or not
        self.state.add_use(Register(self.project.arch.bp_offset, self.project.arch.bits // 8), codeloc)
        # We don't add sp since stack pointers are supposed to be get rid of in AIL. this is definitely a hack though
        # self.state.add_use(Register(self.project.arch.sp_offset, self.project.arch.bits // 8), codeloc)

    def _ail_handle_DirtyStatement(self, stmt: ailment.Stmt.DirtyStatement):
        # TODO: The logic below is subject to change when ailment.Stmt.DirtyStatement is changed
        tmp = stmt.dirty_stmt.dst
        cvt_sizes = {
            'ILGop_IdentV128': 16,
            'ILGop_Ident64': 8,
            'ILGop_Ident32': 4,
            'ILGop_16Uto32': 4,
            'ILGop_16Sto32': 4,
            'ILGop_8Uto32': 4,
            'ILGop_8Sto32': 4,
        }
        size = cvt_sizes[stmt.dirty_stmt.cvt]
        self.state.kill_and_add_definition(Tmp(tmp, size), self._codeloc(), None)
        self.tmps[tmp] = None

    #
    # AIL expression handlers
    #

    def _ail_handle_BV(self, expr: claripy.ast.Base) -> MultiValues:
        return MultiValues(offset_to_values={0: {expr}})

    def _ail_handle_Tmp(self, expr: ailment.Expr.Tmp) -> MultiValues:

        self.state.add_use(Tmp(expr.tmp_idx, expr.size), self._codeloc())

        return super()._ail_handle_Tmp(expr)

    def _ail_handle_CallExpr(self, expr: ailment.Stmt.Call) -> MultiValues:
        self._handle_Call_base(expr, is_expr=True)
        return MultiValues(offset_to_values={0: {self.state.top(expr.bits)}})

    def _ail_handle_Register(self, expr) -> MultiValues:

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
            value = MultiValues(offset_to_values={0: {top}})
            # write it back
            self.state.kill_and_add_definition(reg_atom, self._external_codeloc(), value)

        # extract Definitions
        defs: Optional[Iterable[Definition]] = None
        for vs in value.values.values():
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
            for def_ in defs:
                self.state.add_use_by_def(def_, codeloc)

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
        if len(addrs.values) == 1:
            addrs_v = next(iter(addrs.values.values()))
        else:
            top = self.state.top(bits)
            # annotate it
            dummy_atom = MemoryLocation(0, size, endness=expr.endness)
            top = self.state.annotate_with_def(top, Definition(dummy_atom, ExternalCodeLocation()))
            # add use
            self.state.add_use(dummy_atom, self._codeloc())
            return MultiValues(offset_to_values={0: {top}})

        result: Optional[MultiValues] = None
        for addr in addrs_v:
            if not isinstance(addr, claripy.ast.Base):
                continue
            if addr.concrete:
                # a concrete address
                addr = addr._model_concrete.value
                try:
                    vs: MultiValues = self.state.memory_definitions.load(addr, size=size, endness=expr.endness)
                except SimMemoryMissingError:
                    continue

                memory_location = MemoryLocation(addr, size, endness=expr.endness)
                self.state.add_use(memory_location, self._codeloc())
                result = result.merge(vs) if result is not None else vs
            elif self.state.is_stack_address(addr):
                stack_offset = self.state.get_stack_offset(addr)
                if stack_offset is not None:
                    stack_addr = self.state.live_definitions.stack_offset_to_stack_addr(stack_offset)
                    try:
                        vs: MultiValues = self.state.stack_definitions.load(stack_addr, size=size, endness=expr.endness)
                    except SimMemoryMissingError:
                        continue

                    memory_location = MemoryLocation(SpOffset(self.arch.bits, stack_offset), size, endness=expr.endness)
                    self.state.add_use(memory_location, self._codeloc())
                    result = result.merge(vs) if result is not None else vs
            else:
                l.debug('Memory address %r undefined or unsupported at pc %#x.', addr, self.ins_addr)

        if result is None:
            top = self.state.top(bits)
            # TODO: Annotate top with a definition
            result = MultiValues(offset_to_values={0: {top}})

        return result

    def _ail_handle_Convert(self, expr: ailment.Expr.Convert) -> MultiValues:
        to_conv: MultiValues = self._expr(expr.operand)
        bits = expr.to_bits
        size = bits // self.arch.byte_width

        if len(to_conv.values) == 1 and 0 in to_conv.values:
            values = to_conv.values[0]
        else:
            top = self.state.top(expr.to_bits)
            # annotate it
            dummy_atom = MemoryLocation(0, size, endness=self.arch.memory_endness)
            top = self.state.annotate_with_def(top, Definition(dummy_atom, ExternalCodeLocation()))
            # add use
            self.state.add_use(dummy_atom, self._codeloc())
            return MultiValues(offset_to_values={0: {top}})

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

    def _ail_handle_ITE(self, expr: ailment.Expr.ITE) -> MultiValues:
        _: MultiValues = self._expr(expr.cond)
        iftrue: MultiValues = self._expr(expr.iftrue)
        _: MultiValues = self._expr(expr.iffalse)
        top = self.state.top(len(iftrue))
        return MultiValues(offset_to_values={0: {top}})

    def _ail_handle_Not(self, expr: ailment.Expr.UnaryOp) -> MultiValues:
        operand: MultiValues = self._expr(expr.operand)
        bits = expr.bits

        r = None
        operand_v = operand.one_value()

        if operand_v is None or self.state.is_top(operand_v):
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        else:
            r = MultiValues(offset_to_values={0: {~operand_v}})

        return r

    def _ail_handle_BinaryOp(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        r = super()._ail_handle_BinaryOp(expr)
        if isinstance(r, ailment.Expr.BinaryOp):
            l.warning("Unimplemented operation %s.", expr.op)
            top = self.state.top(expr.bits)
            return MultiValues(offset_to_values={0: {top}})
        return r

    def _ail_handle_Add(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # adding a single value to a multivalue
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {v + expr1_v for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # adding a single value to a multivalue
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {v + expr0_v for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # adding two single values together
            r = MultiValues(offset_to_values={0: {expr0_v + expr1_v}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _ail_handle_Sub(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # subtracting a single value from a multivalue
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {v - expr1_v for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # subtracting a single value from a multivalue
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {expr0_v - v for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            r = MultiValues(offset_to_values={0: {expr0_v - expr1_v}})

        if r is None:
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
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # each value in expr0 >> expr1_v
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {(claripy.LShR(v, expr1_v._model_concrete.value) if v.concrete else self.state.top(bits)) for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v >> each value in expr1
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {(claripy.LShR(expr0_v, v._model_concrete.value) if v.concrete else self.state.top(bits)) for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            if expr1_v.concrete:
                r = MultiValues(offset_to_values={0: {claripy.LShR(expr0_v, expr1_v._model_concrete.value)}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _ail_handle_Sar(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # each value in expr0 >> expr1_v
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {(claripy.LShR(v, expr1_v._model_concrete.value) if v.concrete else self.state.top(bits)) for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v >> each value in expr1
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {(claripy.LShR(expr0_v, v._model_concrete.value) if v.concrete else self.state.top(bits)) for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            if expr1_v.concrete:
                r = MultiValues(offset_to_values={0: {expr0_v >> expr1_v._model_concrete.value}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _ail_handle_Shl(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # each value in expr0 << expr1_v
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {((v << expr1_v._model_concrete.value) if v.concrete else self.state.top(bits)) for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v >> each value in expr1
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {((expr0_v << v._model_concrete.value) if v.concrete else self.state.top(bits)) for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            if expr1_v.concrete:
                r = MultiValues(offset_to_values={0: {expr0_v << expr1_v._model_concrete.value}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _ail_handle_And(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
            return r

        if expr0_v is None and expr1_v is not None:
            # expr1_v & each value in expr0
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {v & expr1_v for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v & each value in expr1
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {expr0_v & v for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # spcial handling for stack alignment
            if self.state.is_stack_address(expr0_v):
                r = MultiValues(offset_to_values={0: {expr0_v}})
            else:
                r = MultiValues(offset_to_values={0: {expr0_v & expr1_v}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _ail_handle_Or(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # expr1_v | each value in expr0
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {v | expr1_v for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v | each value in expr1
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {expr0_v | v for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            r = MultiValues(offset_to_values={0: {expr0_v | expr1_v}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _ail_handle_Xor(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # expr1_v ^ each value in expr0
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {v ^ expr1_v for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # expr0_v ^ each value in expr1
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {expr0_v ^ v for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            r = MultiValues(offset_to_values={0: {expr0_v ^ expr1_v}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _ail_handle_Concat(self, expr: ailment.Expr.BinaryOp) -> MultiValues:
        expr0: MultiValues = self._expr(expr.operands[0])
        expr1: MultiValues = self._expr(expr.operands[1])
        bits = expr.bits

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # concatenate expr1_v with each value in expr0
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {claripy.Concat(v, expr1_v) for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # concatenate expr0_v with each value in expr1
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {claripy.Concat(expr0_v, v) for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            r = MultiValues(offset_to_values={0: {claripy.Concat(expr0_v, expr1_v)}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _ail_handle_Cmp(self, expr) -> MultiValues:
        op0 = self._expr(expr.operands[0])
        op1 = self._expr(expr.operands[1])

        if op0 is None: op0 = expr.operands[0]
        if op1 is None: op1 = expr.operands[1]

        top = self.state.top(expr.bits)
        return MultiValues(offset_to_values={0: {top}})

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
        return MultiValues(offset_to_values={0: {claripy.BVV(expr.value, expr.bits)}})

    def _ail_handle_StackBaseOffset(self, expr: ailment.Expr.StackBaseOffset) -> MultiValues:
        stack_addr = self.state.stack_address(expr.offset)
        return MultiValues(offset_to_values={0: {stack_addr}})

    def _ail_handle_DirtyExpression(self, expr: ailment.Expr.DirtyExpression) -> MultiValues:  # pylint:disable=no-self-use
        # FIXME: DirtyExpression needs .bits
        top = self.state.top(expr.bits)
        return MultiValues(offset_to_values={0: {top}})

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
        ext_func_name = None
        if self.project.loader.main_object.contains_addr(ip_addr) is True:
            ext_func_name = self.project.loader.find_plt_stub_name(ip_addr)
            if ext_func_name is None:
                is_internal = True
        else:
            symbol = self.project.loader.find_symbol(ip_addr)
            if symbol is not None:
                ext_func_name = symbol.name

        if ext_func_name is not None:
            handler_name = 'handle_%s' % ext_func_name
            if hasattr(self._function_handler, handler_name):
                getattr(self._function_handler, handler_name)(self.state, self._codeloc())
            else:
                l.warning('Please implement the external function handler for %s() with your own logic.',
                          ext_func_name)
        elif is_internal is True:
            handler_name = 'handle_local_function'
            if hasattr(self._function_handler, handler_name):
                is_updated, state, visited_blocks, dep_graph = getattr(self._function_handler, handler_name)(
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
                l.warning('Please implement the local function handler with your own logic.')
        else:
            l.warning('Could not find function name for external function at address %#x.', ip_addr)
        return None
