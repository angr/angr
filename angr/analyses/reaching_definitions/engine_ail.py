from typing import Iterable, Union
import logging

import ailment

from ...engines.light import SimEngineLight, SimEngineLightAILMixin, RegisterOffset, SpOffset
from ...errors import SimEngineError
from ...calling_conventions import DEFAULT_CC, SimRegArg, SimStackArg
from ...knowledge_plugins.key_definitions.atoms import Register, Tmp, MemoryLocation
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from ...knowledge_plugins.key_definitions.dataset import DataSet
from ...knowledge_plugins.key_definitions.undefined import Undefined, undefined
from ...knowledge_plugins.key_definitions.live_definitions import Definition
from .external_codeloc import ExternalCodeLocation
from .rd_state import ReachingDefinitionsState

l = logging.getLogger(name=__name__)


class SimEngineRDAIL(
    SimEngineLightAILMixin,
    SimEngineLight,
):  # pylint:disable=abstract-method
    def __init__(self, project, current_local_call_depth, maximum_local_call_depth, function_handler=None):
        super(SimEngineRDAIL, self).__init__()
        self.project = project
        self._current_local_call_depth = current_local_call_depth
        self._maximum_local_call_depth = maximum_local_call_depth
        self._function_handler = function_handler
        self._visited_blocks = None

        self.state: ReachingDefinitionsState

    def process(self, state, *args, **kwargs):
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
        return self.state, self._visited_blocks

    #
    # Private methods
    #

    @staticmethod
    def _external_codeloc():
        return ExternalCodeLocation()

    @staticmethod
    def _dataset_unpack(d):
        if type(d) is DataSet and len(d) == 1:
            return next(iter(d.data))
        return d

    #
    # AIL statement handlers
    #

    def _handle_Stmt(self, stmt):

        if self.state.analysis:
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

        super(SimEngineRDAIL, self)._handle_Stmt(stmt)

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
            src = DataSet(undefined, dst.bits)

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

    def _ail_handle_Store(self, stmt: ailment.Stmt.Store):
        data: DataSet = self._expr(stmt.data)
        addr: Iterable[Union[int,SpOffset,Undefined]] = self._expr(stmt.addr)
        size: int = stmt.size
        if stmt.guard is not None:
            guard = self._expr(stmt.guard)  # pylint:disable=unused-variable
        else:
            guard = None  # pylint:disable=unused-variable

        for a in addr:
            if type(a) is Undefined:
                l.info('Memory address undefined, ins_addr = %#x.', self.ins_addr)
                continue

            if any(type(d) is Undefined for d in data):
                l.info('Data to write at address %s undefined, ins_addr = %#x.',
                       hex(a) if type(a) is int else a, self.ins_addr
                       )

            memory_location = MemoryLocation(a, size)
            if not memory_location.symbolic:
                # different addresses are not killed by a subsequent iteration, because kill only removes entries
                # with same index and same size
                self.state.kill_and_add_definition(memory_location, self._codeloc(), data)

    def _ail_handle_Jump(self, stmt):
        _ = self._expr(stmt.target)

    def _ail_handle_ConditionalJump(self, stmt):

        cond = self._expr(stmt.condition)  # pylint:disable=unused-variable
        true_target = self._expr(stmt.true_target)  # pylint:disable=unused-variable
        false_target = self._expr(stmt.false_target)  # pylint:disable=unused-variable

        ip = Register(self.arch.ip_offset, self.arch.bytes)
        self.state.kill_definitions(ip, self._codeloc(), )

        # kill all cc_ops
        if 'cc_op' in self.arch.registers:
            self.state.kill_definitions(Register(*self.arch.registers['cc_op']), self._codeloc())
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep1']), self._codeloc())
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep2']), self._codeloc())
            self.state.kill_definitions(Register(*self.arch.registers['cc_ndep']), self._codeloc())

    def _ail_handle_Call(self, stmt):
        target = self._expr(stmt.target)  # pylint:disable=unused-variable

        ip = Register(self.arch.ip_offset, self.arch.bytes)
        self.state.kill_definitions(ip, self._codeloc())

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
        return_reg_offset, return_reg_size = self.arch.registers[cc.RETURN_VAL.reg_name]

        # Add uses
        if used_exprs is None:
            used_exprs = [ Register(*self.arch.registers[reg_name]) for reg_name in cc.ARG_REGS ]
        for expr in used_exprs:
            self._expr(expr)

        # Return value is redefined here, so it is not a dummy value
        self.state.kill_definitions(Register(return_reg_offset, return_reg_size), self._codeloc(), dummy=False)
        # Kill those ones that should be killed
        for var in killed_vars:
            if var.reg_offset == return_reg_offset:
                # Skip the return variable
                continue
            self.state.kill_definitions(var, self._codeloc())

        # kill all cc_ops
        if 'cc_op' in self.arch.registers:
            self.state.kill_definitions(Register(*self.arch.registers['cc_op']), self._codeloc())
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep1']), self._codeloc())
            self.state.kill_definitions(Register(*self.arch.registers['cc_dep2']), self._codeloc())
            self.state.kill_definitions(Register(*self.arch.registers['cc_ndep']), self._codeloc())

    def _ail_handle_Return(self, stmt):  # pylint:disable=unused-argument
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

    def _ail_handle_Tmp(self, expr: ailment.Expr.Tmp):

        self.state.add_use(Tmp(expr.tmp_idx, expr.size), self._codeloc())

        return super(SimEngineRDAIL, self)._ail_handle_Tmp(expr)

    def _ail_handle_Register(self, expr):

        reg_offset = expr.reg_offset
        size = expr.size
        bits = size * 8

        # first check if it is ever defined
        defs: Iterable[Definition] = self.state.register_definitions.get_objects_by_offset(reg_offset)
        if not defs:
            # define it right away as an external dependency
            self.state.kill_and_add_definition(Register(reg_offset, size), self._external_codeloc(), None)

        self.state.add_use(Register(reg_offset, size), self._codeloc())

        if reg_offset == self.arch.sp_offset:
            return DataSet(SpOffset(bits, 0), bits)
        elif reg_offset == self.arch.bp_offset:
            return DataSet(SpOffset(bits, 0, is_base=True), bits)

        try:
            data = DataSet(set(), bits)
            for def_ in defs:
                if def_.data is not None:
                    if def_.data.bits < data.bits:
                        # zero-extend
                        def_data = DataSet(def_.data.data, data.bits)
                    elif def_.data.bits > data.bits:
                        # truncate
                        def_data = def_.data.truncate(data.bits)
                    else:
                        def_data = def_.data
                    data.update(def_data)
                else:
                    l.warning('Data in register <%s> is undefined at %#x.',
                              self.arch.register_names[reg_offset], self.ins_addr
                              )
            return data
        except KeyError:
            return DataSet(RegisterOffset(bits, reg_offset, 0), bits)

    def _ail_handle_Load(self, expr: ailment.Expr.Load):
        addrs = self._expr(expr.addr)
        size = expr.size
        bits = expr.bits
        if expr.guard is not None:
            guard = self._expr(expr.guard)  # pylint:disable=unused-variable
            alt = self._expr(expr.alt)  # pylint:disable=unused-variable
        else:
            guard = None  # pylint:disable=unused-variable
            alt = None  # pylint:disable=unused-variable

        data = set()
        for addr in addrs:
            if isinstance(addr, int):
                current_defs = self.state.memory_definitions.get_objects_by_offset(addr)
                if current_defs:
                    for current_def in current_defs:
                        data.update(current_def.data)
                    if any(type(d) is Undefined for d in data):
                        l.info('Memory at address %#x undefined, ins_addr = %#x.', addr, self.ins_addr)
                else:
                    try:
                        data.add(self.project.loader.memory.unpack_word(addr, size=size))
                    except KeyError:
                        pass

                # FIXME: _add_memory_use() iterates over the same loop
                memory_location = MemoryLocation(addr, size)
                self.state.add_use(memory_location, self._codeloc())
            elif isinstance(addr, SpOffset) and isinstance(addr.offset, int):
                current_defs = self.state.stack_definitions.get_objects_by_offset(addr.offset)
                if current_defs:
                    for current_def in current_defs:
                        # self.state.add_use(current_def, codeloc)
                        data.update(current_def.data)
                    if any(type(d) is Undefined for d in data):
                        l.info('Stack access at offset %#x undefined, ins_addr = %#x.', addr.offset, self.ins_addr)
                else:
                    data.add(undefined)

                self.state.add_use(MemoryLocation(addr, size), self._codeloc())
            else:
                l.debug('Memory address %r undefined or unsupported at pc %#x.', addr, self.ins_addr)

        if len(data) == 0:
            data.add(undefined)

        return DataSet(data, bits)

    def _ail_handle_Convert(self, expr):
        to_conv = self._expr(expr.operand)
        if type(to_conv) is int:
            return to_conv

        r = None
        if expr.from_bits == to_conv.bits and \
                isinstance(to_conv, DataSet):
            if len(to_conv) == 1 and type(next(iter(to_conv.data))) is Undefined:
                # handle Undefined
                r = DataSet(to_conv.data.copy(), expr.to_bits)
            elif all(isinstance(d, (ailment.Expr.Const, int)) for d in to_conv.data):
                # handle consts
                converted = set()
                for d in to_conv.data:
                    if isinstance(d, ailment.Expr.Const):
                        converted.add(ailment.Expr.Const(d.idx, d.variable, d.value, expr.to_bits))
                    else:  # isinstance(d, int)
                        converted.add(d)
                r = DataSet(converted, expr.to_bits)
            else:
                # handle other cases
                converted = set()
                for item in to_conv.data:
                    if isinstance(item, ailment.Expr.Convert):
                        # unpack it
                        item_ = ailment.Expr.Convert(expr.idx, item.from_bits, expr.to_bits, expr.is_signed,
                                                     item.operand)
                    elif isinstance(item, int):
                        # TODO: integer conversion
                        item_ = item
                    elif isinstance(item, Undefined):
                        item_ = item
                    else:
                        item_ = ailment.Expr.Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, item)
                    converted.add(item_)
                r = DataSet(converted, expr.to_bits)

        if r is None:
            r = DataSet(undefined, expr.to_bits)

        return r

    def _ail_handle_ITE(self, expr: ailment.Expr.ITE):
        cond = self._expr(expr.cond)
        iftrue = self._expr(expr.iftrue)
        iffalse = self._expr(expr.iffalse)
        return ailment.Expr.ITE(expr.idx, cond, iffalse, iftrue)

    def _ail_handle_BinaryOp(self, expr):
        r = super()._ail_handle_BinaryOp(expr)
        if isinstance(r, ailment.Expr.BinaryOp):
            return DataSet(undefined, r.bits)
        return r

    def _ail_handle_Cmp(self, expr):
        op0 = self._expr(expr.operands[0])
        op1 = self._expr(expr.operands[1])

        if op0 is None: op0 = expr.operands[0]
        if op1 is None: op1 = expr.operands[1]

        return ailment.Expr.BinaryOp(expr.idx, expr.op, [op0, op1], expr.signed, **expr.tags)

    _ail_handle_CmpEQ = _ail_handle_Cmp
    _ail_handle_CmpNE = _ail_handle_Cmp
    _ail_handle_CmpLE = _ail_handle_Cmp
    _ail_handle_CmpLT = _ail_handle_Cmp
    _ail_handle_CmpGE = _ail_handle_Cmp
    _ail_handle_CmpGT = _ail_handle_Cmp

    def _ail_handle_Const(self, expr):
        return DataSet(expr.value, expr.bits)

    def _ail_handle_StackBaseOffset(self, expr):
        return DataSet(SpOffset(self.arch.bits,
                                expr.offset if expr.offset is not None else 0,
                                is_base=False
                                ),
                       self.arch.bits
                       )

    def _ail_handle_DirtyExpression(self, expr):  # pylint:disable=no-self-use
        return DataSet(undefined, expr.bits // 8)

    #
    # User defined high-level statement handlers
    #

    def _handle_function(self):
        if self._current_local_call_depth > self._maximum_local_call_depth:
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
                is_updated, state = getattr(self._function_handler, handler_name)(self.state, ip_addr,
                                                                                  self._current_local_call_depth + 1,
                                                                                  self._maximum_local_call_depth)
                if is_updated is True:
                    self.state = state
            else:
                l.warning('Please implement the local function handler with your own logic.')
        else:
            l.warning('Could not find function name for external function at address %#x.', ip_addr)
        return None
