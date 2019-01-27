import logging

import ailment

from .atoms import Register, Tmp, MemoryLocation
from .constants import OP_BEFORE, OP_AFTER
from .dataset import DataSet
from .external_codeloc import ExternalCodeLocation
from .undefined import Undefined
from ...engines.light import SimEngineLightAIL, RegisterOffset, SpOffset
from ...errors import SimEngineError

l = logging.getLogger(name=__name__)


class SimEngineRDAIL(SimEngineLightAIL):  # pylint:disable=abstract-method
    def __init__(self, project, current_local_call_depth, maximum_local_call_depth, function_handler=None):
        super(SimEngineRDAIL, self).__init__()
        self.project = project
        self._current_local_call_depth = current_local_call_depth
        self._maximum_local_call_depth = maximum_local_call_depth
        self._function_handler = function_handler

    def process(self, state, *args, **kwargs):
        # we are using a completely different state. Therefore, we directly call our _process() method before
        # SimEngine becomes flexible enough.
        try:
            self._process(state, None, block=kwargs.pop('block', None))
        except SimEngineError as e:
            if kwargs.pop('fail_fast', False) is True:
                raise e
        return self.state

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

    def _ail_handle_Stmt(self, stmt):

        if self.state.analysis:
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

        super(SimEngineRDAIL, self)._ail_handle_Stmt(stmt)

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
            src = DataSet(Undefined(dst.bits), dst.bits)

        if type(dst) is ailment.Tmp:
            self.state.kill_and_add_definition(Tmp(dst.tmp_idx), self._codeloc(), src)
            self.tmps[dst.tmp_idx] = src

        elif type(dst) is ailment.Register:
            reg = Register(dst.reg_offset, dst.bits // 8)
            self.state.kill_and_add_definition(reg, self._codeloc(), src)

            if dst.reg_offset == self.arch.sp_offset:
                # TODO: Special logic that frees all definitions above the current stack pointer
                pass

        else:
            l.warning('Unsupported type of Assignment dst %s.', type(dst).__name__)

    def _ail_handle_Store(self, stmt):
        data = self._expr(stmt.data)
        addr = self._expr(stmt.addr)
        size = stmt.size

        for a in addr:
            if type(a) is Undefined:
                l.info('Memory address undefined, ins_addr = %#x.', self.ins_addr)
            else:
                if any(type(d) is Undefined for d in data):
                    l.info('Data to write at address %#x undefined, ins_addr = %#x.', a, self.ins_addr)

                if type(a) is SpOffset:
                    # Writing to stack
                    memloc = a
                else:
                    # Writing to a non-stack memory region
                    memloc = MemoryLocation(a, size)

                if not memloc.symbolic:
                    # different addresses are not killed by a subsequent iteration, because kill only removes entries
                    # with same index and same size
                    self.state.kill_and_add_definition(memloc, self._codeloc(), data)

    def _ail_handle_Jump(self, stmt):
        target = self._expr(stmt.target)  # pylint:disable=unused-variable

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

        # if arguments exist, use them
        if stmt.args:
            for arg in stmt.args:
                self._expr(arg)

        # When stmt.args are available, used registers/stack variables are decided by stmt.args. Otherwise we fall-back
        # to using all caller-saved registers.
        if stmt.args is not None:
            used_vars = stmt.args
        else:
            used_vars = None

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
        if used_vars is None:
            used_vars = [ var for var in killed_vars if var.reg_offset != return_reg_offset ]
        for var in used_vars:
            self.state.add_use(var, self._codeloc())

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

    #
    # AIL expression handlers
    #

    def _ail_handle_Tmp(self, expr):

        if self.state._track_tmps:
            self.state.add_use(Tmp(expr.tmp_idx), self._codeloc())

        return super(SimEngineRDAIL, self)._ail_handle_Tmp(expr)

    def _ail_handle_Register(self, expr):

        reg_offset = expr.reg_offset
        bits = expr.bits

        self.state.add_use(Register(reg_offset, bits // 8), self._codeloc())

        if reg_offset == self.arch.sp_offset:
            return DataSet(SpOffset(bits, 0), bits)
        elif reg_offset == self.arch.bp_offset:
            return DataSet(SpOffset(bits, 0, is_base=True), bits)

        try:
            data = DataSet(set(), bits)
            defs = self.state.register_definitions.get_objects_by_offset(reg_offset)
            if not defs:
                # define it right away as an external dependency
                self.state.kill_and_add_definition(Register(reg_offset, bits // 8), self._external_codeloc(),
                                                   data=expr
                                                   )
                defs = self.state.register_definitions.get_objects_by_offset(reg_offset)
                assert defs
            for def_ in defs:
                if def_.data is not None:
                    data.update(def_.data)
                else:
                    l.warning('Data in register <%s> is undefined at %#x.',
                              self.arch.register_names[reg_offset], self.ins_addr
                              )
            return data
        except KeyError:
            return DataSet(RegisterOffset(bits, reg_offset, 0), bits)

    def _ail_handle_Load(self, expr):

        addrs = self._expr(expr.addr)
        size = expr.size
        bits = expr.bits

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
                        data.add(self.state.loader.memory.unpack_word(addr, size=size))
                    except KeyError:
                        pass

                # FIXME: _add_memory_use() iterates over the same loop
                self.state.add_use(MemoryLocation(addr, size), self._codeloc())
            elif isinstance(addr, SpOffset):
                current_defs = self.state.stack_definitions.get_objects_by_offset(addr.offset)
                if current_defs:
                    for current_def in current_defs:
                        data.update(current_def.data)
                    if any(type(d) is Undefined for d in data):
                        l.info('Stack access at offset %#x undefined, ins_addr = %#x.', addr.offset, self.ins_addr)
                else:
                    data.add(Undefined(bits))

                self.state.add_use(addr, self._codeloc())
            else:
                l.info('Memory address undefined, ins_addr = %#x.', self.ins_addr)

        if len(data) == 0:
            data.add(Undefined(bits))

        return DataSet(data, bits)

    def _ail_handle_Convert(self, expr):
        r = super()._ail_handle_Convert(expr)
        if r is None:
            to_conv = self._expr(expr.operand)
            if expr.from_bits == to_conv.bits and \
                    isinstance(to_conv, DataSet):
                if len(to_conv) == 1 and type(next(iter(to_conv.data))) is Undefined:
                    r = DataSet(to_conv.data.copy(), expr.to_bits)
                elif all(isinstance(d, (ailment.Expr.Const, int)) for d in to_conv.data):
                    converted = set()
                    for d in to_conv.data:
                        if isinstance(d, ailment.Expr.Const):
                            converted.add(ailment.Expr.Const(d.idx, d.variable, d.value, expr.to_bits))
                        else:  # isinstance(d, int)
                            converted.add(d)
                    r = DataSet(converted, expr.to_bits)

            if r is None:
                r = ailment.Expr.Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed,
                                         self._expr(expr.operand))
                r = DataSet(r, expr.to_bits)
        return r

    def _ail_handle_BinaryOp(self, expr):
        r = super()._ail_handle_BinaryOp(expr)
        if isinstance(r, ailment.Expr.BinaryOp):
            # Repack it with DataSet
            return DataSet({r}, r.bits)
        return r

    def _ail_handle_CmpEQ(self, expr):
        op0 = self._expr(expr.operands[0])
        op1 = self._expr(expr.operands[1])

        if op0 is None: op0 = expr.operands[0]
        if op1 is None: op1 = expr.operands[1]

        return ailment.Expr.BinaryOp(expr.idx, expr.op, [op0, op1], **expr.tags)

    def _ail_handle_CmpLE(self, expr):
        op0 = self._expr(expr.operands[0])
        op1 = self._expr(expr.operands[1])

        if op0 is None: op0 = expr.operands[0]
        if op1 is None: op1 = expr.operands[1]

        return ailment.Expr.BinaryOp(expr.idx, expr.op, [op0, op1], **expr.tags)

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
        return expr

    #
    # User defined high level statement handlers
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
        if self.state.loader.main_object.contains_addr(ip_addr) is True:
            ext_func_name = self.state.loader.find_plt_stub_name(ip_addr)
            if ext_func_name is None:
                is_internal = True
        else:
            symbol = self.state.loader.find_symbol(ip_addr)
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
