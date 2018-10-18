import logging

import ailment

from .atoms import Register, Tmp, MemoryLocation
from .constants import OP_BEFORE, OP_AFTER
from .dataset import DataSet
from .external_codeloc import ExternalCodeLocation
from .undefined import Undefined
from ...engines.light import SimEngineLightAIL, RegisterOffset, SpOffset
from ...errors import SimEngineError

l = logging.getLogger('angr.analyses.reaching_definitions.engine_ail')


class SimEngineRDAIL(SimEngineLightAIL):  # pylint:disable=abstract-method
    def __init__(self, current_local_call_depth, maximum_local_call_depth, function_handler=None):
        super(SimEngineRDAIL, self).__init__()
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

    #
    # AIL statement handlers
    #

    def _ail_handle_Stmt(self, stmt):

        if self.state.analysis:
            self.state.analysis.observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

        super(SimEngineRDAIL, self)._ail_handle_Stmt(stmt)

        if self.state.analysis:
            self.state.analysis.observe(self.ins_addr, stmt, self.block, self.state, OP_AFTER)

    def _ail_handle_Assignment(self, stmt):
        """

        :param ailment.Assignment stmt:
        :return:
        """

        src = self._expr(stmt.src)
        dst = stmt.dst

        if src is None:
            src = DataSet(Undefined(), dst.bits)

        if type(dst) is ailment.Tmp:
            self.state.kill_and_add_definition(Tmp(dst.tmp_idx), self._codeloc(), src)
            self.tmps[dst.tmp_idx] = src

        elif type(dst) is ailment.Register:
            reg = Register(dst.reg_offset, dst.bits // 8)
            self.state.kill_and_add_definition(reg, self._codeloc(), src)

        else:
            l.warning('Unsupported type of Assignment dst %s.', type(dst).__name__)

    def _ail_handle_Store(self, stmt):
        data = self._expr(stmt.data)  # pylint:disable=unused-variable
        addr = self._expr(stmt.addr)  # pylint:disable=unused-variable

    def _ail_handle_Jump(self, stmt):
        target = self._expr(stmt.target)  # pylint:disable=unused-variable

    def _ail_handle_ConditionalJump(self, stmt):

        cond = self._expr(stmt.condition)  # pylint:disable=unused-variable
        true_target = self._expr(stmt.true_target)  # pylint:disable=unused-variable
        false_target = self._expr(stmt.false_target)  # pylint:disable=unused-variable

        ip = Register(self.arch.ip_offset, self.arch.bytes)
        self.state.kill_definitions(ip, self._codeloc(), )

        # kill all cc_ops
        # TODO: make it architecture agnostic
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

        # kill all caller-saved registers
        if stmt.calling_convention is not None and stmt.calling_convention.CALLER_SAVED_REGS:
            for reg_name in stmt.calling_convention.CALLER_SAVED_REGS:
                offset, size = self.arch.registers[reg_name]
                reg = Register(offset, size)
                self.state.kill_definitions(reg, self._codeloc())

        # kill all cc_ops
        # TODO: make it architecture agnostic
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
            return SpOffset(bits, 0)
        elif reg_offset == self.arch.bp_offset:
            return SpOffset(bits, 0, is_base=True)

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
            return RegisterOffset(bits, reg_offset, 0)

    def _ail_handle_Load(self, expr):

        addr = self._expr(expr.addr)
        size = expr.size

        # TODO: Load from memory
        return MemoryLocation(addr, size)

    def _ail_handle_Convert(self, expr):
        return ailment.Expr.Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed,
                                    self._expr(expr.operand))

    def _ail_handle_CmpEQ(self, expr):
        op0 = self._expr(expr.operands[0])
        op1 = self._expr(expr.operands[1])

        return ailment.Expr.BinaryOp(expr.idx, expr.op, [op0, op1], **expr.tags)

    def _ail_handle_CmpLE(self, expr):
        op0 = self._expr(expr.operands[0])
        op1 = self._expr(expr.operands[1])

        return ailment.Expr.BinaryOp(expr.idx, expr.op, [op0, op1], **expr.tags)

    def _ail_handle_Xor(self, expr):
        op0 = self._expr(expr.operands[0])
        op1 = self._expr(expr.operands[1])

        return ailment.Expr.BinaryOp(expr.idx, expr.op, [op0, op1], **expr.tags)

    def _ail_handle_Const(self, expr):
        return DataSet(expr, expr.bits)

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
