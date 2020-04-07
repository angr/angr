import logging

import pyvex

from .atoms import Register, MemoryLocation, Parameter, Tmp
from .constants import OP_BEFORE, OP_AFTER
from .dataset import DataSet
from .external_codeloc import ExternalCodeLocation
from .undefined import Undefined, undefined
from ...engines.light import SimEngineLight, SimEngineLightVEXMixin, SpOffset
from angr.engines.vex.claripy.irop import operations as vex_operations
from ...errors import SimEngineError

l = logging.getLogger(name=__name__)


class SimEngineRDVEX(
    SimEngineLightVEXMixin,
    SimEngineLight,
):  # pylint:disable=abstract-method
    def __init__(self, project, current_local_call_depth, maximum_local_call_depth, function_handler=None):
        super(SimEngineRDVEX, self).__init__()
        self.project = project
        self._current_local_call_depth = current_local_call_depth
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
            l.error(e)
        return self.state, self._visited_blocks

    #
    # Private methods
    #

    @staticmethod
    def _external_codeloc():
        return ExternalCodeLocation()

    #
    # VEX statement handlers
    #

    def _handle_Stmt(self, stmt):

        if self.state.analysis:
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

        super(SimEngineRDVEX, self)._handle_Stmt(stmt)

        if self.state.analysis:
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_AFTER)

    def _handle_WrTmp(self, stmt):
        super()._handle_WrTmp(stmt)
        self.state.kill_and_add_definition(Tmp(stmt.tmp), self._codeloc(), self.tmps[stmt.tmp])

    def _handle_WrTmpData(self, tmp, data):
        super()._handle_WrTmpData(tmp, data)
        self.state.kill_and_add_definition(Tmp(tmp), self._codeloc(), self.tmps[tmp])

    # e.g. PUT(rsp) = t2, t2 might include multiple values
    def _handle_Put(self, stmt):
        reg_offset = stmt.offset
        size = stmt.data.result_size(self.tyenv) // 8
        reg = Register(reg_offset, size)
        data = self._expr(stmt.data)

        if any(type(d) is Undefined for d in data):
            l.info('Data to write into register <%s> with offset %d undefined, ins_addr = %#x.',
                   self.arch.register_names[reg_offset], reg_offset, self.ins_addr)

        self.state.kill_and_add_definition(reg, self._codeloc(), data)

    # e.g. STle(t6) = t21, t6 and/or t21 might include multiple values
    # sync with _handle_StoreG()
    def _handle_Store(self, stmt):

        addr = self._expr(stmt.addr)
        size = stmt.data.result_size(self.tyenv) // 8
        data = self._expr(stmt.data)

        for a in addr:
            if type(a) is Undefined:
                l.info('Memory address undefined, ins_addr = %#x.', self.ins_addr)
            else:
                if any(type(d) is Undefined for d in data):
                    l.info('Data to write at address %#x undefined, ins_addr = %#x.', a, self.ins_addr)

                memloc = MemoryLocation(a, size)
                # different addresses are not killed by a subsequent iteration, because kill only removes entries
                # with same index and same size
                self.state.kill_and_add_definition(memloc, self._codeloc(), data)

    # sync with _handle_Store()
    def _handle_StoreG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard.data == {True}:
            self._handle_Store(stmt)
        elif guard.data == {False}:
            pass
        else:
            # guard.data == {True, False}
            addr = self._expr(stmt.addr)
            size = stmt.data.result_size(self.tyenv) // 8

            # get current data
            load_end = stmt.end
            load_ty = self.tyenv.lookup(stmt.data.tmp)
            load_addr = stmt.addr
            load_expr = pyvex.IRExpr.Load(load_end, load_ty, load_addr)
            data_old = self._handle_Load(load_expr)

            # get new data
            data_new = self._expr(stmt.data)

            # merge old and new data
            data_new.update(data_old)

            for a in addr:
                if type(a) is Undefined:
                    l.info('Memory address undefined, ins_addr = %#x.', self.ins_addr)
                else:
                    if any(type(d) is Undefined for d in data_new):
                        l.info('Data to write at address %#x undefined, ins_addr = %#x.', a, self.ins_addr)

                    memloc = MemoryLocation(a, size)
                    # different addresses are not killed by a subsequent iteration, because kill only removes entries
                    # with same index and same size
                    self.state.kill_and_add_definition(memloc, self._codeloc(), data_new)

    def _handle_LoadG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard.data == {True}:
            # FIXME: full conversion support
            if stmt.cvt.find('Ident') < 0:
                l.warning('Unsupported conversion %s in LoadG.', stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, load_expr)
            self._handle_WrTmp(wr_tmp_stmt)
        elif guard.data == {False}:
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, stmt.alt)
            self._handle_WrTmp(wr_tmp_stmt)
        else:
            if stmt.cvt.find('Ident') < 0:
                l.warning('Unsupported conversion %s in LoadG.', stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)
            data = set()
            data.update(self._expr(load_expr).data)
            data.update(self._expr(stmt.alt).data)
            self._handle_WrTmpData(stmt.dst, DataSet(data, load_expr.result_size(self.tyenv)))

    def _handle_Exit(self, stmt):
        guard = self._expr(stmt.guard)
        target = stmt.dst.value
        self.state.mark_guard(self._codeloc(), guard, target)

    def _handle_IMark(self, stmt):
        pass

    def _handle_AbiHint(self, stmt):
        pass

    #
    # VEX expression handlers
    #

    def _expr(self, expr):
        data = super()._expr(expr)
        if data is None:
            bits = expr.result_size(self.tyenv)
            data = DataSet(undefined, bits)
        return data

    def _handle_RdTmp(self, expr):
        tmp = expr.tmp

        self.state.add_use(Tmp(tmp), self._codeloc())

        if tmp in self.tmps:
            return self.tmps[tmp]
        return None

    # e.g. t0 = GET:I64(rsp), rsp might be defined multiple times
    def _handle_Get(self, expr):

        reg_offset = expr.offset
        bits = expr.result_size(self.tyenv)
        size = bits // self.arch.byte_width

        # FIXME: size, overlapping
        data = set()
        current_defs = self.state.register_definitions.get_objects_by_offset(reg_offset)
        for current_def in current_defs:
            data.update(current_def.data)
        if len(data) == 0:
            # no defs can be found. add a fake definition
            data.add(undefined)
            self.state.kill_and_add_definition(Register(reg_offset, size), self._external_codeloc(), DataSet(data, bits))
        if any(type(d) is Undefined for d in data):
            l.info('Data in register <%s> with offset %d undefined, ins_addr = %#x.',
                   self.arch.register_names[reg_offset], reg_offset, self.ins_addr)

        self.state.add_use(Register(reg_offset, size), self._codeloc())

        return DataSet(data, expr.result_size(self.tyenv))

    # e.g. t27 = LDle:I64(t9), t9 might include multiple values
    # caution: Is also called from StoreG
    def _handle_Load(self, expr):
        addr = self._expr(expr.addr)
        bits = expr.result_size(self.tyenv)
        size = bits // self.arch.byte_width

        data = set()
        for a in addr:
            if isinstance(a, int):
                current_defs = self.state.memory_definitions.get_objects_by_offset(a)
                if current_defs:
                    for current_def in current_defs:
                        data.update(current_def.data)
                    if any(type(d) is Undefined for d in data):
                        l.info('Memory at address %#x undefined, ins_addr = %#x.', a, self.ins_addr)
                else:
                    try:
                        data.add(self.project.loader.memory.unpack_word(a, size=size))
                    except KeyError:
                        pass

                # FIXME: _add_memory_use() iterates over the same loop
                self.state.add_use(MemoryLocation(a, size), self._codeloc())
            else:
                l.info('Memory address undefined, ins_addr = %#x.', self.ins_addr)

        if len(data) == 0:
            data.add(undefined)

        return DataSet(data, bits)

    # CAUTION: experimental
    def _handle_ITE(self, expr):
        cond = self._expr(expr.cond)

        if cond.data == {True}:
            return self._expr(expr.iftrue)
        elif cond.data == {False}:
            return self._expr(expr.iffalse)
        else:
            if cond.data != {True, False}:
                l.info('Could not resolve condition %s for ITE.', str(cond))
            data = set()
            data.update(self._expr(expr.iftrue).data)
            data.update(self._expr(expr.iffalse).data)
            return DataSet(data, expr.result_size(self.tyenv))

    #
    # Unary operation handlers
    #

    def _handle_Const(self, expr):
        return DataSet(expr.con.value, expr.result_size(self.tyenv))

    def _handle_Conversion(self, expr):
        simop = vex_operations[expr.op]
        arg_0 = self._expr(expr.args[0])

        bits = int(simop.op_attrs['to_size'])
        data = set()
        # convert operand if possible otherwise keep it unchanged
        for a in arg_0:
            if type(a) is Undefined:
                pass
            elif isinstance(a, int):
                mask = 2 ** bits - 1
                a &= mask
            elif type(a) is Parameter:
                if type(a.value) is Register:
                    a.value.size = bits // 8
                elif type(a.value) is SpOffset:
                    a.value.bits = bits
                else:
                    l.warning('Unsupported type Parameter->%s for conversion.', type(a.value).__name__)
            else:
                l.warning('Unsupported type %s for conversion.', type(a).__name__)
            data.add(a)

        return DataSet(data, expr.result_size(self.tyenv))

    def _handle_Not1(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)

        if len(expr_0) == 1:
            e0 = expr_0.get_first_element()
            if isinstance(e0, int):
                return DataSet(e0 != 1, expr.result_size(self.tyenv))

        l.warning('Comparison of multiple values / different types.')
        return DataSet({True, False}, expr.result_size(self.tyenv))

    def _handle_Not(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)

        if len(expr_0) == 1:
            e0 = expr_0.get_first_element()
            if isinstance(e0, int):
                return DataSet(e0 == 0, expr.result_size(self.tyenv))

        l.warning('Comparison of multiple values / different types.')
        return DataSet({True, False}, expr.result_size(self.tyenv))

    #
    # Binary operation handlers
    #

    def _handle_Sar(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        bits = expr.result_size(self.tyenv)
        data = set()
        for e0 in expr_0:
            for e1 in expr_1:
                try:
                    if e0 >> (bits - 1) == 0:
                        head = 0
                    else:
                        head = ((1 << e1) - 1) << (bits - e1)
                    data.add(head | (e0 >> e1))
                except (ValueError, TypeError) as e:
                    data.add(undefined)
                    l.warning(e)

        return DataSet(data, expr.result_size(self.tyenv))

    def _handle_CmpEQ(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if len(expr_0) == 1 and len(expr_1) == 1:
            e0 = expr_0.get_first_element()
            e1 = expr_1.get_first_element()
            if isinstance(e0, int) and isinstance(e1, int):
                return DataSet(e0 == e1, expr.result_size(self.tyenv))

        l.warning('Comparison of multiple values / different types.')
        return DataSet({True, False}, expr.result_size(self.tyenv))

    def _handle_CmpNE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if len(expr_0) == 1 and len(expr_1) == 1:
            e0 = expr_0.get_first_element()
            e1 = expr_1.get_first_element()
            if isinstance(e0, int) and isinstance(e1, int):
                return DataSet(e0 != e1, expr.result_size(self.tyenv))

        l.warning('Comparison of multiple values / different types.')
        return DataSet({True, False}, expr.result_size(self.tyenv))

    def _handle_CmpLT(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if len(expr_0) == 1 and len(expr_1) == 1:
            e0 = expr_0.get_first_element()
            e1 = expr_1.get_first_element()
            if isinstance(e0, int) and isinstance(e1, int):
                return DataSet(e0 < e1, expr.result_size(self.tyenv))

        l.warning('Comparison of multiple values / different types.')
        return DataSet({True, False}, expr.result_size(self.tyenv))

    # ppc only
    def _handle_CmpORD(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if len(expr_0) == 1 and len(expr_1) == 1:
            e0 = expr_0.get_first_element()
            e1 = expr_1.get_first_element()
            if isinstance(e0, int) and isinstance(e1, int):
                if e0 < e1:
                    return DataSet(0x08, expr.result_size(self.tyenv))
                elif e0 > e1:
                    return DataSet(0x04, expr.result_size(self.tyenv))
                else:
                    return DataSet(0x02, expr.result_size(self.tyenv))

        l.warning('Comparison of multiple values / different types.')
        return DataSet({True, False}, expr.result_size(self.tyenv))

    def _handle_CCall(self, expr):
        bits = expr.result_size(self.tyenv)
        for arg_expr in expr.args:
            self._expr(arg_expr)
        return DataSet(undefined, bits)

    #
    # User defined high level statement handlers
    #

    def _handle_function(self, *args, **kwargs):  # pylint:disable=unused-argument
        if self._current_local_call_depth > self._maximum_local_call_depth:
            l.warning('The analysis reached its maximum recursion depth.')
            return None

        defs_ip = self.state.register_definitions.get_objects_by_offset(self.arch.ip_offset)
        if len(defs_ip) != 1:
            l.error('Invalid definition(s) for IP.')
            return None

        ip_data = next(iter(defs_ip)).data
        if len(ip_data) != 1:
            handler_name = 'handle_indirect_call'
            if hasattr(self._function_handler, handler_name):
                _, state = getattr(self._function_handler, handler_name)(self.state, self._codeloc())
                self.state = state
            else:
                l.warning('Please implement the indirect function handler with your own logic.')
            return None

        ip_addr = ip_data.get_first_element()
        if not isinstance(ip_addr, int):
            l.warning('Invalid type %s for IP.', type(ip_addr).__name__)
            handler_name = 'handle_unknown_call'
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(self.state, self._codeloc())
                self.state = state
            else:
                l.warning('Please implement the unknown function handler with your own logic.')
            return None

        ext_func_name = None
        if self.project.loader.main_object.contains_addr(ip_addr):
            ext_func_name = self.project.loader.find_plt_stub_name(ip_addr)
        else:
            symbol = self.project.loader.find_symbol(ip_addr)
            if symbol is not None:
                ext_func_name = symbol.name
        is_internal = ext_func_name is None

        executed_rda = False
        if ext_func_name is not None:
            handler_name = 'handle_%s' % ext_func_name
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(self.state, self._codeloc())
                self.state = state
            else:
                l.warning('Please implement the external function handler for %s() with your own logic.', ext_func_name)
                handler_name = 'handle_external_function_fallback'
                if hasattr(self._function_handler, handler_name):
                    executed_rda, state = getattr(self._function_handler, handler_name)(self.state, self._codeloc())
                    self.state = state
        elif is_internal is True:
            handler_name = 'handle_local_function'
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(self.state,
                                                                                    ip_addr,
                                                                                    self._current_local_call_depth + 1,
                                                                                    self._maximum_local_call_depth,
                                                                                    self._codeloc(),
                                                                                    )
                self.state = state
            else:
                l.warning('Please implement the local function handler with your own logic.')
        else:
            l.warning('Could not find function name for external function at address %#x.', ip_addr)
            handler_name = 'handle_unknown_call'
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(self.state, self._codeloc())
                self.state = state
            else:
                l.warning('Please implement the unknown function handler with your own logic.')

        # pop return address if necessary
        if executed_rda is False and self.arch.call_pushes_ret is True:
            defs_sp = self.state.register_definitions.get_objects_by_offset(self.arch.sp_offset)
            if len(defs_sp) == 0:
                raise ValueError('No definition for SP found')
            if len(defs_sp) == 1:
                sp_data = next(iter(defs_sp)).data.data
            else:  # len(defs_sp) > 1
                sp_data = set()
                for d in defs_sp:
                    sp_data.update(d.data)

            if len(sp_data) != 1:
                raise ValueError('Invalid number of values for stack pointer.')

            sp_addr = next(iter(sp_data))
            if isinstance(sp_addr, int):
                sp_addr -= self.arch.stack_change
            elif isinstance(sp_addr, Undefined):
                pass
            else:
                raise TypeError('Invalid type %s for stack pointer.' % type(sp_addr).__name__)

            atom = Register(self.arch.sp_offset, self.arch.bytes)
            self.state.kill_and_add_definition(atom, self._codeloc(), DataSet(sp_addr, self.arch.bits))

        return None
