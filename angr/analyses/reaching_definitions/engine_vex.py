
import struct
import logging

import pyvex

from ...engines.vex.irop import operations as vex_operations
from ...engines.light import SimEngineLightVEX, SpOffset
from ...errors import SimEngineError
from .atoms import Register, MemoryLocation, Parameter
from .dataset import DataSet
from .external_codeloc import ExternalCodeLocation
from .constants import OP_BEFORE, OP_AFTER

l = logging.getLogger('angr.analyses.reaching_definitions.engine_vex')


class SimEngineRDVEX(SimEngineLightVEX):
    def __init__(self, current_depth, maximum_depth, function_handler=None):
        super(SimEngineRDVEX, self).__init__()
        self._current_depth = current_depth
        self._maximum_depth = maximum_depth
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

    def _external_codeloc(self):
        return ExternalCodeLocation()

    #
    # VEX statement handlers
    #

    def _handle_Stmt(self, stmt):

        if self.state.analysis:
            self.state.analysis.observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

        super(SimEngineRDVEX, self)._handle_Stmt(stmt)

        if self.state.analysis:
            self.state.analysis.observe(self.ins_addr, stmt, self.block, self.state, OP_AFTER)

    # e.g. PUT(rsp) = t2, t2 might include multiple values
    def _handle_Put(self, stmt):
        reg_offset = stmt.offset
        size = stmt.data.result_size(self.tyenv) / 8
        reg = Register(reg_offset, size)
        data = self._expr(stmt.data)

        if DataSet.undefined in data:
            l.info('Data to write into register <%s> with offset %d undefined, ins_addr = %#x.',
                   self.arch.register_names[reg_offset], reg_offset, self.ins_addr)

        self.state.kill_and_add_definition(reg, self._codeloc(), data)

    # e.g. STle(t6) = t21, t6 and/or t21 might include multiple values
    def _handle_Store(self, stmt):

        addr = self._expr(stmt.addr)
        size = stmt.data.result_size(self.tyenv) / 8
        data = self._expr(stmt.data)

        for a in addr:
            if a is DataSet.undefined:
                l.info('Memory address undefined, ins_addr = %#x.', self.ins_addr)
            else:
                if DataSet.undefined in data:
                    l.info('Data to write at address %#x undefined, ins_addr = %#x.', a, self.ins_addr)

                memloc = MemoryLocation(a, size)
                # different addresses are not killed by a subsequent iteration, because kill only removes entries
                # with same index and same size
                self.state.kill_and_add_definition(memloc, self._codeloc(), data)

    def _handle_StoreG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard is True:
            self._handle_Store(stmt)
        elif guard is False:
            pass
        else:
            # FIXME: implement both
            l.info('Could not resolve guard %s for StoreG.', str(guard))

    # CAUTION: experimental
    def _handle_LoadG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard is True:
            # FIXME: full conversion support
            if stmt.cvt.find('Ident') < 0:
                l.warning('Unsupported conversion %s in LoadG.', stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, load_expr)
            self._handle_WrTmp(wr_tmp_stmt)
        elif guard is False:
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
        pass

    def _handle_IMark(self, stmt):
        pass

    def _handle_AbiHint(self, stmt):
        pass

    #
    # VEX expression handlers
    #

    def _handle_RdTmp(self, expr):
        tmp = expr.tmp

        if tmp in self.tmps:
            return self.tmps[tmp]
        return DataSet(DataSet.undefined, expr.result_size(self.tyenv))

    # e.g. t0 = GET:I64(rsp), rsp might be defined multiple times
    def _handle_Get(self, expr):

        reg_offset = expr.offset
        size = expr.result_size(self.tyenv)

        # FIXME: size, overlapping
        data = set()
        current_defs = self.state.register_definitions.get_objects_by_offset(reg_offset)
        for current_def in current_defs:
            data.update(current_def.data)
        if len(data) == 0:
            data.add(DataSet.undefined)
        if DataSet.undefined in data:
            l.info('Data in register <%s> with offset %d undefined, ins_addr = %#x.',
                   self.arch.register_names[reg_offset], reg_offset, self.ins_addr)

        self.state.add_use(Register(reg_offset, size), self._codeloc())

        return DataSet(data, expr.result_size(self.tyenv))

    # e.g. t27 = LDle:I64(t9), t9 might include multiple values
    def _handle_Load(self, expr):
        addr = self._expr(expr.addr)
        size = expr.result_size(self.tyenv) / 8

        data = set()
        for a in addr:
            if a is not DataSet.undefined:
                current_defs = self.state.memory_definitions.get_objects_by_offset(a)
                if current_defs:
                    for current_def in current_defs:
                        data.update(current_def.data)
                    if DataSet.undefined in data:
                        l.info('Memory at address %#x undefined, ins_addr = %#x.', a, self.ins_addr)
                else:
                    mem = self.state.loader.memory.read_bytes(a, size)
                    if mem:
                        if self.arch.memory_endness == 'Iend_LE':
                            fmt = "<"
                        else:
                            fmt = ">"

                        if size == 8:
                            fmt += "Q"
                        elif size == 4:
                            fmt += "I"

                        if size in [4, 8] and size == len(mem):
                            mem_str = ''.join(mem)
                            data.add(struct.unpack(fmt, mem_str)[0])

                # FIXME: _add_memory_use() iterates over the same loop
                self.state.add_use(MemoryLocation(a, size), self._codeloc())
            else:
                l.info('Memory address undefined, ins_addr = %#x.', self.ins_addr)

        if len(data) == 0:
            data.add(DataSet.undefined)

        return DataSet(data, expr.result_size(self.tyenv))

    # CAUTION: experimental
    def _handle_ITE(self, expr):
        cond = self._expr(expr.cond)

        if cond is True:
            return self._expr(expr.iftrue)
        elif cond is False:
            return self._expr(expr.iffalse)
        else:
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
            if a is DataSet.undefined:
                pass
            elif isinstance(a, (int, long)):
                mask = 2 ** bits - 1
                a &= mask
            elif type(a) is Parameter:
                if type(a.value) is Register:
                    a.value.size = bits / 8
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
            if isinstance(e0, (int, long)):
                return e0 != 1

        l.warning('Comparison of multiple values / different types.')
        return DataSet({True, False}, expr.result_size(self.tyenv))

    #
    # Binary operation handlers
    #

    def _handle_Sar(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        size = expr.result_size(self.tyenv)
        data = set()
        for e0 in expr_0:
            for e1 in expr_1:
                try:
                    if e0 >> (size - 1) == 0:
                        head = 0
                    else:
                        head = ((1 << e1) - 1) << (size - e1)
                    data.add(head | (e0 >> e1))
                except (ValueError, TypeError) as e:
                    l.warning(e)
                    data.add(DataSet.undefined)

        return DataSet(data, expr.result_size(self.tyenv))

    def _handle_CmpEQ(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if len(expr_0) == 1 and len(expr_1) == 1:
            e0 = expr_0.get_first_element()
            e1 = expr_1.get_first_element()
            if isinstance(e0, (int, long)) and isinstance(e1, (int, long)):
                return e0 == e1

        l.warning('Comparison of multiple values / different types.')
        return DataSet({True, False}, expr.result_size(self.tyenv))

    def _handle_CmpNE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if len(expr_0) == 1 and len(expr_1) == 1:
            e0 = expr_0.get_first_element()
            e1 = expr_1.get_first_element()
            if isinstance(e0, (int, long)) and isinstance(e1, (int, long)):
                return e0 != e1

        l.warning('Comparison of multiple values / different types.')
        return DataSet({True, False}, expr.result_size(self.tyenv))

    def _handle_CmpLT(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if len(expr_0) == 1 and len(expr_1) == 1:
            e0 = expr_0.get_first_element()
            e1 = expr_1.get_first_element()
            if isinstance(e0, (int, long)) and isinstance(e1, (int, long)):
                return e0 < e1

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
            if isinstance(e0, (int, long)) and isinstance(e1, (int, long)):
                if e0 < e1:
                    return DataSet(0x08, expr.result_size(self.tyenv))
                elif e0 > e1:
                    return DataSet(0x04, expr.result_size(self.tyenv))
                else:
                    return DataSet(0x02, expr.result_size(self.tyenv))

        l.warning('Comparison of multiple values / different types.')
        return DataSet({True, False}, expr.result_size(self.tyenv))

    def _handle_CCall(self, expr):
        return DataSet(DataSet.undefined, expr.result_size(self.tyenv))

    #
    # User defined high level statement handlers
    #

    def _handle_function(self):
        if self._current_depth > self._maximum_depth:
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
        if not isinstance(ip_addr, (int, long)):
            l.error('Invalid type %s for IP.' % type(ip_addr).__name__)
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
                                                                                  self._current_depth + 1,
                                                                                  self._maximum_depth)
                if is_updated is True:
                    self.state = state
            else:
                l.warning('Please implement the local function handler with your own logic.')
        else:
            l.warning('Could not find function name for external function at address %#x.', ip_addr)
        return None
