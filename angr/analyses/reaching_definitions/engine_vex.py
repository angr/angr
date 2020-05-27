from typing import Optional, Iterable, Set, Union, TYPE_CHECKING
import logging

import pyvex

from ...engines.light import SimEngineLight, SimEngineLightVEXMixin, SpOffset, RegisterOffset
from ...engines.vex.claripy.irop import operations as vex_operations
from ...errors import SimEngineError
from ...calling_conventions import DEFAULT_CC, SimRegArg, SimStackArg
from ...knowledge_plugins.key_definitions.definition import Definition
from ...knowledge_plugins.key_definitions.atoms import Register, MemoryLocation, Parameter, Tmp
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from ...knowledge_plugins.key_definitions.dataset import DataSet
from ...knowledge_plugins.key_definitions.undefined import Undefined, undefined
from .rd_state import ReachingDefinitionsState
from .external_codeloc import ExternalCodeLocation

if TYPE_CHECKING:
    from ...calling_conventions import SimCC
    from ...knowledge_plugins import FunctionManager


l = logging.getLogger(name=__name__)


class SimEngineRDVEX(
    SimEngineLightVEXMixin,
    SimEngineLight,
):  # pylint:disable=abstract-method
    def __init__(self, project, current_local_call_depth, maximum_local_call_depth, functions=None,
                 function_handler=None):
        super(SimEngineRDVEX, self).__init__()
        self.project = project
        self.functions: Optional['FunctionManager'] = functions
        self._current_local_call_depth = current_local_call_depth
        self._maximum_local_call_depth = maximum_local_call_depth
        self._function_handler = function_handler
        self._visited_blocks = None
        self._dep_graph = None

        self.state: ReachingDefinitionsState

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

    def _handle_WrTmp(self, stmt: pyvex.IRStmt.WrTmp):
        super()._handle_WrTmp(stmt)
        self.state.kill_and_add_definition(Tmp(stmt.tmp, self.tyenv.sizeof(stmt.tmp) // 8),
                                           self._codeloc(),
                                           self.tmps[stmt.tmp])

    def _handle_WrTmpData(self, tmp: int, data):
        super()._handle_WrTmpData(tmp, data)
        self.state.kill_and_add_definition(Tmp(tmp, self.tyenv.sizeof(tmp)),
                                           self._codeloc(),
                                           self.tmps[tmp])

    # e.g. PUT(rsp) = t2, t2 might include multiple values
    def _handle_Put(self, stmt):
        reg_offset: int = stmt.offset
        size: int = stmt.data.result_size(self.tyenv) // 8
        reg = Register(reg_offset, size)
        data = self._expr(stmt.data)

        if any(type(d) is Undefined for d in data):
            l.info('Data to write into register <%s> with offset %d undefined, ins_addr = %#x.',
                   self.arch.register_names[reg_offset], reg_offset, self.ins_addr)

        # special handling for references to stack variables
        for d in data:
            if isinstance(d, SpOffset) and isinstance(d.offset, int):
                self.state.add_use(MemoryLocation(d, 1), self._codeloc())

        self.state.kill_and_add_definition(reg, self._codeloc(), data)

    # e.g. STle(t6) = t21, t6 and/or t21 might include multiple values
    def _handle_Store(self, stmt):
        addr = self._expr(stmt.addr)
        size = stmt.data.result_size(self.tyenv) // 8
        data = self._expr(stmt.data)

        self._store_core(addr, size, data)

    def _handle_StoreG(self, stmt: pyvex.IRStmt.StoreG):
        guard = self._expr(stmt.guard)
        if guard.data == {True}:
            addr = self._expr(stmt.addr)
            size = stmt.data.result_size(self.tyenv) // 8
            data = self._expr(stmt.data)

            self._store_core(addr, size, data)
        elif guard.data == {False}:
            pass
        else:
            # guard.data == {True, False}
            # get current data
            addr = self._expr(stmt.addr)
            size = stmt.data.result_size(self.tyenv) // 8
            data_old = self._load_core(addr, size, stmt.endness)
            data = self._expr(stmt.data)

            self._store_core(addr, size, data, data_old=data_old)

    def _store_core(self, addr: Iterable[Union[int,SpOffset,Undefined]], size: int, data, data_old=None):
        if data_old:
            data.update(data_old)

        for a in addr:
            if type(a) is Undefined:
                l.info('Memory address undefined, ins_addr = %#x.', self.ins_addr)
            else:
                if any(type(d) is Undefined for d in data):
                    l.info('Data to write at address %#x undefined, ins_addr = %#x.', a, self.ins_addr)

                if isinstance(a, int) or (isinstance(a, SpOffset) and isinstance(a.offset, int)):
                    memloc = MemoryLocation(a, size)
                    # different addresses are not killed by a subsequent iteration, because kill only removes entries
                    # with same index and same size
                    self.state.kill_and_add_definition(memloc, self._codeloc(), data)

    def _handle_LoadG(self, stmt):
        guard: DataSet = self._expr(stmt.guard)
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

    def _handle_LLSC(self, stmt: pyvex.IRStmt.LLSC):
        if stmt.storedata is None:
            # load-link
            addr = self._expr(stmt.addr)
            size = self.tyenv.sizeof(stmt.result) // self.arch.byte_width
            load_result = self._load_core(addr, size, stmt.endness)
            self.tmps[stmt.result] = load_result
            self.state.kill_and_add_definition(Tmp(stmt.result, self.tyenv.sizeof(stmt.result) // self.arch.byte_width),
                                               self._codeloc(),
                                               load_result)
        else:
            # store-conditional
            storedata = self._expr(stmt.storedata)
            addr = self._expr(stmt.addr)
            size = self.tyenv.sizeof(stmt.storedata.tmp) // self.arch.byte_width

            self._store_core(addr, size, storedata)
            self.tmps[stmt.result] = DataSet({1}, 1)
            self.state.kill_and_add_definition(Tmp(stmt.result, self.tyenv.sizeof(stmt.result) // self.arch.byte_width),
                                               self._codeloc(),
                                               self.tmps[stmt.result])

    #
    # VEX expression handlers
    #

    def _expr(self, expr) -> DataSet:
        data = super()._expr(expr)
        if data is None:
            bits = expr.result_size(self.tyenv)
            data = DataSet(undefined, bits)
        return data

    def _handle_RdTmp(self, expr: pyvex.IRExpr.RdTmp) -> Optional[DataSet]:
        tmp: int = expr.tmp

        self.state.add_use(Tmp(tmp, expr.result_size(self.tyenv) // self.arch.byte_width), self._codeloc())

        if tmp in self.tmps:
            return self.tmps[tmp]
        return None

    # e.g. t0 = GET:I64(rsp), rsp might be defined multiple times
    def _handle_Get(self, expr: pyvex.IRExpr.Get) -> Optional[DataSet]:

        reg_offset: int = expr.offset
        bits: int = expr.result_size(self.tyenv)
        size: int = bits // self.arch.byte_width

        # FIXME: size, overlapping
        data: Set[Union[Undefined,RegisterOffset,int]] = set()
        current_defs: Iterable[Definition] = self.state.register_definitions.get_objects_by_offset(reg_offset)
        for current_def in current_defs:
            data.update(current_def.data)
        if len(data) == 0:
            # no defs can be found. add a fake definition
            data.add(undefined)
            self.state.kill_and_add_definition(Register(reg_offset, size), self._external_codeloc(),
                                               DataSet(data, bits))
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

        return self._load_core(addr, size, expr.endness)

    def _load_core(self, addr: Iterable[Union[int,SpOffset]], size: int, endness: str):  # pylint:disable=unused-argument

        current_defs: Iterable[Definition]

        data = set()
        for a in addr:
            if isinstance(a, int):
                # Load data from a global region
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
                memory_location = MemoryLocation(a, size)
                self.state.add_use(memory_location, self._codeloc())
            elif isinstance(a, SpOffset) and isinstance(a.offset, int):
                # Load data from a local variable
                current_defs = self.state.stack_definitions.get_objects_by_offset(a.offset)
                if current_defs:
                    for def_ in current_defs:
                        data.update(def_.data)
                else:
                    data.add(undefined)
                memory_location = MemoryLocation(a, size)
                self.state.add_use(memory_location, self._codeloc())
            else:
                l.info('Memory address undefined, ins_addr = %#x.', self.ins_addr)

        if len(data) == 0:
            data.add(undefined)

        return DataSet(data, size * self.arch.byte_width)

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

        # l.warning('Comparison of multiple values / different types.')
        return DataSet({True, False}, expr.result_size(self.tyenv))

    def _handle_Not(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)

        if len(expr_0) == 1:
            e0 = expr_0.get_first_element()
            if isinstance(e0, int):
                return DataSet(e0 == 0, expr.result_size(self.tyenv))

        # l.warning('Comparison of multiple values / different types.')
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

        # l.warning('Comparison of multiple values / different types.')
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

        # l.warning('Comparison of multiple values / different types.')
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

        # l.warning('Comparison of multiple values / different types.')
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

        # l.warning('Comparison of multiple values / different types.')
        return DataSet({True, False}, expr.result_size(self.tyenv))

    def _handle_CCall(self, expr):
        bits = expr.result_size(self.tyenv)
        for arg_expr in expr.args:
            self._expr(arg_expr)
        return DataSet(undefined, bits)

    #
    # User defined high level statement handlers
    #

    def _handle_function(self, func_addr: Optional[DataSet], **kwargs):
        skip_cc = self._handle_function_core(func_addr, **kwargs)
        if not skip_cc:
            self._handle_function_cc(func_addr)

    def _handle_function_core(self, func_addr: Optional[DataSet], **kwargs) -> bool:  # pylint:disable=unused-argument

        if self._current_local_call_depth > self._maximum_local_call_depth:
            l.warning('The analysis reached its maximum recursion depth.')
            return False

        if func_addr is None:
            l.warning('Invalid type %s for IP.', type(func_addr).__name__)
            handler_name = 'handle_unknown_call'
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(self.state, self._codeloc())
                state: ReachingDefinitionsState
                self.state = state
            else:
                l.warning('Please implement the unknown function handler with your own logic.')
            return False

        if len(func_addr) != 1:
            # indirect call
            handler_name = 'handle_indirect_call'
            if hasattr(self._function_handler, handler_name):
                _, state = getattr(self._function_handler, handler_name)(self.state, self._codeloc())
                self.state = state
            else:
                l.warning('Please implement the indirect function handler with your own logic.')
            return False

        func_addr_int = func_addr.get_first_element()
        if not isinstance(func_addr_int, int):
            l.warning('Invalid type %s for IP.', type(func_addr_int).__name__)
            handler_name = 'handle_unknown_call'
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(self.state, self._codeloc())
                state: ReachingDefinitionsState
                self.state = state
            else:
                l.warning('Please implement the unknown function handler with your own logic.')
            return False

        # direct calls
        ext_func_name = None
        if self.project.loader.main_object.contains_addr(func_addr_int):
            ext_func_name = self.project.loader.find_plt_stub_name(func_addr_int)
        else:
            symbol = self.project.loader.find_symbol(func_addr_int)
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
                l.warning('Please implement the external function handler for %s() with your own logic.',
                          ext_func_name)
                handler_name = 'handle_external_function_fallback'
                if hasattr(self._function_handler, handler_name):
                    executed_rda, state = getattr(self._function_handler, handler_name)(self.state, self._codeloc())
                    self.state = state
        elif is_internal is True:
            handler_name = 'handle_local_function'
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(
                    self.state,
                    func_addr_int,
                    self._current_local_call_depth + 1,
                    self._maximum_local_call_depth,
                    self._codeloc(),
                )
                self.state = state
            else:
                # l.warning('Please implement the local function handler with your own logic.')
                pass
        else:
            l.warning('Could not find function name for external function at address %#x.', func_addr_int)
            handler_name = 'handle_unknown_call'
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(self.state, self._codeloc())
                self.state = state
            else:
                l.warning('Please implement the unknown function handler with your own logic.')
        skip_cc = executed_rda

        return skip_cc

    def _handle_function_cc(self, func_addr: Optional[DataSet]):  # pylint:disable=unused-argument

        cc: Optional['SimCC'] = None
        if func_addr is not None and len(func_addr) == 1 and self.functions is not None:
            func_addr_int = next(iter(func_addr))
            if self.functions.contains_addr(func_addr_int):
                cc = self.functions[func_addr_int].calling_convention

        if cc is None:
            cc = DEFAULT_CC.get(self.arch.name, None)(self.arch)

        if cc is not None:
            # follow the calling convention and:
            # - add uses for arguments
            # - kill return value registers
            # - caller-saving registers
            if cc.args:
                code_loc = self._codeloc()
                for arg in cc.args:
                    if isinstance(arg, SimRegArg):
                        reg_offset, reg_size = self.arch.registers[arg.reg_name]
                        self.state.add_use(Register(reg_offset, reg_size), code_loc)
                    elif isinstance(arg, SimStackArg):
                        self.state.add_use(MemoryLocation(SpOffset(self.arch.bits,
                                                                   arg.stack_offset),
                                                          arg.size * self.arch.byte_width),
                                           code_loc)
            if cc.RETURN_VAL is not None:
                if isinstance(cc.RETURN_VAL, SimRegArg):
                    reg_offset, reg_size = self.arch.registers[cc.RETURN_VAL.reg_name]
                    atom = Register(reg_offset, reg_size)
                    self.state.kill_and_add_definition(atom, self._codeloc(), DataSet({undefined}, reg_size * 8))
            if cc.CALLER_SAVED_REGS is not None:
                for reg in cc.CALLER_SAVED_REGS:
                    reg_offset, reg_size = self.arch.registers[reg]
                    atom = Register(reg_offset, reg_size)
                    self.state.kill_and_add_definition(atom, self._codeloc(), DataSet({undefined}, reg_size * 8))

        if self.arch.call_pushes_ret is True:
            # pop return address if necessary
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
            if isinstance(sp_addr, (int, SpOffset)):
                sp_addr -= self.arch.stack_change
            elif isinstance(sp_addr, Undefined):
                pass
            else:
                raise TypeError('Invalid type %s for stack pointer.' % type(sp_addr).__name__)

            atom = Register(self.arch.sp_offset, self.arch.bytes)
            self.state.kill_and_add_definition(atom, self._codeloc(), DataSet(sp_addr, self.arch.bits))
