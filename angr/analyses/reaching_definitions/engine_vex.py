from itertools import chain
from typing import Optional, Iterable, Set, Union, TYPE_CHECKING
import logging

import pyvex
import claripy
from cle import Symbol

from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ...engines.light import SimEngineLight, SimEngineLightVEXMixin, SpOffset
from ...engines.vex.claripy.datalayer import value as claripy_value
from ...engines.vex.claripy.irop import operations as vex_operations
from ...errors import SimEngineError, SimMemoryMissingError
from ...calling_conventions import DEFAULT_CC, SimRegArg, SimStackArg, SimCC, SimStructArg, SimArrayArg
from ...utils.constants import DEFAULT_STATEMENT
from ...knowledge_plugins.key_definitions.definition import Definition
from ...knowledge_plugins.key_definitions.tag import LocalVariableTag, ParameterTag, ReturnValueTag, Tag
from ...knowledge_plugins.key_definitions.atoms import Atom, Register, MemoryLocation, Tmp
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from ...knowledge_plugins.key_definitions.heap_address import HeapAddress
from ...knowledge_plugins.key_definitions.undefined import Undefined
from ...code_location import CodeLocation
from .rd_state import ReachingDefinitionsState
from .external_codeloc import ExternalCodeLocation

if TYPE_CHECKING:
    from ...knowledge_plugins import FunctionManager
    from .function_handler import FunctionHandler


l = logging.getLogger(name=__name__)


class SimEngineRDVEX(
    SimEngineLightVEXMixin,
    SimEngineLight,
):  # pylint:disable=abstract-method
    """
    Implements the VEX execution engine for reaching definition analysis.
    """

    def __init__(self, project, call_stack, maximum_local_call_depth, functions=None,
                 function_handler=None):
        super().__init__()
        self.project = project
        self._call_stack = call_stack
        self._maximum_local_call_depth = maximum_local_call_depth
        self.functions: Optional['FunctionManager'] = functions
        self._function_handler: Optional["FunctionHandler"] = function_handler
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
        return self.state, self._visited_blocks, self._dep_graph

    def _process_block_end(self):
        self.stmt_idx = DEFAULT_STATEMENT
        if self.block.vex.jumpkind == "Ijk_Call":
            # it has to be a function
            addr = self._expr(self.block.vex.next)
            self._handle_function(addr)
        elif self.block.vex.jumpkind == "Ijk_Boring":
            # test if the target addr is a function or not
            addr = self._expr(self.block.vex.next)
            addr_v = addr.one_value()
            if addr_v is not None and addr_v.concrete:
                addr_int = addr_v._model_concrete.value
                if addr_int in self.functions:
                    # yes it's a jump to a function
                    self._handle_function(addr)

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

        super()._handle_Stmt(stmt)

        if self.state.analysis:
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_AFTER)

    def _handle_WrTmp(self, stmt: pyvex.IRStmt.WrTmp):

        data: MultiValues = self._expr(stmt.data)

        tmp_atom = Tmp(stmt.tmp, self.tyenv.sizeof(stmt.tmp) // self.arch.byte_width)
        # if len(data.values) == 1 and 0 in data.values:
        #     data_v = data.one_value()
        #     if data_v is not None:
        #         # annotate data with its definition
        #         data = MultiValues(offset_to_values={
        #             0: {self.state.annotate_with_def(data_v, Definition(tmp_atom, self._codeloc()))
        #                 }
        #         })
        self.tmps[stmt.tmp] = data

        self.state.kill_and_add_definition(tmp_atom,
                                           self._codeloc(),
                                           data,
                                           )

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

        # special handling for references to heap or stack variables
        if len(data.values) == 1:
            for d in next(iter(data.values.values())):
                if self.state.is_heap_address(d):
                    heap_offset = self.state.get_heap_offset(d)
                    if heap_offset is not None:
                        self.state.add_use(MemoryLocation(HeapAddress(heap_offset), 1), self._codeloc())
                elif self.state.is_stack_address(d):
                    stack_offset = self.state.get_stack_offset(d)
                    if stack_offset is not None:
                        self.state.add_use(MemoryLocation(SpOffset(self.arch.bits, stack_offset), 1), self._codeloc())

        self.state.kill_and_add_definition(reg, self._codeloc(), data)

    # e.g. STle(t6) = t21, t6 and/or t21 might include multiple values
    def _handle_Store(self, stmt):
        addr = self._expr(stmt.addr)
        size = stmt.data.result_size(self.tyenv) // 8
        data = self._expr(stmt.data)

        if len(addr.values) == 1:
            addrs = next(iter(addr.values.values()))
            self._store_core(addrs, size, data, endness=stmt.endness)

    def _handle_StoreG(self, stmt: pyvex.IRStmt.StoreG):
        guard = self._expr(stmt.guard)
        guard_v = guard.one_value()

        if claripy.is_true(guard_v):
            addr = self._expr(stmt.addr)
            if len(addr.values) == 1:
                addrs = next(iter(addr.values.values()))
                size = stmt.data.result_size(self.tyenv) // 8
                data = self._expr(stmt.data)
                self._store_core(addrs, size, data)
        elif claripy.is_false(guard_v):
            pass
        else:
            # guard.data == {True, False}
            # get current data
            addr = self._expr(stmt.addr)
            if len(addr.values) == 1:
                addrs = next(iter(addr.values.values()))
                size = stmt.data.result_size(self.tyenv) // 8
                data_old = self._load_core(addrs, size, stmt.endness)
                data = self._expr(stmt.data)

                self._store_core(addrs, size, data, data_old=data_old)

    def _store_core(self, addr: Iterable[Union[int,HeapAddress,SpOffset]], size: int, data: MultiValues,
                    data_old: Optional[MultiValues]=None, endness=None):
        if data_old is not None:
            data = data.merge(data_old)

        for a in addr:
            if self.state.is_top(a):
                l.debug('Memory address undefined, ins_addr = %#x.', self.ins_addr)
            else:
                tags: Optional[Set[Tag]]
                if isinstance(a, int):
                    atom = MemoryLocation(a, size)
                    tags = None
                elif self.state.is_stack_address(a):
                    atom = MemoryLocation(SpOffset(self.arch.bits, self.state.get_stack_offset(a)), size)
                    function_address = None  # we cannot get the function address in the middle of a store if a CFG
                                             # does not exist. you should backpatch the function address later using
                                             # the 'ins_addr' metadata entry.
                    tags = {LocalVariableTag(
                        function=function_address,
                        metadata={'tagged_by': 'SimEngineRDVEX._store_core',
                                  'ins_addr': self.ins_addr}
                    )}

                elif self.state.is_heap_address(a):
                    atom = MemoryLocation(HeapAddress(self.state.get_heap_offset(a)), size)
                    tags = None

                else:
                    continue

                # different addresses are not killed by a subsequent iteration, because kill only removes entries
                # with same index and same size
                self.state.kill_and_add_definition(atom, self._codeloc(), data, tags=tags, endness=endness)

    def _handle_LoadG(self, stmt):
        guard = self._expr(stmt.guard)
        guard_v = guard.one_value()

        if claripy.is_true(guard_v):
            # FIXME: full conversion support
            if stmt.cvt.find('Ident') < 0:
                l.warning('Unsupported conversion %s in LoadG.', stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, load_expr)
            self._handle_WrTmp(wr_tmp_stmt)
        elif claripy.is_false(guard_v):
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, stmt.alt)
            self._handle_WrTmp(wr_tmp_stmt)
        else:
            if stmt.cvt.find('Ident') < 0:
                l.warning('Unsupported conversion %s in LoadG.', stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)

            load_expr_v = self._expr(load_expr)
            alt_v = self._expr(stmt.alt)

            data = load_expr_v.merge(alt_v)
            self._handle_WrTmpData(stmt.dst, data)

    def _handle_Exit(self, stmt):
        _ = self._expr(stmt.guard)
        target = stmt.dst.value
        self.state.mark_guard(self._codeloc(), target)

    def _handle_IMark(self, stmt):
        pass

    def _handle_AbiHint(self, stmt):
        pass

    def _handle_LLSC(self, stmt: pyvex.IRStmt.LLSC):
        if stmt.storedata is None:
            # load-link
            addr = self._expr(stmt.addr)
            if len(addr.values) == 1:
                addrs = next(iter(addr.values.values()))
                size = self.tyenv.sizeof(stmt.result) // self.arch.byte_width
                load_result = self._load_core(addrs, size, stmt.endness)
                self.tmps[stmt.result] = load_result
                self.state.kill_and_add_definition(Tmp(stmt.result,
                                                       self.tyenv.sizeof(stmt.result) // self.arch.byte_width),
                                                   self._codeloc(),
                                                   load_result)
        else:
            # store-conditional
            storedata = self._expr(stmt.storedata)
            addr = self._expr(stmt.addr)
            if len(addr.values) == 1:
                addrs = next(iter(addr.values.values()))
                size = self.tyenv.sizeof(stmt.storedata.tmp) // self.arch.byte_width

                self._store_core(addrs, size, storedata)
                self.tmps[stmt.result] = MultiValues(offset_to_values={0: {claripy.BVV(1, 1)}})
                self.state.kill_and_add_definition(Tmp(stmt.result,
                                                       self.tyenv.sizeof(stmt.result) // self.arch.byte_width),
                                                   self._codeloc(),
                                                   self.tmps[stmt.result])

    #
    # VEX expression handlers
    #

    def _expr(self, expr) -> MultiValues:
        data = super()._expr(expr)
        if data is None:
            bits = expr.result_size(self.tyenv)
            top = self.state.top(bits)
            data = MultiValues(offset_to_values={0: {top}})
        return data

    def _handle_RdTmp(self, expr: pyvex.IRExpr.RdTmp) -> Optional[MultiValues]:
        tmp: int = expr.tmp

        self.state.add_use(Tmp(tmp, expr.result_size(self.tyenv) // self.arch.byte_width), self._codeloc())

        if tmp in self.tmps:
            return self.tmps[tmp]
        return None

    # e.g. t0 = GET:I64(rsp), rsp might be defined multiple times
    def _handle_Get(self, expr: pyvex.IRExpr.Get) -> MultiValues:

        reg_offset: int = expr.offset
        bits: int = expr.result_size(self.tyenv)
        size: int = bits // self.arch.byte_width

        reg_atom = Register(reg_offset, size)
        try:
            values: MultiValues = self.state.register_definitions.load(reg_offset, size=size)
        except SimMemoryMissingError:
            top = self.state.top(size * self.arch.byte_width)
            # annotate it
            top = self.state.annotate_with_def(top, Definition(reg_atom, ExternalCodeLocation()))
            values = MultiValues({0: {top}})
            # write it to registers
            self.state.kill_and_add_definition(reg_atom, self._external_codeloc(), values)

        current_defs: Optional[Iterable[Definition]] = None
        for vs in values.values.values():
            for v in vs:
                if current_defs is None:
                    current_defs = self.state.extract_defs(v)
                else:
                    current_defs = chain(current_defs, self.state.extract_defs(v))

        if current_defs is None:
            # no defs can be found. add a fake definition
            self.state.kill_and_add_definition(reg_atom, self._external_codeloc(), values)

        self.state.add_use(reg_atom, self._codeloc())

        return values

    # e.g. t27 = LDle:I64(t9), t9 might include multiple values
    # caution: Is also called from StoreG
    def _handle_Load(self, expr) -> MultiValues:
        addr = self._expr(expr.addr)
        bits = expr.result_size(self.tyenv)
        size = bits // self.arch.byte_width

        # convert addr from MultiValues to a list of valid addresses
        if len(addr.values) == 1:
            addrs = next(iter(addr.values.values()))
            return self._load_core(addrs, size, expr.endness)

        top = self.state.top(bits)
        # annotate it
        dummy_atom = MemoryLocation(0, size)
        top = self.state.annotate_with_def(top, Definition(dummy_atom, ExternalCodeLocation()))
        # add use
        self.state.add_use(dummy_atom, self._codeloc())
        return MultiValues(offset_to_values={0: {top}})

    def _load_core(self, addrs: Iterable[claripy.ast.Base], size: int, endness: str) -> MultiValues:

        result: Optional[MultiValues] = None
        for addr in addrs:
            if self.state.is_top(addr):
                l.debug('Memory address undefined, ins_addr = %#x.', self.ins_addr)
            elif self.state.is_stack_address(addr):
                # Load data from a local variable
                stack_offset = self.state.get_stack_offset(addr)
                if stack_offset is not None:
                    stack_addr = self.state.live_definitions.stack_offset_to_stack_addr(stack_offset)
                    try:
                        vs: MultiValues = self.state.stack_definitions.load(stack_addr, size=size, endness=endness)
                    except SimMemoryMissingError:
                        continue

                    memory_location = MemoryLocation(SpOffset(self.arch.bits, stack_offset), size, endness=endness)
                    self.state.add_use(memory_location, self._codeloc())
                    result = result.merge(vs) if result is not None else vs

            elif self.state.is_heap_address(addr):
                # Load data from the heap
                heap_offset = self.state.get_heap_offset(addr)
                vs: MultiValues = self.state.heap_definitions.load(heap_offset, size=size, endness=endness)
                memory_location = MemoryLocation(HeapAddress(heap_offset), size, endness=endness)
                self.state.add_use(memory_location, self._codeloc())
                result = result.merge(vs) if result is not None else vs

            else:

                addr_v = addr._model_concrete.value

                # Load data from a global region
                try:
                    vs: MultiValues = self.state.memory_definitions.load(addr_v, size=size, endness=endness)
                except SimMemoryMissingError:
                    # try to load it from the static memory backer
                    # TODO: Is this still required?
                    try:
                        vs = MultiValues(offset_to_values={0: {
                            claripy.BVV(
                                self.project.loader.memory.unpack_word(addr_v, size=size),
                                size * self.arch.byte_width
                            )}})
                    except KeyError:
                        continue

                result = result.merge(vs) if result is not None else vs

                # FIXME: _add_memory_use() iterates over the same loop
                memory_location = MemoryLocation(addr_v, size, endness=endness)
                self.state.add_use(memory_location, self._codeloc())

        if result is None:
            result = MultiValues(offset_to_values={0: {self.state.top(size * self.arch.byte_width)}})

        return result

    # CAUTION: experimental
    def _handle_ITE(self, expr: pyvex.IRExpr.ITE):
        cond = self._expr(expr.cond)
        cond_v = cond.one_value()
        iftrue = self._expr(expr.iftrue)
        iffalse = self._expr(expr.iffalse)

        if claripy.is_true(cond_v):
            return iftrue
        elif claripy.is_false(cond_v):
            return iffalse
        else:
            data = iftrue.merge(iffalse)
            return data

    #
    # Unary operation handlers
    #

    def _handle_Const(self, expr) -> MultiValues:
        return MultiValues(offset_to_values={0: { claripy_value(expr.con.type, expr.con.value) }})

    def _handle_Conversion(self, expr):
        simop = vex_operations[expr.op]
        bits = int(simop.op_attrs['to_size'])
        arg_0 = self._expr(expr.args[0])

        # if there are multiple values with only one offset, we apply conversion to each one of them
        # otherwise, we return a TOP

        if len(arg_0.values) == 1:
            # extension, extract, or doing nothing
            data = set()
            for v in next(iter(arg_0.values.values())):
                if bits > v.size():
                    data.add(v.zero_extend(bits - v.size()))
                else:
                    if isinstance(v, claripy.ast.fp.FP):
                        data.add(v.val_to_bv(bits))
                    else:
                        data.add(v[bits - 1:0])
            r = MultiValues(offset_to_values={next(iter(arg_0.values.keys())): data})

        else:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _handle_Not1(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)

        e0 = expr_0.one_value()

        if e0 is not None and not e0.symbolic:
            return MultiValues(offset_to_values={0: {
                    claripy.BVV(1, 1) if e0._model_concrete.value != 1 else claripy.BVV(0, 1)
                }})

        return MultiValues(offset_to_values={0: {self.state.top(1)}})

    def _handle_Not(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)
        bits = expr.result_size(self.tyenv)

        e0 = expr_0.one_value()

        if e0 is not None and not e0.symbolic:
            return MultiValues(offset_to_values={0: {~e0}})  # pylint:disable=invalid-unary-operand-type

        return MultiValues(offset_to_values={0: {self.state.top(bits)}})

    def _handle_Clz(self, expr):
        arg0 = expr.args[0]
        _ = self._expr(arg0)
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        return MultiValues(offset_to_values={0: {self.state.top(bits)}})

    def _handle_Ctz(self, expr):
        arg0 = expr.args[0]
        _ = self._expr(arg0)
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        return MultiValues(offset_to_values={0: {self.state.top(bits)}})

    #
    # Binary operation handlers
    #
    def _handle_ExpCmpNE64(self, expr):
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        return r

    def _handle_16HLto32(self, expr):
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        return r

    def _handle_Add(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support addition between two real multivalues
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # adding a single value to a multivalue
            if len(expr0.values) == 1 and 0 in expr0.values:

                vs = {v.sign_extend(expr1_v.size() - v.size()) + expr1_v for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # adding a single value to a multivalue
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {v.sign_extend(expr0_v.size() - v.size()) + expr0_v for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # adding two single values together
            r = MultiValues(offset_to_values={0: {expr0_v + expr1_v}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _handle_Sub(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support addition between two real multivalues
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
            # subtracting a single value from another single value
            r = MultiValues(offset_to_values={0: {expr0_v - expr1_v}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _handle_Mul(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support multiplication between two real multivalues
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # multiplying a single value to a multivalue
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {v * expr1_v for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # multiplying a single value to a multivalue
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {v * expr0_v for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # multiplying two single values together
            r = MultiValues(offset_to_values={0: {expr0_v * expr1_v}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _handle_Mull(self, expr):
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)
        return MultiValues(offset_to_values={0: {self.state.top(bits)}})

    def _handle_Div(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support division between two real multivalues
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {v / expr1_v for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {v / expr0_v for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                # dividing two single values
                if expr1_v._model_concrete.value == 0:
                    r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
                else:
                    r = MultiValues(offset_to_values={0: {expr0_v / expr1_v}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _handle_DivMod(self, expr):
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _handle_And(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support addition between two real multivalues
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # bitwise-and a single value with a multivalue
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {v & expr1_v for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # bitwise-and a single value to a multivalue
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {v & expr0_v for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                # bitwise-and two single values together
                r = MultiValues(offset_to_values={0: {expr0_v & expr1_v}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _handle_Xor(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support xor between two real multivalues
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # bitwise-xor a single value with a multivalue
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {v.sign_extend(expr1_v.size() - v.size()) ^ expr1_v for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # bitwise-xor a single value to a multivalue
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {v.sign_extend(expr0_v.size() - v.size()) ^ expr0_v for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                # bitwise-xor two single values together
                r = MultiValues(offset_to_values={0: {expr0_v ^ expr1_v}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r


    def _handle_Or(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support or between two real multivalues
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # bitwise-or a single value with a multivalue
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = {v | expr1_v for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # bitwise-or a single value to a multivalue
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {v | expr0_v for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # bitwise-and two single values together
            r = MultiValues(offset_to_values={0: {expr0_v | expr1_v}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _handle_Sar(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        def _shift_sar(e0, e1):
            # convert e1 to an integer to prevent claripy from complaining "args' lengths must all be equal"
            if e1.symbolic:
                return self.state.top(bits)
            e1 = e1._model_concrete.value

            if claripy.is_true(e0 >> (bits - 1) == 0):
                head = claripy.BVV(0, bits)
            else:
                head = ((1 << e1) - 1) << (bits - e1)
            return head | (e0 >> e1)

        if expr0_v is None and expr1_v is None:
            # we do not support shifting between two real multivalues
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # shifting a single value by a multivalue
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = { _shift_sar(v, expr1_v) for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # shifting a multivalue by a single value
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {_shift_sar(expr0_v, v) for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # subtracting a single value from another single value
            r = MultiValues(offset_to_values={0: {_shift_sar(expr0_v, expr1_v)}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _handle_Shr(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        def _shift_shr(e0, e1):
            if e1.symbolic:
                return self.state.top(bits)
            if e1.size() < e0.size():
                e1 = e1.sign_extend(e0.size()-e1.size())
            else:
                e0 = e0.sign_extend(e1.size()-e0.size())

            return claripy.LShR(e0, e1)

        if expr0_v is None and expr1_v is None:
            # we do not support shifting between two real multivalues
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # shifting a single value by a multivalue
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = { _shift_shr(v, expr1_v) for v in expr0.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # shifting a multivalue by a single value
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = {_shift_shr(expr0_v, v) for v in expr1.values[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # shifting a single value from another single value
            r = MultiValues(offset_to_values={0: {_shift_shr(expr0_v, expr1_v)}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _handle_Shl(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        def _shift_shl(e0, e1):
            # convert e1 to an integer to prevent claripy from complaining "args' lengths must all be equal"
            if e1.symbolic:
                return self.state.top(bits)
            e1 = e1._model_concrete.value
            return e0 << e1

        if expr0_v is None and expr1_v is None:
            # we do not support shifting between two real multivalues
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        elif expr0_v is None and expr1_v is not None:
            # shifting left a single value by a multivalue
            if len(expr0.values) == 1 and 0 in expr0.values:
                vs = { _shift_shl(v, expr1_v) for v in expr0.values[0] }
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # shifting left a multivalue by a single value
            if len(expr1.values) == 1 and 0 in expr1.values:
                vs = { _shift_shl(expr0_v, v) for v in expr1.values[0] }
                r = MultiValues(offset_to_values={0: vs})
        else:
            # subtracting a single value from another single value
            r = MultiValues(offset_to_values={0: {_shift_shl(expr0_v, expr1_v)}})

        if r is None:
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        return r

    def _handle_CmpEQ(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()

        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return MultiValues(offset_to_values={0: {
                    claripy.BVV(1, 1) if e0._model_concrete.value == e1._model_concrete.value else claripy.BVV(0, 1)
                }})
            elif e0 is e1:
                return MultiValues(offset_to_values={0: {claripy.BVV(1, 1)}})
            return MultiValues(offset_to_values={0: { self.state.top(1) }})

        return MultiValues(offset_to_values={0: { self.state.top(1) }})

    def _handle_CmpNE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return MultiValues(offset_to_values={0: {
                    claripy.BVV(1, 1) if e0._model_concrete.value != e1._model_concrete.value else claripy.BVV(0, 1)
                }})
            elif e0 is e1:
                return MultiValues(offset_to_values={0: {claripy.BVV(0, 1)}})
        return MultiValues(offset_to_values={0: { self.state.top(1) }})

    def _handle_CmpLT(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return MultiValues(offset_to_values={0: {
                    claripy.BVV(1, 1) if e0._model_concrete.value < e1._model_concrete.value else claripy.BVV(0, 1)
                }})
            elif e0 is e1:
                return MultiValues(offset_to_values={0: {claripy.BVV(0, 1)}})
        return MultiValues(offset_to_values={0: { self.state.top(1) }})

    def _handle_CmpLE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return MultiValues(offset_to_values={0: {
                    claripy.BVV(1, 1) if e0._model_concrete.value <= e1._model_concrete.value else claripy.BVV(0, 1)
                }})
            elif e0 is e1:
                return MultiValues(offset_to_values={0: {claripy.BVV(0, 1)}})
        return MultiValues(offset_to_values={0: {self.state.top(1)}})

    # ppc only
    def _handle_CmpORD(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        bits = expr.result_size(self.tyenv)

        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                if e0 < e1:
                    return MultiValues(offset_to_values={0: {claripy.BVV(0x8, bits)}})
                elif e0 > e1:
                    return MultiValues(offset_to_values={0: {claripy.BVV(0x4, bits)}})
                else:
                    return MultiValues(offset_to_values={0: {claripy.BVV(0x2, bits)}})
            elif e0 is e1:
                return MultiValues(offset_to_values={0: {claripy.BVV(0x2, bits)}})

        return MultiValues(offset_to_values={0: { self.state.top(1) }})

    def _handle_CCall(self, expr):
        bits = expr.result_size(self.tyenv)
        for arg_expr in expr.args:
            self._expr(arg_expr)
        return MultiValues(offset_to_values={0: { self.state.top(bits) }})

    #
    # User defined high level statement handlers
    #

    def _handle_function(self, func_addr: Optional[MultiValues], **kwargs):
        skip_cc = self._handle_function_core(func_addr, **kwargs)
        if not skip_cc:
            self._handle_function_cc(func_addr)

    def _handle_function_core(self, func_addr: Optional[MultiValues], **kwargs) -> bool:  # pylint:disable=unused-argument

        if self._call_stack is not None and len(self._call_stack) + 1 > self._maximum_local_call_depth:
            l.warning('The analysis reached its maximum recursion depth.')
            return False

        if func_addr is None:
            l.warning('Invalid type %s for IP.', type(func_addr).__name__)
            _, state = self._function_handler.handle_unknown_call(
                self.state,
                src_codeloc=self._codeloc(),
            )
            self.state = state
            return False

        func_addr_v = func_addr.one_value()
        if func_addr_v is None or self.state.is_top(func_addr_v):
            # probably an indirect call
            _, state = self._function_handler.handle_indirect_call(self.state, src_codeloc=self._codeloc())
            self.state = state
            return False

        if not func_addr_v.concrete:
            try:
                executed_rda, state = self._function_handler.handle_unknown_call(self.state,
                                                                                    src_codeloc=self._codeloc())
                state: ReachingDefinitionsState
                self.state = state
            except NotImplementedError:
                l.warning('Please implement the unknown function handler with your own logic.')
            return False

        func_addr_int: int = func_addr_v._model_concrete.value

        # direct calls
        symbol: Optional[Symbol] = None
        if not self.project.loader.main_object.contains_addr(func_addr_int):
            is_internal = False
            symbol = self.project.loader.find_symbol(func_addr_int)
        else:
            is_internal = True

        executed_rda = False
        if symbol is not None:
            codeloc = CodeLocation(func_addr_int, 0, None, func_addr_int, context=self._context)
            executed_rda, state = self._function_handler.handle_external_function_symbol(self.state, symbol=symbol, src_codeloc=codeloc)
            self.state = state

        elif is_internal is True:
            codeloc = CodeLocation(func_addr_int, 0, None, func_addr_int, context=self._context)
            executed_rda, state, visited_blocks, dep_graph = self._function_handler.handle_local_function(
                self.state,
                func_addr_int,
                self._call_stack,
                self._maximum_local_call_depth,
                self._visited_blocks,
                self._dep_graph,
                src_ins_addr=self.ins_addr,
                codeloc=codeloc,
            )
            if executed_rda:
                # update everything
                self.state = state
                self._visited_blocks = visited_blocks
                self._dep_graph = dep_graph

        else:
            l.error('Could not find symbol for external function at address %#x.', func_addr_int)
            executed_rda, state = self._function_handler.handle_unknown_call(self.state,
                                                                                src_codeloc=self._codeloc())
            self.state = state
        skip_cc = executed_rda

        return skip_cc

    def _handle_function_cc(self, func_addr: Optional[MultiValues]):
        _cc = None
        proto = None
        func_addr_int: Optional[Union[int,Undefined]] = None
        if func_addr is not None and self.functions is not None:
            func_addr_v = func_addr.one_value()
            if func_addr_v is not None and not self.state.is_top(func_addr_v):
                func_addr_int = func_addr_v._model_concrete.value
                if self.functions.contains_addr(func_addr_int):
                    _cc = self.functions[func_addr_int].calling_convention
                    proto = self.functions[func_addr_int].prototype

        cc: SimCC = _cc or DEFAULT_CC.get(self.arch.name, None)(self.arch)

        # follow the calling convention and:
        # - add uses for arguments
        # - kill return value registers
        # - caller-saving registers
        atom: Atom
        if proto and proto.args:
            code_loc = self._codeloc()
            for arg in cc.arg_locs(proto):
                if isinstance(arg, SimRegArg):
                    reg_offset, reg_size = self.arch.registers[arg.reg_name]
                    atom = Register(reg_offset, reg_size)
                    self.state.add_use(atom, code_loc)
                    self._tag_definitions_of_atom(atom, func_addr_int)
                elif isinstance(arg, SimStackArg):
                    atom = MemoryLocation(SpOffset(self.arch.bits,
                                          arg.stack_offset),
                                          arg.size * self.arch.byte_width)
                    self.state.add_use(atom, code_loc)
                    self._tag_definitions_of_atom(atom, func_addr_int)
                elif isinstance(arg, SimStructArg):
                    min_stack_offset = None
                    for subargfield, subargloc in arg.locs.items():
                        if not isinstance(subargloc, SimStackArg):
                            raise TypeError(f"Unexpected: Field {subargfield} in {arg} is not a stack location.")
                        if min_stack_offset is None:
                            min_stack_offset = subargloc.stack_offset
                        elif min_stack_offset > subargloc.stack_offset:
                            min_stack_offset = subargloc.stack_offset

                    if min_stack_offset is not None:
                        atom = MemoryLocation(SpOffset(self.arch.bits,
                                              min_stack_offset),
                                              arg.size * self.arch.byte_width)
                        self.state.add_use(atom, code_loc)
                        self._tag_definitions_of_atom(atom, func_addr_int)
                elif isinstance(arg, SimArrayArg):
                    min_stack_offset = None
                    max_stack_loc = None
                    for subargloc in arg.locs:
                        if isinstance(subargloc, SimRegArg):
                            atom = Register(subargloc.reg_offset, subargloc.size)
                            self.state.add_use(atom, code_loc)
                            self._tag_definitions_of_atom(atom, func_addr_int)
                        elif isinstance(subargloc, SimStackArg):
                            if min_stack_offset is None:
                                min_stack_offset = subargloc.stack_offset
                            elif min_stack_offset > subargloc.stack_offset:
                                min_stack_offset = subargloc.stack_offset
                            if max_stack_loc is None:
                                max_stack_loc = subargloc.stack_offset + subargloc.size
                            elif max_stack_loc < subargloc.stack_offset + subargloc.size:
                                max_stack_loc = subargloc.stack_offset + subargloc.size
                        else:
                            raise TypeError("Unsupported argument type %s" % type(subargloc))

                    if min_stack_offset is not None:
                        atom = MemoryLocation(SpOffset(self.arch.bits,
                                              min_stack_offset),
                                              max_stack_loc - min_stack_offset)
                        self.state.add_use(atom, code_loc)
                        self._tag_definitions_of_atom(atom, func_addr_int)
                else:
                    raise TypeError("Unsupported argument type %s" % type(arg))


        if cc.RETURN_VAL is not None:
            if isinstance(cc.RETURN_VAL, SimRegArg):
                reg_offset, reg_size = self.arch.registers[cc.RETURN_VAL.reg_name]
                atom = Register(reg_offset, reg_size)
                tag = ReturnValueTag(
                    function = func_addr_int if isinstance(func_addr_int, int) else None,
                    metadata = {'tagged_by': 'SimEngineRDVEX._handle_function_cc'}
                )
                self.state.kill_and_add_definition(
                    atom,
                    self._codeloc(),
                    MultiValues(offset_to_values={0: {self.state.top(reg_size * self.arch.byte_width)}}),
                    tags={tag},
                )

        if cc.CALLER_SAVED_REGS is not None:
            for reg in cc.CALLER_SAVED_REGS:
                reg_offset, reg_size = self.arch.registers[reg]
                atom = Register(reg_offset, reg_size)
                self.state.kill_and_add_definition(atom,
                                                   self._codeloc(),
                                                   MultiValues(offset_to_values=
                                                               {0: {self.state.top(reg_size * self.arch.byte_width)}}),
                                                   )

        if self.arch.call_pushes_ret is True:
            # pop return address if necessary
            sp: MultiValues = self.state.register_definitions.load(self.arch.sp_offset, size=self.arch.bytes)
            sp_v = sp.one_value()
            if sp_v is not None and not self.state.is_top(sp_v):
                sp_addr = sp_v - self.arch.stack_change

                atom = Register(self.arch.sp_offset, self.arch.bytes)
                tag = ReturnValueTag(
                    function = func_addr_int,
                    metadata = {'tagged_by': 'SimEngineRDVEX._handle_function_cc'}
                )
                self.state.kill_and_add_definition(atom, self._codeloc(),
                                                   MultiValues(offset_to_values={0: {sp_addr}}),
                                                   tags={tag},
                                                   )

    def _tag_definitions_of_atom(self, atom: Atom, func_addr: int):
        definitions = self.state.get_definitions(atom)
        tag = ParameterTag(
            function = func_addr,
            metadata = {'tagged_by': 'SimEngineRDVEX._handle_function_cc'}
        )
        for definition in definitions:
            definition.tags |= {tag}
