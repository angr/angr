from itertools import chain
from typing import Optional, TYPE_CHECKING
from collections.abc import Iterable
import logging

import pyvex
import claripy

from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ...engines.light import SimEngineLight, SimEngineLightVEXMixin, SpOffset
from ...engines.vex.claripy.datalayer import value as claripy_value
from ...engines.vex.claripy.irop import operations as vex_operations
from ...errors import SimEngineError, SimMemoryMissingError
from ...utils.constants import DEFAULT_STATEMENT
from ...knowledge_plugins.key_definitions.live_definitions import Definition, LiveDefinitions
from ...knowledge_plugins.key_definitions.tag import LocalVariableTag, ParameterTag, Tag
from ...knowledge_plugins.key_definitions.atoms import Atom, Register, MemoryLocation, Tmp
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from ...knowledge_plugins.key_definitions.heap_address import HeapAddress
from ...code_location import CodeLocation, ExternalCodeLocation
from .rd_state import ReachingDefinitionsState
from .function_handler import FunctionCallData

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

    state: ReachingDefinitionsState

    def __init__(self, project, functions=None, function_handler=None):
        super().__init__()
        self.project = project
        self.functions: Optional["FunctionManager"] = functions
        self._function_handler: Optional["FunctionHandler"] = function_handler
        self._visited_blocks = None
        self._dep_graph = None

        self.state: ReachingDefinitionsState

    def process(self, state, *args, block=None, fail_fast=False, visited_blocks=None, dep_graph=None, **kwargs):
        self._visited_blocks = visited_blocks
        self._dep_graph = dep_graph
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
            l.error(e)
        return self.state

    def _process_block_end(self):
        self.stmt_idx = DEFAULT_STATEMENT
        self._set_codeloc()
        if self.block.vex.jumpkind == "Ijk_Call":
            # it has to be a function
            addr = self._expr(self.block.vex.next)
            self._handle_function(addr)
        elif self.block.vex.jumpkind == "Ijk_Boring":
            # test if the target addr is a function or not
            addr = self._expr(self.block.vex.next)
            addr_v = addr.one_value()
            if addr_v is not None and addr_v.concrete:
                addr_int = addr_v.concrete_value
                if addr_int in self.functions:
                    # yes it's a jump to a function
                    self._handle_function(addr)

    #
    # Private methods
    #

    def _external_codeloc(self):
        return ExternalCodeLocation(self.state.codeloc.context)

    def _set_codeloc(self):
        # TODO do we want a better mechanism to specify context updates?
        new_codeloc = CodeLocation(
            self.block.addr, self.stmt_idx, ins_addr=self.ins_addr, context=self.state.codeloc.context
        )
        self.state.move_codelocs(new_codeloc)
        self.state.analysis.model.at_new_stmt(new_codeloc)

    def _is_top(self, expr):
        """
        MultiValues are not really "top" in the stricter sense. They are just a collection of values,
        some of which might be top
        """
        return False

    def _top(self, size) -> MultiValues:
        """
        Because _is_top is always False, this method is only very rarely called.
        Currently, it is only expected to be called from the _handle_Cmp*_v methods that aren't
        implemented in the SimEngineLightVexMixin, which then falls back to returning top
        :param size:
        :return:
        """
        return MultiValues(self.state.top(size))

    #
    # VEX statement handlers
    #

    def _handle_Stmt(self, stmt):
        if self.state.analysis:
            self.state.analysis.stmt_observe(self.stmt_idx, stmt, self.block, self.state, OP_BEFORE)
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

        self._set_codeloc()
        super()._handle_Stmt(stmt)

        if self.state.analysis:
            self.state.analysis.stmt_observe(self.stmt_idx, stmt, self.block, self.state, OP_AFTER)
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

        self.state.kill_and_add_definition(
            tmp_atom,
            data,
        )

    def _handle_WrTmpData(self, tmp: int, data):
        super()._handle_WrTmpData(tmp, data)
        self.state.kill_and_add_definition(Tmp(tmp, self.tyenv.sizeof(tmp)), self.tmps[tmp])

    # e.g. PUT(rsp) = t2, t2 might include multiple values
    def _handle_Put(self, stmt):
        reg_offset: int = stmt.offset
        size: int = stmt.data.result_size(self.tyenv) // 8
        reg = Register(reg_offset, size, self.arch)
        data = self._expr(stmt.data)

        # special handling for references to heap or stack variables
        if data.count() == 1:
            for d in next(iter(data.values())):
                if self.state.is_heap_address(d):
                    heap_offset = self.state.get_heap_offset(d)
                    if heap_offset is not None:
                        self.state.add_heap_use(heap_offset, 1)
                elif self.state.is_stack_address(d):
                    stack_offset = self.state.get_stack_offset(d)
                    if stack_offset is not None:
                        self.state.add_stack_use(stack_offset, 1)

        if self.state.exit_observed and reg_offset == self.arch.sp_offset:
            return
        self.state.kill_and_add_definition(reg, data)

    def _handle_PutI(self, stmt):
        pass

    # e.g. STle(t6) = t21, t6 and/or t21 might include multiple values
    def _handle_Store(self, stmt):
        addr = self._expr(stmt.addr)
        size = stmt.data.result_size(self.tyenv) // 8
        data = self._expr(stmt.data)

        if addr.count() == 1:
            addrs = next(iter(addr.values()))
            self._store_core(addrs, size, data, endness=stmt.endness)

    def _handle_StoreG(self, stmt: pyvex.IRStmt.StoreG):
        guard = self._expr(stmt.guard)
        guard_v = guard.one_value()

        if claripy.is_true(guard_v):
            addr = self._expr(stmt.addr)
            if addr.count() == 1:
                addrs = next(iter(addr.values()))
                size = stmt.data.result_size(self.tyenv) // 8
                data = self._expr(stmt.data)
                self._store_core(addrs, size, data)
        elif claripy.is_false(guard_v):
            pass
        else:
            # guard.data == {True, False}
            # get current data
            addr = self._expr(stmt.addr)
            if addr.count() == 1:
                addrs = next(iter(addr.values()))
                size = stmt.data.result_size(self.tyenv) // 8
                data_old = self._load_core(addrs, size, stmt.endness)
                data = self._expr(stmt.data)

                self._store_core(addrs, size, data, data_old=data_old)

    def _store_core(
        self,
        addr: Iterable[int | claripy.ast.bv.BV],
        size: int,
        data: MultiValues,
        data_old: MultiValues | None = None,
        endness=None,
    ):
        if data_old is not None:
            data = data.merge(data_old)

        for a in addr:
            if self.state.is_top(a):
                l.debug("Memory address undefined, ins_addr = %#x.", self.ins_addr)
            else:
                tags: set[Tag] | None
                if isinstance(a, int):
                    atom = MemoryLocation(a, size)
                    tags = None
                elif self.state.is_stack_address(a):
                    offset = self.state.get_stack_offset(a)
                    if offset is None:
                        continue
                    atom = MemoryLocation(SpOffset(self.arch.bits, offset), size)
                    function_address = None  # we cannot get the function address in the middle of a store if a CFG
                    # does not exist. you should backpatch the function address later using
                    # the 'ins_addr' metadata entry.
                    tags = {
                        LocalVariableTag(
                            function=function_address,
                            metadata={"tagged_by": "SimEngineRDVEX._store_core", "ins_addr": self.ins_addr},
                        )
                    }

                elif self.state.is_heap_address(a):
                    offset = self.state.get_heap_offset(a)
                    if offset is not None:
                        atom = MemoryLocation(HeapAddress(offset), size)
                        tags = None
                    else:
                        continue

                elif isinstance(a, claripy.ast.BV):
                    addr_v = a.concrete_value
                    atom = MemoryLocation(addr_v, size)
                    tags = None

                else:
                    continue

                # different addresses are not killed by a subsequent iteration, because kill only removes entries
                # with same index and same size
                self.state.kill_and_add_definition(atom, data, tags=tags, endness=endness)

    def _handle_LoadG(self, stmt):
        guard = self._expr(stmt.guard)
        guard_v = guard.one_value()

        if claripy.is_true(guard_v):
            # FIXME: full conversion support
            if stmt.cvt.find("Ident") < 0:
                l.warning("Unsupported conversion %s in LoadG.", stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, load_expr)
            self._handle_WrTmp(wr_tmp_stmt)
        elif claripy.is_false(guard_v):
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, stmt.alt)
            self._handle_WrTmp(wr_tmp_stmt)
        else:
            if stmt.cvt.find("Ident") < 0:
                l.warning("Unsupported conversion %s in LoadG.", stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)

            load_expr_v = self._expr(load_expr)
            alt_v = self._expr(stmt.alt)

            data = load_expr_v.merge(alt_v)
            self._handle_WrTmpData(stmt.dst, data)

    def _handle_Exit(self, stmt):
        _ = self._expr(stmt.guard)
        target = stmt.dst.value
        self.state.mark_guard(target)
        if self.state.analysis is not None:
            self.state.analysis.exit_observe(
                self.block.addr,
                self.stmt_idx,
                self.block,
                self.state,
                node_idx=self.block.block_idx if hasattr(self.block, "block_idx") else None,
            )
        if (
            self.block.instruction_addrs
            and self.ins_addr in self.block.instruction_addrs
            and self.block.instruction_addrs.index(self.ins_addr) == self.block.instructions - 1
        ):
            self.state.exit_observed = True

    def _handle_IMark(self, stmt):
        pass

    def _handle_AbiHint(self, stmt):
        pass

    def _handle_LLSC(self, stmt: pyvex.IRStmt.LLSC):
        if stmt.storedata is None:
            # load-link
            addr = self._expr(stmt.addr)
            if addr.count() == 1:
                addrs = next(iter(addr.values()))
                size = self.tyenv.sizeof(stmt.result) // self.arch.byte_width
                load_result = self._load_core(addrs, size, stmt.endness)
                self.tmps[stmt.result] = load_result
                self.state.kill_and_add_definition(
                    Tmp(stmt.result, self.tyenv.sizeof(stmt.result) // self.arch.byte_width),
                    load_result,
                )
        else:
            # store-conditional
            storedata = self._expr(stmt.storedata)
            addr = self._expr(stmt.addr)
            if addr.count() == 1:
                addrs = next(iter(addr.values()))
                if isinstance(stmt.storedata, pyvex.IRExpr.Const):
                    size = stmt.storedata.con.size // self.arch.byte_width
                else:
                    size = self.tyenv.sizeof(stmt.storedata.tmp) // self.arch.byte_width

                self._store_core(addrs, size, storedata)
                self.tmps[stmt.result] = MultiValues(claripy.BVV(1, 1))
                self.state.kill_and_add_definition(
                    Tmp(stmt.result, self.tyenv.sizeof(stmt.result) // self.arch.byte_width),
                    self.tmps[stmt.result],
                )

    #
    # VEX expression handlers
    #

    def _expr(self, expr) -> MultiValues:
        data = super()._expr(expr)
        if data is None:
            bits = expr.result_size(self.tyenv)
            top = self.state.top(bits)
            data = MultiValues(top)
        return data

    def _handle_RdTmp(self, expr: pyvex.IRExpr.RdTmp) -> MultiValues | None:
        tmp: int = expr.tmp

        self.state.add_tmp_use(tmp)

        if tmp in self.tmps:
            return self.tmps[tmp]
        return None

    # e.g. t0 = GET:I64(rsp), rsp might be defined multiple times
    def _handle_Get(self, expr: pyvex.IRExpr.Get) -> MultiValues:
        reg_offset: int = expr.offset
        bits: int = expr.result_size(self.tyenv)
        size: int = bits // self.arch.byte_width

        reg_atom = Register(reg_offset, size, self.arch)
        try:
            values: MultiValues = self.state.registers.load(reg_offset, size=size)
        except SimMemoryMissingError:
            top = self.state.top(size * self.arch.byte_width)
            # annotate it
            top = self.state.annotate_with_def(top, Definition(reg_atom, self._external_codeloc()))
            values = MultiValues(top)
            # write it to registers
            self.state.kill_and_add_definition(reg_atom, values, override_codeloc=self._external_codeloc())

        current_defs: Iterable[Definition] | None = None
        for vs in values.values():
            for v in vs:
                if current_defs is None:
                    current_defs = self.state.extract_defs(v)
                else:
                    current_defs = chain(current_defs, self.state.extract_defs(v))

        if current_defs is None:
            # no defs can be found. add a fake definition
            mv = self.state.kill_and_add_definition(reg_atom, values, override_codeloc=self._external_codeloc())
            current_defs = set()
            for vs in mv.values():
                for v in vs:
                    current_defs |= self.state.extract_defs(v)

        self.state.add_register_use_by_defs(current_defs)

        return values

    def _handle_GetI(self, expr: pyvex.IRExpr.GetI) -> MultiValues:
        return MultiValues(self.state.top(expr.result_size(self.tyenv)))

    # e.g. t27 = LDle:I64(t9), t9 might include multiple values
    # caution: Is also called from StoreG
    def _handle_Load(self, expr) -> MultiValues:
        addr = self._expr(expr.addr)
        bits = expr.result_size(self.tyenv)
        size = bits // self.arch.byte_width

        # convert addr from MultiValues to a list of valid addresses
        if addr.count() == 1 and 0 in addr:
            addrs = list(addr[0])
            return self._load_core(addrs, size, expr.endness)

        top = self.state.top(bits)
        # annotate it
        dummy_atom = MemoryLocation(0, size)
        def_ = Definition(dummy_atom, self._external_codeloc())
        top = self.state.annotate_with_def(top, def_)
        # add use
        self.state.add_memory_use_by_def(def_)
        return MultiValues(top)

    def _load_core(self, addrs: Iterable[claripy.ast.Base], size: int, endness: str) -> MultiValues:
        result: MultiValues | None = None
        # we may get more than one stack addrs with the same value but different annotations (because they are defined
        # at different locations). only load them once.
        loaded_stack_offsets = set()

        for addr in addrs:
            if self.state.is_top(addr):
                l.debug("Memory address undefined, ins_addr = %#x.", self.ins_addr)
            elif self.state.is_stack_address(addr):
                # Load data from a local variable
                stack_offset = self.state.get_stack_offset(addr)
                if stack_offset is not None and stack_offset not in loaded_stack_offsets:
                    loaded_stack_offsets.add(stack_offset)
                    stack_addr = self.state.live_definitions.stack_offset_to_stack_addr(stack_offset)
                    try:
                        vs: MultiValues = self.state.stack.load(stack_addr, size=size, endness=endness)
                        # extract definitions
                        defs = set(LiveDefinitions.extract_defs_from_mv(vs))
                    except SimMemoryMissingError:
                        continue

                    self.state.add_stack_use_by_defs(defs)
                    result = result.merge(vs) if result is not None else vs

            elif self.state.is_heap_address(addr):
                # Load data from the heap
                heap_offset = self.state.get_heap_offset(addr)
                if heap_offset is not None:
                    try:
                        vs: MultiValues = self.state.heap.load(heap_offset, size=size, endness=endness)
                        defs = set(LiveDefinitions.extract_defs_from_mv(vs))
                    except SimMemoryMissingError:
                        continue

                    self.state.add_heap_use_by_defs(defs)
                    result = result.merge(vs) if result is not None else vs

            else:
                addr_v = addr.concrete_value

                # Load data from a global region
                try:
                    vs: MultiValues = self.state.memory.load(addr_v, size=size, endness=endness)
                    defs = set(LiveDefinitions.extract_defs_from_mv(vs))
                except SimMemoryMissingError:
                    try:
                        val = self.project.loader.memory.unpack_word(addr_v, size=size)
                        section = self.project.loader.find_section_containing(addr_v)
                        missing_atom = MemoryLocation(addr_v, size)
                        missing_def = Definition(missing_atom, self._external_codeloc())
                        if val == 0 and (not section or section.is_writable):
                            top = self.state.top(size * self.arch.byte_width)
                            v = self.state.annotate_with_def(top, missing_def)
                        else:
                            v = self.state.annotate_with_def(claripy.BVV(val, size * self.arch.byte_width), missing_def)
                        vs = MultiValues(v)
                        if not section or section.is_writable:
                            self.state.memory.store(addr_v, vs, size=size, endness=endness)
                            self.state.all_definitions.add(missing_def)
                        defs = {missing_def}
                    except KeyError:
                        continue

                self.state.add_memory_use_by_defs(defs)
                result = result.merge(vs) if result is not None else vs

        if result is None:
            result = MultiValues(self.state.top(size * self.arch.byte_width))

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
        clrp = claripy_value(expr.con.type, expr.con.value)
        self.state.mark_const(expr.con.value, len(clrp) // 8)
        return MultiValues(clrp)

    def _handle_Conversion(self, expr):
        simop = vex_operations[expr.op]
        bits = int(simop.op_attrs["to_size"])
        arg_0 = self._expr(expr.args[0])

        # if there are multiple values with only one offset, we apply conversion to each one of them
        # otherwise, we return a TOP

        if arg_0.count() == 1:
            # extension, extract, or doing nothing
            data = set()
            for v in next(iter(arg_0.values())):
                if bits > v.size():
                    data.add(v.zero_extend(bits - v.size()))
                else:
                    if isinstance(v, claripy.ast.fp.FP):
                        data.add(v.val_to_bv(bits))
                    else:
                        data.add(v[bits - 1 : 0])
            r = MultiValues(offset_to_values={next(iter(arg_0.keys())): data})

        else:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_Not1(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)

        e0 = expr_0.one_value()

        if e0 is not None and not e0.symbolic:
            return MultiValues(claripy.BVV(1, 1) if e0.concrete_value != 1 else claripy.BVV(0, 1))

        return MultiValues(self.state.top(1))

    def _handle_Not(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)
        bits = expr.result_size(self.tyenv)

        e0 = expr_0.one_value()

        if e0 is not None and not e0.symbolic:
            return MultiValues(~e0)  # pylint:disable=invalid-unary-operand-type

        return MultiValues(self.state.top(bits))

    def _handle_Clz(self, expr):
        arg0 = expr.args[0]
        _ = self._expr(arg0)
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        return MultiValues(self.state.top(bits))

    def _handle_Ctz(self, expr):
        arg0 = expr.args[0]
        _ = self._expr(arg0)
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        return MultiValues(self.state.top(bits))

    #
    # Binary operation handlers
    #
    def _handle_ExpCmpNE64(self, expr):
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        r = MultiValues(self.state.top(bits))
        return r

    def _handle_16HLto32(self, expr):
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        r = MultiValues(self.state.top(bits))
        return r

    def _handle_Add(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support addition between two real multivalues
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # adding a single value to a multivalue
            if expr0.count() == 1 and 0 in expr0:
                vs = {v.sign_extend(expr1_v.size() - v.size()) + expr1_v for v in expr0[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # adding a single value to a multivalue
            if expr1.count() == 1 and 0 in expr1:
                vs = {expr0_v + v.sign_extend(expr0_v.size() - v.size()) for v in expr1[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # adding two single values together
            r = MultiValues(expr0_v + expr1_v)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_Sub(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support addition between two real multivalues
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # subtracting a single value from a multivalue
            if expr0.count() == 1 and 0 in expr0:
                vs = {v - expr1_v for v in expr0[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # subtracting a single value from a multivalue
            if expr1.count() == 1 and 0 in expr1:
                vs = {expr0_v - v for v in expr1[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # subtracting a single value from another single value
            r = MultiValues(expr0_v - expr1_v)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_Mul(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support multiplication between two real multivalues
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # multiplying a single value to a multivalue
            if expr0.count() == 1 and 0 in expr0:
                vs = {v * expr1_v for v in expr0[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # multiplying a single value to a multivalue
            if expr1.count() == 1 and 0 in expr1:
                vs = {v * expr0_v for v in expr1[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # multiplying two single values together
            r = MultiValues(expr0_v * expr1_v)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_Mull(self, expr):
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)
        return MultiValues(self.state.top(bits))

    def _handle_Div(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support division between two real multivalues
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            if expr1_v.concrete and expr1_v.concrete_value == 0:
                r = MultiValues(self.state.top(bits))
            elif expr0.count() == 1 and 0 in expr0:
                vs = {v / expr1_v for v in expr0[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            if expr1.count() == 1 and 0 in expr1:
                vs = {expr0_v / v for v in expr1[0] if (not v.concrete) or v.concrete_value != 0}
                r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                # dividing two single values
                if expr1_v.concrete_value == 0:
                    r = MultiValues(self.state.top(bits))
                else:
                    r = MultiValues(expr0_v / expr1_v)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_DivMod(self, expr):
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = MultiValues(self.state.top(bits))

        return r

    def _handle_And(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support addition between two real multivalues
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # bitwise-and a single value with a multivalue
            if expr0.count() == 1 and 0 in expr0:
                vs = {v & expr1_v for v in expr0[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # bitwise-and a single value to a multivalue
            if expr1.count() == 1 and 0 in expr1:
                vs = {v & expr0_v for v in expr1[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                # bitwise-and two single values together
                r = MultiValues(expr0_v & expr1_v)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_Xor(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support xor between two real multivalues
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # bitwise-xor a single value with a multivalue
            if expr0.count() == 1 and 0 in expr0:
                vs = {v.sign_extend(expr1_v.size() - v.size()) ^ expr1_v for v in expr0[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # bitwise-xor a single value to a multivalue
            if expr1.count() == 1 and 0 in expr1:
                vs = {v.sign_extend(expr0_v.size() - v.size()) ^ expr0_v for v in expr1[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            if expr0_v.concrete and expr1_v.concrete:
                # bitwise-xor two single values together
                r = MultiValues(expr0_v ^ expr1_v)

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_Or(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is None and expr1_v is None:
            # we do not support or between two real multivalues
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # bitwise-or a single value with a multivalue
            if expr0.count() == 1 and 0 in expr0:
                vs = {v | expr1_v for v in expr0[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # bitwise-or a single value to a multivalue
            if expr1.count() == 1 and 0 in expr1:
                vs = {v | expr0_v for v in expr1[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # bitwise-and two single values together
            r = MultiValues(expr0_v | expr1_v)

        if r is None:
            r = MultiValues(self.state.top(bits))

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
            e1 = e1.concrete_value

            if e1 > bits:
                return claripy.BVV(0, bits)

            if claripy.is_true(e0 >> (bits - 1) == 0):
                head = claripy.BVV(0, bits)
            else:
                head = ((1 << e1) - 1) << (bits - e1)
            return head | (e0 >> e1)

        if expr0_v is None and expr1_v is None:
            # we do not support shifting between two real multivalues
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # shifting a single value by a multivalue
            if expr0.count() == 1 and 0 in expr0:
                vs = {_shift_sar(v, expr1_v) for v in expr0[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # shifting a multivalue by a single value
            if expr1.count() == 1 and 0 in expr1:
                vs = {_shift_sar(expr0_v, v) for v in expr1[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # subtracting a single value from another single value
            r = MultiValues(_shift_sar(expr0_v, expr1_v))

        if r is None:
            r = MultiValues(self.state.top(bits))

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
                e1 = e1.sign_extend(e0.size() - e1.size())
            else:
                e0 = e0.sign_extend(e1.size() - e0.size())

            return claripy.LShR(e0, e1)

        if expr0_v is None and expr1_v is None:
            # we do not support shifting between two real multivalues
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # shifting a single value by a multivalue
            if expr0.count() == 1 and 0 in expr0:
                vs = {_shift_shr(v, expr1_v) for v in expr0[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # shifting a multivalue by a single value
            if expr1.count() == 1 and 0 in expr1:
                vs = {_shift_shr(expr0_v, v) for v in expr1[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # shifting a single value from another single value
            r = MultiValues(_shift_shr(expr0_v, expr1_v))

        if r is None:
            r = MultiValues(self.state.top(bits))

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
            e1 = e1.concrete_value
            return e0 << e1

        if expr0_v is None and expr1_v is None:
            # we do not support shifting between two real multivalues
            r = MultiValues(self.state.top(bits))
        elif expr0_v is None and expr1_v is not None:
            # shifting left a single value by a multivalue
            if expr0.count() == 1 and 0 in expr0:
                vs = {_shift_shl(v, expr1_v) for v in expr0[0]}
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # shifting left a multivalue by a single value
            if expr1.count() == 1 and 0 in expr1:
                vs = {_shift_shl(expr0_v, v) for v in expr1[0]}
                r = MultiValues(offset_to_values={0: vs})
        else:
            # subtracting a single value from another single value
            r = MultiValues(_shift_shl(expr0_v, expr1_v))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    def _handle_CmpEQ(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()

        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return MultiValues(claripy.BVV(1, 1) if e0.concrete_value == e1.concrete_value else claripy.BVV(0, 1))
            elif e0 is e1:
                return MultiValues(claripy.BVV(1, 1))
            return MultiValues(self.state.top(1))

        return MultiValues(self.state.top(1))

    def _handle_CmpNE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return MultiValues(claripy.BVV(1, 1) if e0.concrete_value != e1.concrete_value else claripy.BVV(0, 1))
            elif e0 is e1:
                return MultiValues(claripy.BVV(0, 1))
        return MultiValues(self.state.top(1))

    def _handle_CmpLT(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return MultiValues(claripy.BVV(1, 1) if e0.concrete_value < e1.concrete_value else claripy.BVV(0, 1))
            elif e0 is e1:
                return MultiValues(claripy.BVV(0, 1))
        return MultiValues(self.state.top(1))

    def _handle_CmpLE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return MultiValues(claripy.BVV(1, 1) if e0.concrete_value <= e1.concrete_value else claripy.BVV(0, 1))
            elif e0 is e1:
                return MultiValues(claripy.BVV(0, 1))
        return MultiValues(self.state.top(1))

    def _handle_CmpGT(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return MultiValues(claripy.BVV(1, 1) if e0.concrete_value > e1.concrete_value else claripy.BVV(0, 1))
            elif e0 is e1:
                return MultiValues(claripy.BVV(0, 1))
        return MultiValues(self.state.top(1))

    def _handle_CmpGE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return MultiValues(claripy.BVV(1, 1) if e0.concrete_value >= e1.concrete_value else claripy.BVV(0, 1))
            elif e0 is e1:
                return MultiValues(claripy.BVV(0, 1))
        return MultiValues(self.state.top(1))

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
                e0 = e0.concrete_value
                e1 = e1.concrete_value
                if e0 < e1:
                    return MultiValues(claripy.BVV(0x8, bits))
                elif e0 > e1:
                    return MultiValues(claripy.BVV(0x4, bits))
                else:
                    return MultiValues(claripy.BVV(0x2, bits))
            elif e0 is e1:
                return MultiValues(claripy.BVV(0x2, bits))

        return MultiValues(self.state.top(1))

    def _handle_CCall(self, expr):
        bits = expr.result_size(self.tyenv)
        for arg_expr in expr.args:
            self._expr(arg_expr)
        return MultiValues(self.state.top(bits))

    #
    # User defined high level statement handlers
    #

    def _handle_function(self, func_addr: MultiValues | None):
        if func_addr is None:
            func_addr = self.state.top(self.state.arch.bits)

        callsite = self.state.codeloc
        data = FunctionCallData(
            callsite,
            self._function_handler.make_function_codeloc(func_addr, callsite, self.state.analysis.model.func_addr),
            func_addr,
            visited_blocks=set(),
        )
        self._function_handler.handle_function(self.state, data)
        self._visited_blocks = data.visited_blocks

    def _tag_definitions_of_atom(self, atom: Atom, func_addr: int):
        definitions = self.state.get_definitions(atom)
        tag = ParameterTag(function=func_addr, metadata={"tagged_by": "SimEngineRDVEX._handle_function_cc"})
        for definition in definitions:
            definition.tags |= {tag}
