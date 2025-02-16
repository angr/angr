from __future__ import annotations
from itertools import chain
from typing import TYPE_CHECKING
from collections.abc import Iterable
import logging

import pyvex
import claripy

from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues, mv_is_bv
from angr.engines.light import SimEngineNostmtVEX, SpOffset
from angr.engines.vex.claripy.datalayer import value as claripy_value
from angr.errors import SimEngineError, SimMemoryMissingError
from angr.utils.constants import DEFAULT_STATEMENT
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.tag import LocalVariableTag, ParameterTag, Tag
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register, MemoryLocation, Tmp
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.code_location import CodeLocation, ExternalCodeLocation
from .rd_state import ReachingDefinitionsState
from .function_handler import FunctionCallData

if TYPE_CHECKING:
    from angr.knowledge_plugins import FunctionManager
    from .function_handler import FunctionHandler


l = logging.getLogger(name=__name__)

unop_handler = SimEngineNostmtVEX[
    ReachingDefinitionsState, MultiValues[claripy.ast.BV | claripy.ast.FP], ReachingDefinitionsState
].unop_handler
binop_handler = SimEngineNostmtVEX[
    ReachingDefinitionsState, MultiValues[claripy.ast.BV | claripy.ast.FP], ReachingDefinitionsState
].binop_handler


class SimEngineRDVEX(
    SimEngineNostmtVEX[
        ReachingDefinitionsState, MultiValues[claripy.ast.BV | claripy.ast.FP], ReachingDefinitionsState
    ],
):  # pylint:disable=abstract-method
    """
    Implements the VEX execution engine for reaching definition analysis.
    """

    def __init__(self, project, function_handler: FunctionHandler, functions: FunctionManager):
        super().__init__(project)
        self.functions = functions
        self._function_handler = function_handler
        self._visited_blocks = None
        self._dep_graph = None

        self.state: ReachingDefinitionsState

    def process(
        self, state, *, block=None, fail_fast=False, visited_blocks=None, dep_graph=None, whitelist=None, **kwargs
    ):
        self._visited_blocks = visited_blocks
        self._dep_graph = dep_graph
        # we are using a completely different state. Therefore, we directly call our _process() method before
        # SimEngine becomes flexible enough.
        try:
            return super().process(
                state,
                whitelist=whitelist,
                block=block,
            )
        except SimEngineError as e:
            if fail_fast is True:
                raise e
            l.error(e)
        return self.state

    def _process_block_end(self, stmt_result, whitelist):
        self.stmt_idx = DEFAULT_STATEMENT
        self._set_codeloc()

        function_handled = False
        if self.block.vex.jumpkind == "Ijk_Call":
            # it has to be a function
            block_next = self.block.vex.next
            assert isinstance(block_next, pyvex.expr.IRExpr)
            addr = self._expr_bv(block_next)
            self._handle_function(addr)
            function_handled = True
        elif self.block.vex.jumpkind == "Ijk_Boring":
            # test if the target addr is a function or not
            block_next = self.block.vex.next
            assert isinstance(block_next, pyvex.expr.IRExpr)
            addr = self._expr_bv(block_next)
            addr_v = addr.one_value()
            if addr_v is not None and addr_v.concrete:
                addr_int = addr_v.concrete_value
                if addr_int in self.functions:
                    # yes it's a jump to a function
                    self._handle_function(addr)
                    function_handled = True

        # take care of OP_AFTER during statement processing for function calls in a block
        if self.state.analysis and function_handled:
            self.state.analysis.stmt_observe(
                self.stmt_idx, self.block.vex.statements[-1], self.block, self.state, OP_AFTER
            )
            self.state.analysis.insn_observe(
                self.ins_addr, self.block.vex.statements[-1], self.block, self.state, OP_AFTER
            )

        return self.state

    #
    # Private methods
    #

    def _expr_bv(self, expr: pyvex.expr.IRExpr) -> MultiValues[claripy.ast.BV]:
        result = self._expr(expr)
        assert mv_is_bv(result)
        return result

    def _expr_pair(
        self, arg0: pyvex.expr.IRExpr, arg1: pyvex.expr.IRExpr
    ) -> (
        tuple[MultiValues[claripy.ast.BV], MultiValues[claripy.ast.BV]]
        | tuple[MultiValues[claripy.ast.FP], MultiValues[claripy.ast.FP]]
    ):
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)
        assert type(r0) is type(r1)
        return r0, r1  # type: ignore

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

    def _top(self, bits) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        return MultiValues(self.state.top(bits))

    #
    # VEX statement handlers
    #

    def _stmt(self, stmt):
        if self.state.analysis:
            self.state.analysis.stmt_observe(self.stmt_idx, stmt, self.block, self.state, OP_BEFORE)
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

        self._set_codeloc()
        result = super()._stmt(stmt)

        if self.state.analysis:
            self.state.analysis.stmt_observe(self.stmt_idx, stmt, self.block, self.state, OP_AFTER)
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_AFTER)

        return result

    def _handle_stmt_WrTmp(self, stmt):
        data = self._expr(stmt.data)

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

    # e.g. PUT(rsp) = t2, t2 might include multiple values
    def _handle_stmt_Put(self, stmt):
        size: int = stmt.data.result_size(self.tyenv) // 8
        reg = Register(stmt.offset, size, self.arch)
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

        if self.state.exit_observed and stmt.offset == self.arch.sp_offset:
            return
        self.state.kill_and_add_definition(reg, data)

    def _handle_stmt_PutI(self, stmt):
        pass

    # e.g. STle(t6) = t21, t6 and/or t21 might include multiple values
    def _handle_stmt_Store(self, stmt):
        addr = self._expr_bv(stmt.addr)
        size = stmt.data.result_size(self.tyenv) // 8
        data = self._expr(stmt.data)

        if addr.count() == 1:
            addrs = next(iter(addr.values()))
            self._store_core(addrs, size, data, endness=stmt.endness)

    def _handle_stmt_StoreG(self, stmt):
        guard = self._expr_bv(stmt.guard)
        guard_v = guard.one_value()

        if guard_v is not None and claripy.is_true(guard_v != 0):
            addr = self._expr_bv(stmt.addr)
            if addr.count() == 1:
                addrs = next(iter(addr.values()))
                size = stmt.data.result_size(self.tyenv) // 8
                data = self._expr(stmt.data)
                self._store_core(addrs, size, data)
        elif guard_v is not None and claripy.is_false(guard_v != 0):
            pass
        else:
            # guard.data == {True, False}
            # get current data
            addr = self._expr_bv(stmt.addr)
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

    def _handle_stmt_LoadG(self, stmt):
        guard = self._expr_bv(stmt.guard)
        guard_v = guard.one_value()

        if guard_v is not None and claripy.is_true(guard_v != 0):
            # FIXME: full conversion support
            if stmt.cvt.find("Ident") < 0:
                l.warning("Unsupported conversion %s in LoadG.", stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, load_expr)
            self._handle_stmt_WrTmp(wr_tmp_stmt)
        elif guard_v is not None and claripy.is_false(guard_v != 0):
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, stmt.alt)
            self._handle_stmt_WrTmp(wr_tmp_stmt)
        else:
            if stmt.cvt.find("Ident") < 0:
                l.warning("Unsupported conversion %s in LoadG.", stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)

            load_expr_v = self._expr(load_expr)
            alt_v = self._expr(stmt.alt)

            data = load_expr_v.merge(alt_v)
            self.state.kill_and_add_definition(Tmp(stmt.dst, self.tyenv.sizeof(stmt.dst)), data)

    def _handle_stmt_Exit(self, stmt):
        _ = self._expr(stmt.guard)
        target = stmt.dst.value
        self.state.mark_guard(target)
        if self.state.analysis is not None:
            self.state.analysis.exit_observe(
                self.block.addr,
                self.stmt_idx,
                self.block,
                self.state,
            )
        if (
            self.block.instruction_addrs
            and self.ins_addr in self.block.instruction_addrs
            and self.block.instruction_addrs.index(self.ins_addr) == self.block.instructions - 1
        ):
            self.state.exit_observed = True

    def _handle_stmt_IMark(self, stmt):
        pass

    def _handle_stmt_AbiHint(self, stmt):
        pass

    def _handle_stmt_LLSC(self, stmt):
        if stmt.storedata is None:
            # load-link
            addr = self._expr_bv(stmt.addr)
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
            addr = self._expr_bv(stmt.addr)
            if addr.count() == 1:
                addrs = next(iter(addr.values()))
                if isinstance(stmt.storedata, pyvex.expr.Const):
                    size = stmt.storedata.con.size // self.arch.byte_width
                else:
                    assert isinstance(stmt.storedata, pyvex.expr.RdTmp)
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

    def _handle_expr_RdTmp(self, expr: pyvex.expr.RdTmp):
        self.state.add_tmp_use(expr.tmp)

        if expr.tmp in self.tmps:
            return self.tmps[expr.tmp]
        return self._top(pyvex.get_type_size(self.tyenv.lookup(expr.tmp)))

    # e.g. t0 = GET:I64(rsp), rsp might be defined multiple times
    def _handle_expr_Get(self, expr: pyvex.expr.Get):
        bits: int = expr.result_size(self.tyenv)
        size: int = bits // self.arch.byte_width

        reg_atom = Register(expr.offset, size, self.arch)
        try:
            values: MultiValues = self.state.registers.load(expr.offset, size=size)
        except SimMemoryMissingError:
            top = self.state.top(size * self.arch.byte_width)
            # annotate it
            top = self.state.annotate_with_def(top, Definition(reg_atom, self._external_codeloc()))
            values = MultiValues(top)
            # write it to registers
            self.state.kill_and_add_definition(reg_atom, values, override_codeloc=self._external_codeloc())

        current_defs: Iterable[Definition[Atom]] | None = None
        for vs in values.values():
            for v in vs:
                if current_defs is None:
                    current_defs = self.state.extract_defs(v)
                else:
                    current_defs = chain(current_defs, self.state.extract_defs(v))

        assert current_defs is not None
        self.state.add_register_use_by_defs(current_defs)

        return values

    def _handle_expr_GetI(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        return MultiValues(self.state.top(expr.result_size(self.tyenv)))

    # e.g. t27 = LDle:I64(t9), t9 might include multiple values
    # caution: Is also called from StoreG
    def _handle_expr_Load(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        addr = self._expr_bv(expr.addr)
        bits = expr.result_size(self.tyenv)
        size = bits // self.arch.byte_width

        # convert addr from MultiValues to a list of valid addresses
        if (one_addr := addr.one_value()) is not None:
            return self._load_core([one_addr], size, expr.endness)

        top = self.state.top(bits)
        # annotate it
        dummy_atom = MemoryLocation(0, size)
        def_ = Definition(dummy_atom, self._external_codeloc())
        top = self.state.annotate_with_def(top, def_)
        # add use
        self.state.add_memory_use_by_def(def_)
        return MultiValues(top)

    def _load_core(
        self, addrs: Iterable[claripy.ast.BV], size: int, endness: str
    ) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
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
    def _handle_expr_ITE(self, expr):
        cond = self._expr(expr.cond)
        cond_v = cond.one_value()
        iftrue = self._expr(expr.iftrue)
        iffalse = self._expr(expr.iffalse)

        if claripy.is_true(cond_v):
            return iftrue
        if claripy.is_false(cond_v):
            return iffalse
        return iftrue.merge(iffalse)

    #
    # Unary operation handlers
    #

    def _handle_expr_Const(self, expr):
        clrp = claripy_value(expr.con.type, expr.con.value)
        self.state.mark_const(expr.con.value, len(clrp) // 8)
        return MultiValues(clrp)

    def _handle_conversion(self, from_size, to_size, signed, operand) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        arg_0 = self._expr_bv(operand)

        # if there are multiple values with only one offset, we apply conversion to each one of them
        # otherwise, we return a TOP

        if arg_0.count() == 1:
            # extension, extract, or doing nothing
            data: set[claripy.ast.BV | claripy.ast.FP] = set()
            for v in next(iter(arg_0.values())):
                assert v.size() == from_size
                if to_size > from_size:
                    if signed:
                        data.add(v.sign_extend(to_size - from_size))
                    else:
                        data.add(v.zero_extend(to_size - from_size))
                else:
                    data.add(v[to_size - 1 : 0])
            r = MultiValues({next(iter(arg_0.keys())): data})

        else:
            r = self._top(to_size)

        return r

    @unop_handler
    def _handle_unop_Not(self, expr: pyvex.expr.Unop) -> MultiValues:
        arg0 = expr.args[0]
        expr_0 = self._expr_bv(arg0)
        bits = expr.result_size(self.tyenv)

        e0 = expr_0.one_value()

        if e0 is not None and not e0.symbolic:
            return MultiValues(~e0)  # pylint:disable=invalid-unary-operand-type

        return MultiValues(self.state.top(bits))

    @unop_handler
    def _handle_unop_Clz(self, expr: pyvex.expr.Unop) -> MultiValues:
        arg0 = expr.args[0]
        _ = self._expr(arg0)
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        return MultiValues(self.state.top(bits))

    @unop_handler
    def _handle_unop_Ctz(self, expr: pyvex.expr.Unop) -> MultiValues:
        arg0 = expr.args[0]
        _ = self._expr(arg0)
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        return MultiValues(self.state.top(bits))

    #
    # Binary operation handlers
    #
    @binop_handler
    def _handle_binop_ExpCmpNE64(self, expr: pyvex.expr.Binop) -> MultiValues:
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        return MultiValues(self.state.top(bits))

    @binop_handler
    def _handle_binop_16HLto32(self, expr: pyvex.expr.Binop) -> MultiValues:
        expr0, expr1 = self._expr_bv(expr.args[0]), self._expr_bv(expr.args[1])
        return expr0.concat(expr1)

    @binop_handler
    def _handle_binop_Add(self, expr: pyvex.expr.Binop) -> MultiValues:
        expr0, expr1 = self._expr_bv(expr.args[0]), self._expr_bv(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            # adding two single values together
            r = MultiValues(expr0_v + expr1_v)
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
            # we do not support addition between two real multivalues
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    @binop_handler
    def _handle_binop_Sub(self, expr: pyvex.expr.Binop) -> MultiValues:
        expr0, expr1 = self._expr_bv(expr.args[0]), self._expr_bv(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            # subtracting a single value from another single value
            r = MultiValues(expr0_v - expr1_v)
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
            # we do not support addition between two real multivalues
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    @binop_handler
    def _handle_binop_Mul(self, expr: pyvex.expr.Binop) -> MultiValues:
        expr0, expr1 = self._expr_pair(expr.args[0], expr.args[1])
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
                vs = {v * expr1_v for v in expr0[0]}  # type: ignore
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            # multiplying a single value to a multivalue
            if expr1.count() == 1 and 0 in expr1:
                vs = {v * expr0_v for v in expr1[0]}  # type: ignore
                r = MultiValues(offset_to_values={0: vs})
        else:
            # multiplying two single values together
            r = MultiValues(expr0_v * expr1_v)  # type: ignore

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    @binop_handler
    def _handle_binop_Mull(self, expr: pyvex.expr.Binop) -> MultiValues:
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)
        return MultiValues(self.state.top(bits))

    @binop_handler
    def _handle_binop_Div(self, expr: pyvex.expr.Binop) -> MultiValues:
        expr0, expr1 = self._expr_pair(expr.args[0], expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            if expr0_v.concrete and expr1_v.concrete:
                # dividing two single values
                r = (
                    MultiValues(self.state.top(bits)) if expr1_v.concrete_value == 0 else MultiValues(expr0_v / expr1_v)
                )  # type: ignore
        elif expr0_v is None and expr1_v is not None:
            if expr1_v.concrete and expr1_v.concrete_value == 0:
                r = MultiValues(self.state.top(bits))
            elif expr0.count() == 1 and 0 in expr0:
                vs = {v / expr1_v for v in expr0[0]}  # type: ignore
                r = MultiValues(offset_to_values={0: vs})
        elif expr0_v is not None and expr1_v is None:
            if expr1.count() == 1 and 0 in expr1:
                vs = {expr0_v / v for v in expr1[0] if (not v.concrete) or v.concrete_value != 0}  # type: ignore
                r = MultiValues(offset_to_values={0: vs})
        else:
            # we do not support division between two real multivalues
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    @binop_handler
    def _handle_binop_DivMod(self, expr: pyvex.expr.Binop) -> MultiValues:
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        return MultiValues(self.state.top(bits))

    @binop_handler
    def _handle_Mod(self, expr: pyvex.expr.Binop) -> MultiValues:
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)
        return MultiValues(self.state.top(bits))

    @binop_handler
    def _handle_binop_And(self, expr: pyvex.expr.Binop) -> MultiValues:
        expr0, expr1 = self._expr_bv(expr.args[0]), self._expr_bv(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            # bitwise-and two single values together
            r = MultiValues(expr0_v & expr1_v)
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
            # we do not support addition between two real multivalues
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    @binop_handler
    def _handle_binop_Xor(self, expr: pyvex.expr.Binop) -> MultiValues:
        expr0, expr1 = self._expr_bv(expr.args[0]), self._expr_bv(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            if expr0_v.concrete and expr1_v.concrete:
                # bitwise-xor two single values together
                r = MultiValues(expr0_v ^ expr1_v)
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
            # we do not support xor between two real multivalues
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    @binop_handler
    def _handle_binop_Or(self, expr: pyvex.expr.Binop) -> MultiValues:
        expr0, expr1 = self._expr_bv(expr.args[0]), self._expr_bv(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        if expr0_v is not None and expr1_v is not None:
            # bitwise-and two single values together
            r = MultiValues(expr0_v | expr1_v)
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
            # we do not support or between two real multivalues
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    @binop_handler
    def _handle_binop_Sar(self, expr: pyvex.expr.Binop) -> MultiValues:
        expr0, expr1 = self._expr_bv(expr.args[0]), self._expr_bv(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = None
        expr0_v = expr0.one_value()
        expr1_v = expr1.one_value()

        def _shift_sar(e0: claripy.ast.BV, e1: claripy.ast.BV):
            # convert e1 to an integer to prevent claripy from complaining "args' lengths must all be equal"
            if e1.symbolic:
                return self.state.top(bits)
            e1_int = e1.concrete_value

            if e1_int > bits:
                return claripy.BVV(0, bits)

            head = claripy.BVV(0, bits) if claripy.is_true(e0 >> bits - 1 == 0) else (1 << e1_int) - 1 << bits - e1_int
            return head | (e0 >> e1_int)

        if expr0_v is not None and expr1_v is not None:
            # subtracting a single value from another single value
            r = MultiValues(_shift_sar(expr0_v, expr1_v))
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
            # we do not support shifting between two real multivalues
            r = MultiValues(self.state.top(bits))

        if r is None:
            r = MultiValues(self.state.top(bits))

        return r

    @binop_handler
    def _handle_binop_Shr(self, expr: pyvex.expr.Binop) -> MultiValues:
        expr0, expr1 = self._expr_bv(expr.args[0]), self._expr_bv(expr.args[1])
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

    @binop_handler
    def _handle_binop_Shl(self, expr: pyvex.expr.Binop) -> MultiValues:
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

    @binop_handler
    def _handle_binop_CmpEQ(self, expr: pyvex.expr.Binop) -> MultiValues:
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()

        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return MultiValues(claripy.BVV(1, 1) if e0.concrete_value == e1.concrete_value else claripy.BVV(0, 1))
            if e0 is e1:
                return MultiValues(claripy.BVV(1, 1))
            return MultiValues(self.state.top(1))

        return MultiValues(self.state.top(1))

    @binop_handler
    def _handle_binop_CmpNE(self, expr: pyvex.expr.Binop) -> MultiValues:
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return MultiValues(claripy.BVV(1, 1) if e0.concrete_value != e1.concrete_value else claripy.BVV(0, 1))
            if e0 is e1:
                return MultiValues(claripy.BVV(0, 1))
        return MultiValues(self.state.top(1))

    @binop_handler
    def _handle_binop_CmpLT(self, expr: pyvex.expr.Binop) -> MultiValues:
        arg0, arg1 = expr.args
        expr_0, expr_1 = self._expr_pair(arg0, arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                cmp = e0.concrete_value < e1.concrete_value  # type: ignore
                return MultiValues(claripy.BVV(1, 1) if cmp else claripy.BVV(0, 1))
            if e0 is e1:
                return MultiValues(claripy.BVV(0, 1))
        return MultiValues(self.state.top(1))

    @binop_handler
    def _handle_binop_CmpLE(self, expr: pyvex.expr.Binop) -> MultiValues:
        arg0, arg1 = expr.args
        expr_0, expr_1 = self._expr_pair(arg0, arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                cmp = e0.concrete_value <= e1.concrete_value  # type: ignore
                return MultiValues(claripy.BVV(1, 1) if cmp else claripy.BVV(0, 1))
            if e0 is e1:
                return MultiValues(claripy.BVV(0, 1))
        return MultiValues(self.state.top(1))

    @binop_handler
    def _handle_binop_CmpGT(self, expr: pyvex.expr.Binop) -> MultiValues:
        arg0, arg1 = expr.args
        expr_0, expr_1 = self._expr_pair(arg0, arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                cmp = e0.concrete_value > e1.concrete_value  # type: ignore
                return MultiValues(claripy.BVV(1, 1) if cmp else claripy.BVV(0, 1))
            if e0 is e1:
                return MultiValues(claripy.BVV(0, 1))
        return MultiValues(self.state.top(1))

    @binop_handler
    def _handle_binop_CmpGE(self, expr: pyvex.expr.Binop) -> MultiValues:
        arg0, arg1 = expr.args
        expr_0, expr_1 = self._expr_pair(arg0, arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                cmp = e0.concrete_value >= e1.concrete_value  # type: ignore
                return MultiValues(claripy.BVV(1, 1) if cmp else claripy.BVV(0, 1))
            if e0 is e1:
                return MultiValues(claripy.BVV(0, 1))
        return MultiValues(self.state.top(1))

    # ppc only
    @binop_handler
    def _handle_binop_CmpORD(self, expr: pyvex.expr.Binop) -> MultiValues:
        arg0, arg1 = expr.args
        expr_0, expr_1 = self._expr_pair(arg0, arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        bits = expr.result_size(self.tyenv)

        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                e0 = e0.concrete_value
                e1 = e1.concrete_value
                if e0 < e1:  # type: ignore
                    return MultiValues(claripy.BVV(0x8, bits))
                if e0 > e1:  # type: ignore
                    return MultiValues(claripy.BVV(0x4, bits))
                return MultiValues(claripy.BVV(0x2, bits))
            if e0 is e1:
                return MultiValues(claripy.BVV(0x2, bits))

        return MultiValues(self.state.top(1))

    def _handle_expr_CCall(self, expr) -> MultiValues[claripy.ast.BV | claripy.ast.FP]:
        bits = expr.result_size(self.tyenv)
        for arg_expr in expr.args:
            self._expr(arg_expr)
        return MultiValues(self.state.top(bits))

    def _handle_expr_GSPTR(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_expr_VECRET(self, expr):
        return self._top(expr.result_size(self.tyenv))

    #
    # User defined high level statement handlers
    #

    def _handle_function(self, func_addr: MultiValues[claripy.ast.BV] | None):
        if func_addr is None:
            func_addr = MultiValues(self.state.top(self.state.arch.bits))

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
