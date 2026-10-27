from __future__ import annotations

import logging
import operator
from collections.abc import Callable, Iterable
from itertools import chain
from typing import TYPE_CHECKING

import pyvex

from angr import claripy
from angr.claripy.vsa import mv_eval
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.engines.light import SimEngineNostmtVEX, SpOffset
from angr.engines.vex.claripy.datalayer import value_bv as claripy_value_bv
from angr.errors import SimEngineError, SimMemoryMissingError
from angr.knowledge_plugins.key_definitions.atoms import Atom, MemoryLocation, Register, Tmp
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.tag import LocalVariableTag, ParameterTag, Tag
from angr.utils.constants import DEFAULT_STATEMENT

from .function_handler import FunctionCallData
from .rd_state import ReachingDefinitionsState, shift_amount

if TYPE_CHECKING:
    from angr.knowledge_plugins import FunctionManager

    from .function_handler import FunctionHandler


l = logging.getLogger(name=__name__)

unop_handler = SimEngineNostmtVEX[ReachingDefinitionsState, claripy.ast.BV, ReachingDefinitionsState].unop_handler
binop_handler = SimEngineNostmtVEX[ReachingDefinitionsState, claripy.ast.BV, ReachingDefinitionsState].binop_handler


def _match_widths(expr0: claripy.ast.BV, expr1: claripy.ast.BV) -> tuple[claripy.ast.BV, claripy.ast.BV]:
    """
    Sign-extend the narrower operand to the width of the wider one.
    """
    if len(expr0) < len(expr1):
        return expr0.sign_extend(len(expr1) - len(expr0)), expr1
    if len(expr1) < len(expr0):
        return expr0, expr1.sign_extend(len(expr0) - len(expr1))
    return expr0, expr1


class SimEngineRDVEX(
    SimEngineNostmtVEX[ReachingDefinitionsState, claripy.ast.BV, ReachingDefinitionsState],
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
                raise
            l.error(e)
        return self.state

    def _process_block_end(self, stmt_result, whitelist):
        self.stmt_idx = DEFAULT_STATEMENT
        self._set_codeloc()

        function_handled = False
        if self.block.vex.jumpkind == "Ijk_Call" and self.block.vex.next is not None:
            # it has to be a function
            block_next = self.block.vex.next
            assert isinstance(block_next, pyvex.expr.IRExpr)
            addr = self._expr(block_next)
            self._handle_function(addr)
            function_handled = True
        elif self.block.vex.jumpkind == "Ijk_Boring" and self.block.vex.next is not None:
            # test if the target addr is a function or not
            block_next = self.block.vex.next
            assert isinstance(block_next, pyvex.expr.IRExpr)
            addr = self._expr(block_next)
            if addr.concrete:
                addr_int = addr.concrete_value
                if addr_int in self.functions:
                    # yes it's a jump to a function
                    self._handle_function(addr)
                    function_handled = True

        # take care of OP_AFTER during statement processing for function calls in a block
        if self.state.analysis and function_handled and self.block.vex.statements:
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
        Values with several alternatives are not really "top" in the stricter sense. They are just a collection of
        values,
        some of which might be top
        """
        return False

    def _top(self, bits) -> claripy.ast.BV:
        return self.state.top(bits)

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
        self.tmps[stmt.tmp] = data

        self.state.kill_and_add_definition(
            tmp_atom,
            data,
        )

    # e.g. PUT(rsp) = t2, t2 might include multiple values
    def _handle_stmt_Put(self, stmt):
        size: int = stmt.data.result_size(self.tyenv) // 8
        reg = Register(stmt.offset, size)
        data = self._expr(stmt.data)

        # special handling for references to heap or stack variables
        if (values := mv_eval(data)) is not None:
            for d in values:
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
        addr = self._expr(stmt.addr)
        size = stmt.data.result_size(self.tyenv) // 8
        data = self._expr(stmt.data)

        if (addrs := mv_eval(addr)) is not None:
            self._store_core(addrs, size, data, endness=stmt.endness)

    def _handle_stmt_StoreG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard.concrete and guard.concrete_value != 0:
            addr = self._expr(stmt.addr)
            if (addrs := mv_eval(addr)) is not None:
                size = stmt.data.result_size(self.tyenv) // 8
                data = self._expr(stmt.data)
                self._store_core(addrs, size, data)
        elif guard.concrete:
            pass
        else:
            # guard.data == {True, False}
            # get current data
            addr = self._expr(stmt.addr)
            if (addrs := mv_eval(addr)) is not None:
                size = stmt.data.result_size(self.tyenv) // 8
                data_old = self._load_core(addrs, size, stmt.endness)
                data = self._expr(stmt.data)

                self._store_core(addrs, size, data, data_old=data_old)

    def _store_core(
        self,
        addr: Iterable[int | claripy.ast.bv.BV],
        size: int,
        data: claripy.ast.BV,
        data_old: claripy.ast.BV | None = None,
        endness=None,
    ):
        if data_old is not None:
            data = claripy.union(data, data_old)

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
        guard = self._expr(stmt.guard)
        if guard.concrete and guard.concrete_value != 0:
            # FIXME: full conversion support
            if stmt.cvt.find("Ident") < 0:
                l.warning("Unsupported conversion %s in LoadG.", stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, load_expr)
            self._handle_stmt_WrTmp(wr_tmp_stmt)
        elif guard.concrete:
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, stmt.alt)
            self._handle_stmt_WrTmp(wr_tmp_stmt)
        else:
            if stmt.cvt.find("Ident") < 0:
                l.warning("Unsupported conversion %s in LoadG.", stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)

            load_expr_v = self._expr(load_expr)
            alt_v = self._expr(stmt.alt)

            data = claripy.union(load_expr_v, alt_v)
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
            addr = self._expr(stmt.addr)
            if (addrs := mv_eval(addr)) is not None:
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
            if (addrs := mv_eval(addr)) is not None:
                if isinstance(stmt.storedata, pyvex.expr.Const):
                    size = stmt.storedata.con.size // self.arch.byte_width
                else:
                    assert isinstance(stmt.storedata, pyvex.expr.RdTmp)
                    size = self.tyenv.sizeof(stmt.storedata.tmp) // self.arch.byte_width

                self._store_core(addrs, size, storedata)
                self.tmps[stmt.result] = claripy.BVV(1, 1)
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

        try:
            values: claripy.ast.BV = self.state.registers.load(expr.offset, size=size)
        except SimMemoryMissingError:
            # Define only the bytes that are missing. Redefining the whole register would clobber a narrower definition
            # that is already in place.
            for stride_start, stride_size in self._undefined_register_strides(expr.offset, size):
                stride_atom = Register(stride_start, stride_size)
                top = self.state.top(stride_size * self.arch.byte_width)
                top = self.state.annotate_with_def(top, Definition(stride_atom, self._external_codeloc()))
                self.state.kill_and_add_definition(stride_atom, top, override_codeloc=self._external_codeloc())
            values = self.state.registers.load(expr.offset, size=size)

        current_defs = self.state.extract_defs(values)
        # A read that covers bytes written by a narrower definition uses that definition too.
        # libVEX 3.27.1 lifts byte-register reads as a full-width GET plus a narrowing (e.g.,`mov dl, [m]; test dl, dl`
        # reads dl through `GET:I64(rdx)``). As such, the stored one byte should carry its own definition, but the
        # composed 8-byte value should not carry the definition of the one byte's.
        piece_defs = self.state.live_definitions.get_register_definitions(expr.offset, size)
        self.state.add_register_use_by_defs(chain(current_defs, piece_defs))

        return values

    def _undefined_register_strides(self, offset: int, size: int) -> list[tuple[int, int]]:
        """Contiguous strides of bytes defined in [offset, offset + size) that no definition covers."""
        strides: list[tuple[int, int]] = []
        for byte_off in range(offset, offset + size):
            try:
                self.state.registers.load(byte_off, size=1)
            except SimMemoryMissingError:
                if strides and strides[-1][0] + strides[-1][1] == byte_off:
                    strides[-1] = (strides[-1][0], strides[-1][1] + 1)
                else:
                    strides.append((byte_off, 1))
        return strides

    def _handle_expr_GetI(self, expr) -> claripy.ast.BV:
        return self.state.top(expr.result_size(self.tyenv))

    # e.g. t27 = LDle:I64(t9), t9 might include multiple values
    # caution: Is also called from StoreG
    def _handle_expr_Load(self, expr) -> claripy.ast.BV:
        addr = self._expr(expr.addr)
        bits = expr.result_size(self.tyenv)
        size = bits // self.arch.byte_width

        # load from every address
        if (addrs := mv_eval(addr)) is not None:
            return self._load_core(addrs, size, expr.endness)

        top = self.state.top(bits)
        # annotate it
        dummy_atom = MemoryLocation(0, size)
        def_ = Definition(dummy_atom, self._external_codeloc())
        top = self.state.annotate_with_def(top, def_)
        # add use
        self.state.add_memory_use_by_def(def_)
        return top

    def _load_core(self, addrs: Iterable[claripy.ast.BV], size: int, endness: str) -> claripy.ast.BV:
        result: claripy.ast.BV | None = None
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
                        vs: claripy.ast.BV = self.state.stack.load(stack_addr, size=size, endness=endness)
                        # extract definitions
                        defs = set(LiveDefinitions.extract_defs(vs))
                    except SimMemoryMissingError:
                        continue

                    self.state.add_stack_use_by_defs(defs)
                    result = claripy.union(result, vs) if result is not None else vs

            elif self.state.is_heap_address(addr):
                # Load data from the heap
                heap_offset = self.state.get_heap_offset(addr)
                if heap_offset is not None:
                    try:
                        vs: claripy.ast.BV = self.state.heap.load(heap_offset, size=size, endness=endness)
                        defs = set(LiveDefinitions.extract_defs(vs))
                    except SimMemoryMissingError:
                        continue

                    self.state.add_heap_use_by_defs(defs)
                    result = claripy.union(result, vs) if result is not None else vs

            else:
                addr_v = addr.concrete_value

                # Load data from a global region
                try:
                    vs: claripy.ast.BV = self.state.memory.load(addr_v, size=size, endness=endness)
                    defs = set(LiveDefinitions.extract_defs(vs))
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
                        vs = v
                        if not section or section.is_writable:
                            self.state.memory.store(addr_v, vs, size=size, endness=endness)
                            self.state.all_definitions.add(missing_def)
                        defs = {missing_def}
                    except KeyError:
                        continue

                self.state.add_memory_use_by_defs(defs)
                result = claripy.union(result, vs) if result is not None else vs

        if result is None:
            result = self.state.top(size * self.arch.byte_width)

        return result

    # CAUTION: experimental
    def _handle_expr_ITE(self, expr):
        cond = self._expr(expr.cond)
        iftrue = self._expr(expr.iftrue)
        iffalse = self._expr(expr.iffalse)

        if cond.concrete:
            return iftrue if cond.concrete_value else iffalse
        # Union both branches, but not without bound: a chain of ITEs (e.g., cmovs) doubles the set at every step.
        merged = claripy.union(iftrue, iffalse)
        values = mv_eval(merged)
        if values is None or len(values) > self.state._element_limit:
            return self._top(len(iftrue))
        return merged

    #
    # Unary operation handlers
    #

    def _handle_expr_Const(self, expr):
        clrp = claripy_value_bv(expr.con.type, expr.con.value, size=expr.con.size)
        self.state.mark_const(expr.con.value, len(clrp) // 8)
        return clrp

    def _handle_conversion(self, from_size, to_size, signed, operand) -> claripy.ast.BV:
        arg_0 = self._expr(operand)

        # convert each alternative; a value made of several pieces is TOP

        if (arg_values := mv_eval(arg_0)) is not None:
            # extension, extract, or doing nothing
            data: set[claripy.ast.BV] = set()
            for v in arg_values:
                assert v.size() == from_size
                if to_size > from_size:
                    if signed:
                        data.add(v.sign_extend(to_size - from_size))
                    else:
                        data.add(v.zero_extend(to_size - from_size))
                else:
                    data.add(v[to_size - 1 : 0])
            r = claripy.union(*data)

        else:
            r = self._top(to_size)

        return r

    @unop_handler
    def _handle_unop_Not(self, expr: pyvex.expr.Unop) -> claripy.ast.BV:
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)
        bits = expr.result_size(self.tyenv)

        if expr_0.concrete:
            return ~expr_0

        return self.state.top(bits)

    @unop_handler
    def _handle_unop_Clz(self, expr: pyvex.expr.Unop) -> claripy.ast.BV:
        arg0 = expr.args[0]
        _ = self._expr(arg0)
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        return self.state.top(bits)

    @unop_handler
    def _handle_unop_Ctz(self, expr: pyvex.expr.Unop) -> claripy.ast.BV:
        arg0 = expr.args[0]
        _ = self._expr(arg0)
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        return self.state.top(bits)

    #
    # Binary operation handlers
    #
    @binop_handler
    def _handle_binop_ExpCmpNE64(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)
        # Need to actually implement this later
        return self.state.top(bits)

    @binop_handler
    def _handle_binop_16HLto32(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        return expr0.concat(expr1)

    @binop_handler
    def _handle_binop_Add(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        expr0, expr1 = _match_widths(self._expr(expr.args[0]), self._expr(expr.args[1]))
        return self.state.bounded(expr0 + expr1, expr0, expr1)

    @binop_handler
    def _handle_binop_Sub(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        return self.state.bounded(expr0 - expr1, expr0, expr1)

    @binop_handler
    def _handle_binop_Mul(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        return self.state.bounded(expr0 * expr1, expr0, expr1)

    @binop_handler
    def _handle_binop_Mull(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)
        return self.state.top(bits)

    @binop_handler
    def _handle_binop_Div(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)
        # divide by constants, leaving out zero
        divisors = None if expr1.variables else mv_eval(expr1)
        nonzero = [d for d in divisors if d.concrete_value != 0] if divisors is not None else []
        if not nonzero:
            return self.state.top(bits)
        return self.state.bounded(expr0 / claripy.union(*nonzero), expr0, expr1)

    @binop_handler
    def _handle_binop_DivMod(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        return self.state.top(bits)

    @binop_handler
    def _handle_Mod(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)
        return self.state.top(bits)

    @binop_handler
    def _handle_binop_And(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        return self.state.bounded(expr0 & expr1, expr0, expr1)

    @binop_handler
    def _handle_binop_Xor(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        expr0, expr1 = _match_widths(self._expr(expr.args[0]), self._expr(expr.args[1]))
        return self.state.bounded(expr0 ^ expr1, expr0, expr1)

    @binop_handler
    def _handle_binop_Or(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        return self.state.bounded(expr0 | expr1, expr0, expr1)

    def _shift(self, expr: pyvex.expr.Binop, op: Callable[[claripy.ast.BV, claripy.ast.BV], claripy.ast.BV]):
        """
        Shift by constants; the amount is resized to the width of the shifted value.
        """
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        amount = None if expr1.variables else shift_amount(expr1, len(expr0))
        if amount is None:
            return self.state.top(expr.result_size(self.tyenv))
        return self.state.bounded(op(expr0, amount), expr0, expr1)

    @binop_handler
    def _handle_binop_Sar(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        return self._shift(expr, operator.rshift)

    @binop_handler
    def _handle_binop_Shr(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        return self._shift(expr, claripy.LShR)

    @binop_handler
    def _handle_binop_Shl(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        return self._shift(expr, operator.lshift)

    @binop_handler
    def _handle_binop_CmpEQ(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0.concrete and expr_1.concrete:
            return claripy.BVV(1, 1) if expr_0.concrete_value == expr_1.concrete_value else claripy.BVV(0, 1)
        if expr_0 is expr_1:
            return claripy.BVV(1, 1)
        return self.state.top(1)

    @binop_handler
    def _handle_binop_CmpNE(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0.concrete and expr_1.concrete:
            return claripy.BVV(1, 1) if expr_0.concrete_value != expr_1.concrete_value else claripy.BVV(0, 1)
        if expr_0 is expr_1:
            return claripy.BVV(0, 1)
        return self.state.top(1)

    @binop_handler
    def _handle_binop_CmpLT(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        arg0, arg1 = expr.args
        expr_0, expr_1 = self._expr(arg0), self._expr(arg1)

        if expr_0.concrete and expr_1.concrete:
            cmp = expr_0.concrete_value < expr_1.concrete_value  # type: ignore
            return claripy.BVV(1, 1) if cmp else claripy.BVV(0, 1)
        if expr_0 is expr_1:
            return claripy.BVV(0, 1)
        return self.state.top(1)

    @binop_handler
    def _handle_binop_CmpLE(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        arg0, arg1 = expr.args
        expr_0, expr_1 = self._expr(arg0), self._expr(arg1)

        if expr_0.concrete and expr_1.concrete:
            cmp = expr_0.concrete_value <= expr_1.concrete_value  # type: ignore
            return claripy.BVV(1, 1) if cmp else claripy.BVV(0, 1)
        if expr_0 is expr_1:
            return claripy.BVV(0, 1)
        return self.state.top(1)

    @binop_handler
    def _handle_binop_CmpGT(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        arg0, arg1 = expr.args
        expr_0, expr_1 = self._expr(arg0), self._expr(arg1)

        if expr_0.concrete and expr_1.concrete:
            cmp = expr_0.concrete_value > expr_1.concrete_value  # type: ignore
            return claripy.BVV(1, 1) if cmp else claripy.BVV(0, 1)
        if expr_0 is expr_1:
            return claripy.BVV(0, 1)
        return self.state.top(1)

    @binop_handler
    def _handle_binop_CmpGE(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        arg0, arg1 = expr.args
        expr_0, expr_1 = self._expr(arg0), self._expr(arg1)

        if expr_0.concrete and expr_1.concrete:
            cmp = expr_0.concrete_value >= expr_1.concrete_value  # type: ignore
            return claripy.BVV(1, 1) if cmp else claripy.BVV(0, 1)
        if expr_0 is expr_1:
            return claripy.BVV(0, 1)
        return self.state.top(1)

    # ppc only
    @binop_handler
    def _handle_binop_CmpORD(self, expr: pyvex.expr.Binop) -> claripy.ast.BV:
        arg0, arg1 = expr.args
        expr_0, expr_1 = self._expr(arg0), self._expr(arg1)

        bits = expr.result_size(self.tyenv)

        if expr_0.concrete and expr_1.concrete:
            e0 = expr_0.concrete_value
            e1 = expr_1.concrete_value
            if e0 < e1:  # type: ignore
                return claripy.BVV(0x8, bits)
            if e0 > e1:  # type: ignore
                return claripy.BVV(0x4, bits)
            return claripy.BVV(0x2, bits)
        if expr_0 is expr_1:
            return claripy.BVV(0x2, bits)

        return self.state.top(bits)

    def _handle_expr_CCall(self, expr) -> claripy.ast.BV:
        bits = expr.result_size(self.tyenv)
        for arg_expr in expr.args:
            self._expr(arg_expr)
        return self.state.top(bits)

    def _handle_expr_GSPTR(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_expr_VECRET(self, expr):
        return self._top(expr.result_size(self.tyenv))

    #
    # User defined high level statement handlers
    #

    def _handle_function(self, func_addr: claripy.ast.BV | None):
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
