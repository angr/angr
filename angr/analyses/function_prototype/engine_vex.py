from typing import TYPE_CHECKING, Optional, Set, Any
import logging

from ...knowledge_plugins.key_definitions.atoms import Register, MemoryLocation
from ...engines.light import SimEngineLight, SimEngineLightVEXMixin, SpOffset
from ...engines.vex.claripy.irop import operations as vex_operations
from .domain import (ValuedVariable, LocalVariable, Constant, Add, AddN, Assignment, Load, Store, CmpLtExpr, CmpLeExpr,
                     CmpLtN)

if TYPE_CHECKING:
    from pyvex import IRExpr, IRStmt
    from angr import Project
    from .base_state import FunctionPrototypeAnalysisState


_l = logging.getLogger(name=__name__)


class SimEngineFunctionPrototypeVEX(
    SimEngineLightVEXMixin,
    SimEngineLight,
):
    def __init__(self, project: 'Project'):
        super().__init__()
        self.project = project

        self.state: 'FunctionPrototypeAnalysisState' = None

    def process(self, state, *args, **kwargs):
        super().process(state, *args, **kwargs)
        return state

    #
    # Statement handlers
    #

    def _handle_Put(self, stmt: 'IRStmt.Put'):
        data_set: Optional[Set[Any]] = self._expr(stmt.data)
        if data_set:
            size = stmt.data.result_size(self.tyenv) // self.arch.byte_width
            for i, data in enumerate(data_set):
                self._Put(stmt, data, size, is_set=i == 0)

    def _Put(self, stmt: 'IRStmt.Put', data: Any, size: int, is_set=False):
        if isinstance(data, ValuedVariable):
            data_expr = data.variable
            data_value = data.value
        else:
            data_expr = None
            data_value = data
        local_var = LocalVariable(Register(stmt.offset, size), self._codeloc())
        # create constraint
        if data_expr is not None:
            self.state.constraints.add(Assignment(local_var, data_expr))
        new_data = ValuedVariable(local_var, data_value)
        if is_set:
            self.state.registers.set_object(stmt.offset, new_data, size)
        else:
            self.state.registers.add_object(stmt.offset, new_data, size)

    def _handle_Store(self, stmt: 'IRStmt.Store') -> None:
        addrs: Optional[Set[ValuedVariable]] = self._expr(stmt.addr)
        data_set: Optional[Set[ValuedVariable]] = self._expr(stmt.data)

        if addrs:
            if not data_set:
                data_set = {None}
            cleared_addrs = set()
            for addr in addrs:
                for data in data_set:
                    self._Store(stmt, addr, data, cleared_addrs)

    def _Store(self, stmt: 'IRStmt.Store', addr: Optional[ValuedVariable], data: Any, cleared_addrs):
        if addr is not None and data is not None:
            addr_var, addr_value = addr.variable, addr.value
            if isinstance(data, ValuedVariable):
                data_expr, data_value = data.variable, data.value
            else:
                data_expr = None
                data_value = data
            if isinstance(addr_value, SpOffset) and isinstance(addr_value.offset, int) and data is not None:
                size = stmt.data.result_size(self.tyenv) // self.arch.byte_width
                local_var = LocalVariable(MemoryLocation(addr_value, addr_value.bits // 8), self._codeloc())
                # create constraint
                if data_expr is not None:
                    con = Assignment(local_var, data_expr)
                    self.state.constraints.add(con)
                elif isinstance(data, int):
                    con = Assignment(local_var, Constant(data))
                    self.state.constraints.add(con)
                # write to stack
                if addr_value.offset not in cleared_addrs:
                    # strong update
                    self.state.stack.set_object(addr_value.offset,
                                                ValuedVariable(local_var, data_value),
                                                size)
                    cleared_addrs.add(addr_value.offset)
                else:
                    # weak update
                    self.state.stack.add_object(addr_value.offset,
                                                ValuedVariable(local_var, data_value),
                                                size)
                return

        # create constraints
        if addr is not None and addr.variable is not None:
            size = stmt.data.result_size(self.tyenv) // self.arch.byte_width
            con = Store(addr.variable, size)
            self.state.constraints.add(con)

    #
    # Expression handlers
    #

    def _expr(self, expr) -> Optional[Set[ValuedVariable]]:
        r = super()._expr(expr)

        # Resilience: Drop all values that are returned by handlers that we don't implement in this engine
        if not isinstance(r, set):
            return None
        # TODO: Limit cardinality

        return r

    def _handle_Get(self, expr: 'IRExpr.Get'):
        objs = self.state.registers.get_objects_by_offset(expr.offset)
        if objs:
            return objs
        return None

    def _handle_Load(self, expr: 'IRExpr.Load'):
        addrs: Optional[Set[ValuedVariable]] = self._expr(expr.addr)
        size = expr.result_size(self.tyenv) // self.arch.byte_width
        results = set()

        if addrs is not None:
            for addr in addrs:
                r = self._Load(addr, size)
                if r is not None:
                    results |= r

        return None if not results else results

    def _Load(self, addr, size) -> Optional[Set[ValuedVariable]]:
        addr_var, addr_value = addr.variable, addr.value
        if isinstance(addr_value, SpOffset) and isinstance(addr_value.offset, int):
            # load from stack
            objs = self.state.stack.get_objects_by_offset(addr_value.offset)
            if objs:
                return objs
            return None

        # create constraints
        if addr is not None:
            con = Load(addr.variable, size)
            self.state.constraints.add(con)

    def _handle_Conversion(self, expr: 'IRExpr.Binop'):
        simop = vex_operations[expr.op]
        arg_0: Optional[Set[ValuedVariable]] = self._expr(expr.args[0])
        bits = int(simop.op_attrs['to_size'])

        if arg_0 is None:
            return None
        return {a for a in arg_0}

    def _handle_CmpLT(self, expr):
        arg0s = self._expr(expr.args[0])
        arg1s = self._expr(expr.args[1])

        if arg0s and arg1s:
            for arg0 in arg0s:
                for arg1 in arg1s:
                    self._CmpLT(arg0, arg1)
        return None

    def _CmpLT(self, arg0, arg1):
        if isinstance(arg0, ValuedVariable):
            arg0_var, arg0_value = arg0.variable, arg0.value
            if isinstance(arg1, int):
                con = CmpLtN(arg0_var, arg1)
                self.state.constraints.add(con)
            elif isinstance(arg1, ValuedVariable) and arg1.variable is not None:
                con = CmpLtExpr(arg0_var, arg1.variable)
                self.state.constraints.add(con)

    def _handle_CmpLE(self, expr) -> Optional[ValuedVariable]:
        arg0s = self._expr(expr.args[0])
        arg1s = self._expr(expr.args[1])

        if arg0s and arg1s:
            for arg0 in arg0s:
                for arg1 in arg1s:
                    self._CmpLE(arg0, arg1)
        return None

    def _CmpLE(self, arg0, arg1):
        if isinstance(arg0, ValuedVariable):
            arg0_var, arg0_value = arg0.variable, arg0.value
            if isinstance(arg1, int):
                con = CmpLtN(arg0_var, arg1 + 1)
                self.state.constraints.add(con)
            elif isinstance(arg1, ValuedVariable) and arg1.variable is not None:
                con = CmpLeExpr(arg0_var, arg1.variable)
                self.state.constraints.add(con)

    def _handle_Add(self, expr: 'IRExpr.Binop') -> Optional[ValuedVariable]:
        arg0s = self._expr(expr.args[0])
        arg1s = self._expr(expr.args[1])
        results = set()

        if arg0s and arg1s:
            for arg0 in arg0s:
                for arg1 in arg1s:
                    r = self._Add(arg0, arg1)
                    if r is not None:
                        results.add(r)

        return None if not results else results

    def _Add(self, arg0, arg1) -> Optional[ValuedVariable]:
        if isinstance(arg0, ValuedVariable):
            if isinstance(arg1, int):
                # AddN
                add_expr = AddN(arg0.variable, self._to_signed(arg1))
                if isinstance(arg0.value, int):
                    mask = (1 << self.arch.bits) - 1
                    return ValuedVariable(add_expr,
                                          (arg0.value + arg1) & mask)
                elif isinstance(arg0.value, SpOffset):
                    return ValuedVariable(add_expr,
                                          SpOffset(arg0.value.bits, arg0.value.offset + self._to_signed(arg1)))
                else:
                    return ValuedVariable(add_expr, None)
            else:
                if isinstance(arg1, ValuedVariable):
                    # Add
                    add_expr = Add(arg0.variable, arg1.variable)
                    return ValuedVariable(add_expr, None)
        return None

    def _handle_U32(self, expr):
        return { expr.value }

    def _handle_U64(self, expr):
        return { expr.value }

    def _handle_U16(self, expr):
        return { expr.value }

    def _handle_U8(self, expr):
        return { expr.value }

    def _handle_U1(self, expr):
        return { expr.value }

    def _handle_Const(self, expr: 'IRExpr.Const'):
        return { expr.con.value }

    #
    # Static methods
    #

    def _to_signed(self, n) -> int:
        if n >= 2 ** (self.arch.bits - 1):
            # convert it to a negative number
            return n - 2 ** self.arch.bits
        return n
