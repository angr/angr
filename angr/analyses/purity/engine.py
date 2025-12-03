from __future__ import annotations

# pylint: disable=arguments-differ,arguments-renamed

from typing import Any, TypeAlias
from collections.abc import Callable, MutableMapping
from collections import defaultdict
from dataclasses import dataclass, field
from typing_extensions import Self

import angr
from angr.engines.light import SimEngineLightAIL
from angr import ailment
from angr.knowledge_plugins.functions.function import Function


@dataclass
class DataUsage:
    """
    Facts about a given data source
    """

    ptr_load: bool = False
    ptr_store: bool = False

    def __or__(self, other):
        return DataUsage(
            ptr_load=self.ptr_load | other.ptr_load,
            ptr_store=self.ptr_store | other.ptr_store,
        )

    def __ior__(self, other):
        self.ptr_load |= other.ptr_load
        self.ptr_store |= other.ptr_store
        return self


@dataclass(frozen=True)
class DataSource:
    """
    Descriptor of a given data source: where did this value come from?
    """

    constant_value: int | None = None
    function_arg: int | None = None
    callee_return: Function | str | None = None
    reference_to: int | None = None

    @property
    def callee_return_name(self) -> str | None:
        if self.callee_return is None:
            return None
        if isinstance(self.callee_return, Function):
            return self.callee_return.name
        return self.callee_return


@dataclass
class StateType:
    """
    Internal state for purity analysis
    """

    addr: tuple[int, int | None]
    vars: MutableMapping[int, DataType_co]

    def copy(self):
        return StateType(
            addr=self.addr,
            vars=defaultdict(frozenset, self.vars),
        )


@dataclass
class ResultType:
    """
    Result of purity analysis - how was each data source used and what function calls arguments were passed?
    """

    uses: MutableMapping[DataSource, DataUsage] = field(default_factory=lambda: defaultdict(DataUsage))
    # keyed as: block addr, block idx, stmt idx, call target, call arg idx
    call_args: MutableMapping[tuple[int, int | None, int, Function | str | None, int], DataType_co] = field(
        default_factory=lambda: defaultdict(frozenset)
    )
    ret_vals: MutableMapping[int, DataType_co] = field(default_factory=lambda: defaultdict(frozenset))
    other_storage: MutableMapping[DataSource, DataType_co] = field(default_factory=lambda: defaultdict(frozenset))

    def update(self, other: Self):
        for src, use in other.uses.items():
            self.uses[src] |= use
        for arg, val in other.call_args.items():
            self.call_args[arg] |= val
        for arg, val in other.ret_vals.items():
            self.ret_vals[arg] |= val
        for arg, val in other.other_storage.items():
            self.other_storage[arg] |= val

    def is_pure(
        self,
        pure_functions: set[str] | None = None,
        allow_read_arguments: bool = True,
        allow_write_arguments: bool = False,
        allow_read_globals: bool = True,
        allow_write_globals: bool = False,
    ) -> bool:
        for loc, use in self.uses.items():
            if loc.constant_value is not None and use.ptr_store and not allow_write_globals:
                return False
            if loc.constant_value is not None and use.ptr_load and not allow_read_globals:
                return False
            if loc.function_arg is not None and use.ptr_store and not allow_write_arguments:
                return False
            if loc.function_arg is not None and use.ptr_load and not allow_read_arguments:
                return False
            if loc.callee_return is not None and (
                pure_functions is None or loc.callee_return_name not in pure_functions
            ):
                return False
        for (_, _, _, func, _), _ in self.call_args.items():
            if pure_functions is None:
                return False
            if isinstance(func, Function) and func.name not in pure_functions:
                return False
            if func not in pure_functions:
                return False
        return True


DataType_co: TypeAlias = frozenset[DataSource]
StmtDataType: TypeAlias = None


class PurityEngineAIL(SimEngineLightAIL[StateType, DataType_co, StmtDataType, ResultType]):
    """
    Core of this analysis: THIS data source has THESE uses.

    A use is arithmetic, store, or load.
    """

    def __init__(
        self, project: angr.Project, clinic: angr.analyses.decompiler.Clinic, recurse: Callable[[Function], ResultType]
    ):
        self.clinic = clinic
        self.result = ResultType()
        self.recurse = recurse
        super().__init__(project)

    def initial_state(self, node: ailment.Block):
        assert self.clinic.arg_vvars is not None
        return StateType(
            addr=(node.addr, node.idx),
            vars=defaultdict(
                frozenset,
                (
                    (vvar.varid, frozenset((DataSource(function_arg=idx),)))
                    for idx, (vvar, _) in self.clinic.arg_vvars.items()
                ),
            ),
        )

    def _top(self, bits):
        return frozenset()

    def _is_top(self, expr):
        return expr == frozenset()

    def _expr_single(self, expr: ailment.Expression) -> DataSource:
        result = self._expr(expr)
        if len(result) == 1:
            return next(iter(result))
        return DataSource()

    def _expr_noconst(self, expr: ailment.Expression) -> DataType_co:
        return frozenset(x for x in self._expr(expr) if x.constant_value is None)

    def process(
        self, state: StateType, *, block: ailment.Block | None = None, whitelist: set[int] | None = None, **kwargs
    ) -> ResultType:
        self.tmps = {}
        self.result = ResultType()
        return super().process(state, block=block, whitelist=whitelist, **kwargs)

    def _process_block_end(
        self, block: ailment.Block, stmt_data: list[StmtDataType], whitelist: set[int] | None
    ) -> ResultType:
        return self.result

    def _do_assign(self, dst: ailment.Expression, val: DataType_co):
        match dst:
            case ailment.expression.VirtualVariable():
                self.state.vars[dst.varid] = val
            case ailment.expression.Tmp():
                self.tmps[dst.tmp_idx] = val
            case _:
                raise NotImplementedError

    def _handle_stmt_Assignment(self, stmt: ailment.statement.Assignment) -> StmtDataType:
        if isinstance(stmt.src, ailment.expression.Phi):
            # handled by the analysis layer
            return
        val = self._expr(stmt.src)
        self._do_assign(stmt.dst, val)

    def _handle_stmt_CAS(self, stmt: ailment.statement.CAS) -> StmtDataType:
        raise NotImplementedError

    def _handle_stmt_WeakAssignment(self, stmt: ailment.statement.WeakAssignment) -> StmtDataType:
        raise NotImplementedError

    def _do_store(self, ptr: DataType_co, val: DataType_co):
        for src in ptr:
            if src.reference_to is not None:
                self.state.vars[src.reference_to] = val
            elif self._is_valid_pointer(src):
                self.result.uses[src].ptr_store = True
                if val:
                    self.result.other_storage[src] |= val

    def _handle_stmt_Store(self, stmt: ailment.statement.Store) -> StmtDataType:
        val = self._expr(stmt.data)
        ptr = self._expr(stmt.addr)
        self._do_store(ptr, val)

    def _handle_stmt_Jump(self, stmt: ailment.statement.Jump) -> StmtDataType:
        self._expr_single(stmt.target)

    def _handle_stmt_ConditionalJump(self, stmt: ailment.statement.ConditionalJump) -> StmtDataType:
        self._expr(stmt.condition)
        if stmt.true_target is not None:
            self._expr_single(stmt.true_target)
        if stmt.false_target is not None:
            self._expr_single(stmt.false_target)

    def _handle_stmt_Call(self, stmt: ailment.statement.Call) -> StmtDataType:
        results = self._do_call(stmt)
        if stmt.ret_expr is not None:
            assert 0 in results
            self._do_assign(stmt.ret_expr, results[0])
        if stmt.fp_ret_expr is not None:
            assert 0 in results
            self._do_assign(stmt.fp_ret_expr, results[0])

    def _handle_stmt_Return(self, stmt: ailment.statement.Return) -> StmtDataType:
        for i, expr in enumerate(stmt.ret_exprs):
            r = self._expr(expr)
            self.result.ret_vals[i] |= r

    def _handle_stmt_DirtyStatement(self, stmt: ailment.statement.DirtyStatement) -> StmtDataType:
        self._expr(stmt.dirty)

    def _handle_stmt_Label(self, stmt: ailment.statement.Label) -> StmtDataType:
        pass

    def _handle_expr_Const(self, expr: ailment.expression.Const) -> DataType_co:
        if isinstance(expr.value, int):
            return frozenset((DataSource(constant_value=expr.value),))
        return self._top(expr.bits)

    def _handle_expr_Tmp(self, expr: ailment.expression.Tmp) -> DataType_co:
        return self.tmps[expr.tmp_idx]

    def _handle_expr_VirtualVariable(self, expr: ailment.expression.VirtualVariable) -> DataType_co:
        # allow registers to be uninitialized since callee-save is a thing
        assert (
            self.clinic.function.name == "_security_check_cookie"
            or expr.category == ailment.expression.VirtualVariableCategory.REGISTER
            or expr.varid in self.state.vars
        )
        return self.state.vars[expr.varid]

    def _handle_expr_Phi(self, expr: ailment.expression.Phi) -> DataType_co:
        assert False, "Unreachable"

    def _handle_expr_Convert(self, expr):
        return frozenset(x for x in self._expr(expr.operand) if x.constant_value is not None)

    def _handle_expr_Reinterpret(self, expr: ailment.expression.Reinterpret) -> DataType_co:
        return self._expr(expr.operand)

    def _is_valid_pointer(self, src: DataSource) -> bool:
        return not (
            src.constant_value is not None and self.project.loader.find_object_containing(src.constant_value) is None
        )

    def _do_load(self, ptr: DataType_co) -> DataType_co:
        result: list[DataSource] = []
        for src in ptr:
            if src.reference_to is not None:
                result.extend(self.state.vars[src.reference_to])
            elif self._is_valid_pointer(src):
                self.result.uses[src].ptr_load = True
                if src.constant_value is None:
                    result.append(src)
        return frozenset(result)

    def _handle_expr_Load(self, expr: ailment.expression.Load) -> DataType_co:
        return self._do_load(self._expr(expr.addr))

    def _handle_expr_Register(self, expr: ailment.expression.Register) -> DataType_co:
        return self._top(expr.bits)

    def _handle_expr_ITE(self, expr: ailment.expression.ITE) -> DataType_co:
        self._expr(expr.condition)
        return self._expr(expr.iftrue) | self._expr(expr.iffalse)

    def _do_call(self, expr: ailment.statement.Call, is_expr: bool = False) -> MutableMapping[int, DataType_co]:
        args = [self._expr(arg) for arg in expr.args or []]
        seen = None

        if isinstance(expr.target, ailment.Expression):
            target = self._expr_single(expr.target)
            func = None
            if target.constant_value:
                func = self.clinic.project.kb.functions[target.constant_value]
                if not func.is_plt and not func.is_simprocedure:
                    seen = ResultType() if func.name == "_security_check_cookie" else self.recurse(func)
        elif isinstance(expr.target, str):
            # pure functions
            func = expr.target
            seen = None
        else:
            raise TypeError(f"Unexpected call target type {type(expr.target)}")

        if seen is not None:

            def subst(v: DataSource) -> DataType_co:
                if v.function_arg is not None:
                    return args[v.function_arg]
                if v.reference_to is not None:
                    return frozenset()
                return frozenset((v,))

            def substall(v: DataType_co) -> DataType_co:
                result = []
                for vv in v:
                    result.extend(subst(vv))
                return frozenset(result)

            for srcs, val in seen.other_storage.items():
                if not val:
                    continue
                self._do_store(subst(srcs), substall(val))
            for srcs, kind in seen.uses.items():
                for src in subst(srcs):
                    self.result.uses[src] |= kind
            for callsite, vals in seen.call_args.items():
                self.result.call_args[callsite] |= substall(vals)

            return {i: substall(v) for i, v in seen.ret_vals.items()}
        for i, val in enumerate(args):
            self.result.call_args[(self.block.addr, self.block.idx, self.stmt_idx, func, i)] |= val
        # ummmm need to rearrange data model
        return {
            idx: frozenset((DataSource(callee_return=func),))
            for idx in range(0 if expr.ret_expr is None and not is_expr else 1)
        }

    def _handle_expr_Call(self, expr: ailment.statement.Call) -> DataType_co:
        r = self._do_call(expr, is_expr=True)
        assert 0 in r
        return r[0]

    def _handle_expr_DirtyExpression(self, expr: ailment.expression.DirtyExpression) -> DataType_co:
        for arg in expr.operands:
            self._expr(arg)
        return self._top(expr.bits)

    def _handle_expr_VEXCCallExpression(self, expr: ailment.expression.VEXCCallExpression) -> DataType_co:
        for arg in expr.operands:
            self._expr(arg)
        return self._top(expr.bits)

    def _handle_expr_MultiStatementExpression(self, expr: ailment.expression.MultiStatementExpression) -> DataType_co:
        for stmt in expr.stmts:
            self._stmt(stmt)
        return self._expr(expr.expr)

    def _handle_expr_BasePointerOffset(self, expr: ailment.expression.BasePointerOffset) -> DataType_co:
        return self._top(expr.bits)

    def _handle_expr_StackBaseOffset(self, expr: ailment.expression.StackBaseOffset) -> DataType_co:
        return self._top(expr.bits)

    @staticmethod
    def __concrete_unop(f: Callable[[Any, int], int]):
        def inner(self, expr: ailment.expression.UnaryOp) -> DataType_co:
            arg = self._expr(expr.operand)
            result = []
            for src in arg:
                if src.constant_value is not None:
                    result.append(DataSource(constant_value=f(self, src.constant_value)))
                # see similar commented code in __concrete_binop
                # else:
                #     result.append(src)
            return frozenset(result)

        return inner

    @__concrete_unop
    def _handle_unop_Not(self, v):
        return int(not v)

    @__concrete_unop
    def _handle_unop_Neg(self, v):
        return -v

    @__concrete_unop
    def _handle_unop_BitwiseNeg(self, v):
        return ~v

    def _handle_unop_Reference(self, expr: ailment.expression.UnaryOp) -> DataType_co:
        assert isinstance(expr.operand, ailment.expression.VirtualVariable)
        return frozenset((DataSource(reference_to=expr.operand.varid),))

    def _handle_unop_Dereference(self, expr: ailment.expression.UnaryOp) -> DataType_co:
        return self._do_load(self._expr(expr.addr))

    def _handle_unop_default(self, expr: ailment.Expression) -> DataType_co:
        return self._expr_noconst(expr.operand)

    _handle_unop_Clz = _handle_unop_default
    _handle_unop_Ctz = _handle_unop_default
    _handle_unop_GetMSBs = _handle_unop_default
    _handle_unop_unpack = _handle_unop_default
    _handle_unop_Sqrt = _handle_unop_default
    _handle_unop_RSqrtEst = _handle_unop_default

    @staticmethod
    def __concrete_binop(f: Callable[[Any, int, int], int | None]):
        def inner(self, expr: ailment.expression.BinaryOp) -> DataType_co:
            arg0 = self._expr(expr.operands[0])
            arg1 = self._expr(expr.operands[1])
            arg0c: list[int] = []
            arg1c: list[int] = []
            result = []
            for arg, argc in ((arg0, arg0c), (arg1, arg1c)):
                for src in arg:
                    if src.constant_value is not None:
                        argc.append(src.constant_value)
                    # this line is weird because it basically means "you can compute however you like with a source
                    # and it will come out with the same taints as before"
                    # preliminary testing indicates this is not desired
                    # else:
                    #     result.append(src)
            if len(arg0c) * len(arg1c) <= 10:  # arbitrary limit
                for c0 in arg0c:
                    for c1 in arg1c:
                        try:
                            m = f(self, c0, c1)
                        except ZeroDivisionError:
                            pass
                        else:
                            if m is None:
                                continue
                            result.append(DataSource(constant_value=m % 2**expr.bits))

            return frozenset(result)

        return inner

    def _handle_binop_Add(self, expr: ailment.expression.BinaryOp) -> DataType_co:
        r = self._handle_binop_Add_basic(expr)  # pylint: disable=no-value-for-parameter
        arg0 = self._expr(expr.operands[0])
        arg1 = self._expr(expr.operands[1])
        return r | arg0 | arg1

    def _handle_binop_Sub(self, expr: ailment.expression.BinaryOp) -> DataType_co:
        r = self._handle_binop_Sub_basic(expr)  # pylint: disable=no-value-for-parameter
        arg0 = self._expr(expr.operands[0])
        return r | arg0

    @__concrete_binop
    def _handle_binop_Add_basic(self, a, b):  # pylint: disable=no-self-use
        return a + b

    @__concrete_binop
    def _handle_binop_Sub_basic(self, a, b):  # pylint: disable=no-self-use
        return a - b

    @__concrete_binop
    def _handle_binop_Mul(self, a, b):
        return a * b

    @__concrete_binop
    def _handle_binop_Div(self, a, b):
        return a // b

    @__concrete_binop
    def _handle_binop_Mod(self, a, b):
        return a % b

    @__concrete_binop
    def _handle_binop_And(self, a, b):
        return a & b

    @__concrete_binop
    def _handle_binop_Or(self, a, b):
        return a | b

    @__concrete_binop
    def _handle_binop_Xor(self, a, b):
        return a ^ b

    @__concrete_binop
    def _handle_binop_Shl(self, a, b):
        return a << b

    @__concrete_binop
    def _handle_binop_Shr(self, a, b):
        return a >> b

    @__concrete_binop
    def _handle_binop_Sar(self, a, b):
        return a >> b

    @__concrete_binop
    def _handle_binop_LogicalAnd(self, a, b):
        return a and b

    @__concrete_binop
    def _handle_binop_LogicalOr(self, a, b):
        return a or b

    @__concrete_binop
    def _handle_binop_CmpEQ(self, a, b):
        return int(a == b)

    @__concrete_binop
    def _handle_binop_CmpNE(self, a, b):
        return int(a != b)

    @__concrete_binop
    def _handle_binop_CmpLT(self, a, b):
        return int(a < b)

    @__concrete_binop
    def _handle_binop_CmpLE(self, a, b):
        return int(a <= b)

    @__concrete_binop
    def _handle_binop_CmpGT(self, a, b):
        return int(a > b)

    @__concrete_binop
    def _handle_binop_CmpGE(self, a, b):
        return int(a >= b)

    @__concrete_binop
    def _handle_binop_Concat(self, a, b):
        if a == 0:
            return b
        return None

    def _handle_binop_default(self, expr: ailment.expression.BinaryOp) -> DataType_co:
        return self._expr_noconst(expr.operands[0]) | self._expr_noconst(expr.operands[1])

    _handle_binop_AddF = _handle_binop_default
    _handle_binop_AddV = _handle_binop_default
    _handle_binop_SubF = _handle_binop_default
    _handle_binop_SubV = _handle_binop_default
    _handle_binop_Mull = _handle_binop_default
    _handle_binop_MulF = _handle_binop_default
    _handle_binop_MulHiV = _handle_binop_default
    _handle_binop_MulV = _handle_binop_default
    _handle_binop_DivF = _handle_binop_default
    _handle_binop_DivV = _handle_binop_default
    _handle_binop_CmpF = _handle_binop_default
    _handle_binop_CmpORD = _handle_binop_default
    _handle_binop_Ror = _handle_binop_default
    _handle_binop_Rol = _handle_binop_default
    _handle_binop_Carry = _handle_binop_default
    _handle_binop_SCarry = _handle_binop_default
    _handle_binop_SBorrow = _handle_binop_default
    _handle_binop_InterleaveLOV = _handle_binop_default
    _handle_binop_InterleaveHIV = _handle_binop_default
    _handle_binop_CasCmpEQ = _handle_binop_default
    _handle_binop_CasCmpNE = _handle_binop_default
    _handle_binop_ExpCmpNE = _handle_binop_default
    _handle_binop_SarNV = _handle_binop_default
    _handle_binop_ShrNV = _handle_binop_default
    _handle_binop_ShlNV = _handle_binop_default
    _handle_binop_CmpEQV = _handle_binop_default
    _handle_binop_CmpNEV = _handle_binop_default
    _handle_binop_CmpGEV = _handle_binop_default
    _handle_binop_CmpGTV = _handle_binop_default
    _handle_binop_CmpLEV = _handle_binop_default
    _handle_binop_CmpLTV = _handle_binop_default
    _handle_binop_MinV = _handle_binop_default
    _handle_binop_MaxV = _handle_binop_default
    _handle_binop_QAddV = _handle_binop_default
    _handle_binop_QNarrowBinV = _handle_binop_default
    _handle_binop_PermV = _handle_binop_default
    _handle_binop_Set = _handle_binop_default
