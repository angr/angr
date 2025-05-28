# pylint:disable=no-self-use,unused-argument
from __future__ import annotations
from typing import Any, Protocol, cast, TypeVar, Generic
from collections.abc import Callable
from abc import abstractmethod
import re
import logging

import angr.ailment as ailment
import pyvex
import claripy
from pyvex.expr import IRExpr

from angr.misc.ux import once
from angr.engines.vex.claripy.irop import UnsupportedIROpError, SimOperationError, vexop_to_simop
from angr.code_location import CodeLocation
from angr.project import Project
from angr.engines.engine import DataType_co, SimEngine, StateType
from angr.block import Block


class BlockProtocol(Protocol):
    """
    The minimum protocol that a block an engine can process should adhere to.
    Requires just an addr attribute.
    """

    addr: int


BlockType = TypeVar("BlockType", bound=BlockProtocol)
ResultType = TypeVar("ResultType")
StmtDataType = TypeVar("StmtDataType")


class IRTop(pyvex.expr.IRExpr):
    """
    A dummy IRExpr used for intra-engine communication and code-reuse.
    """

    def __init__(self, ty: str):
        super().__init__()
        self.ty = ty

    def result_type(self, tyenv):
        return self.ty


class SimEngineLight(Generic[StateType, DataType_co, BlockType, ResultType], SimEngine[StateType, ResultType]):
    """
    A full-featured engine base class, suitable for static analysis
    """

    # local variables
    block: BlockType
    _call_stack: list[Any]
    state: StateType

    stmt_idx: int
    ins_addr: int
    tmps: dict[int, DataType_co]

    def __init__(self, project: Project, logger=None):
        self.l = logger or logging.getLogger(self.__module__ + "." + self.__class__.__name__)
        super().__init__(project)

    @abstractmethod
    def process(self, state: StateType, *, block: BlockType | None = None, **kwargs) -> ResultType: ...

    def lift(self, state: StateType) -> BlockType:
        raise TypeError(f"{type(self)} requires `block` to be passed to `process`")

    #
    # Helper methods
    #

    def _codeloc(self, block_only=False, context=None):
        return CodeLocation(
            self.block.addr,
            None if block_only else self.stmt_idx,
            ins_addr=None if block_only else self.ins_addr,
            context=context,
        )

    @abstractmethod
    def _top(self, bits: int) -> DataType_co: ...

    @abstractmethod
    def _is_top(self, expr: Any) -> bool: ...

    @staticmethod
    def sp_offset(bits: int, offset: int) -> claripy.ast.BV:
        base = claripy.BVS("SpOffset", bits, explicit_name=True)
        if offset:
            base += offset
        return base

    @staticmethod
    def extract_offset_to_sp(spoffset_expr: claripy.ast.Base) -> int | None:
        """
        Extract the offset to the original stack pointer.

        :param spoffset_expr:   The claripy AST to parse.
        :return:                The offset to the original stack pointer, or None if `spoffset_expr` is not a supported
                                type of SpOffset expression.
        """

        if "SpOffset" in spoffset_expr.variables:
            # Local variable
            if spoffset_expr.op == "BVS":
                return 0
            if spoffset_expr.op == "__add__":
                if len(spoffset_expr.args) == 1:
                    # Unexpected but fine
                    return 0
                if isinstance(spoffset_expr.args[1], claripy.ast.Base) and spoffset_expr.args[1].op == "BVV":
                    return cast(int, spoffset_expr.args[1].args[0])
            elif spoffset_expr.op == "__sub__":
                if len(spoffset_expr.args) == 1:
                    # Unexpected but fine
                    return 0
                if isinstance(spoffset_expr.args[1], claripy.ast.Base) and spoffset_expr.args[1].op == "BVV":
                    return -cast(int, spoffset_expr.args[1].args[0]) & (
                        (1 << cast(claripy.ast.BV, spoffset_expr).size()) - 1
                    )
        return None


T = TypeVar("T")


def longest_prefix_lookup(haystack: str, mapping: dict[str, T]) -> T | None:
    for l in reversed(range(len(haystack))):
        handler = mapping.get(haystack[:l], None)
        if handler is not None:
            return handler
    return None


# noinspection PyPep8Naming
class SimEngineLightVEX(
    Generic[StateType, DataType_co, ResultType, StmtDataType], SimEngineLight[StateType, DataType_co, Block, ResultType]
):
    """
    A mixin for doing static analysis on VEX
    """

    tyenv: pyvex.IRTypeEnv

    @staticmethod
    def unop_handler(f: Callable[[T, pyvex.expr.Unop], DataType_co]) -> Callable[[T, pyvex.expr.Unop], DataType_co]:
        f.unop_handler = True
        return f

    @staticmethod
    def binop_handler(f: Callable[[T, pyvex.expr.Binop], DataType_co]) -> Callable[[T, pyvex.expr.Binop], DataType_co]:
        f.binop_handler = True
        return f

    @staticmethod
    def binopv_handler(
        f: Callable[[T, int, int, pyvex.expr.Binop], DataType_co],
    ) -> Callable[[T, int, int, pyvex.expr.Binop], DataType_co]:
        f.binopv_handler = True
        return f

    @staticmethod
    def triop_handler(f: Callable[[T, pyvex.expr.Triop], DataType_co]) -> Callable[[T, pyvex.expr.Triop], DataType_co]:
        f.triop_handler = True
        return f

    @staticmethod
    def qop_handler(f: Callable[[T, pyvex.expr.Qop], DataType_co]) -> Callable[[T, pyvex.expr.Qop], DataType_co]:
        f.qop_handler = True
        return f

    @staticmethod
    def ccall_handler(f: Callable[[T, pyvex.expr.CCall], DataType_co]) -> Callable[[T, pyvex.expr.CCall], DataType_co]:
        f.ccall_handler = True
        return f

    @staticmethod
    def dirty_handler(
        f: Callable[[T, pyvex.stmt.Dirty], StmtDataType],
    ) -> Callable[[T, pyvex.stmt.Dirty], StmtDataType]:
        f.dirty_handler = True
        return f

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        def checked(h: T, attr: str) -> T:
            if not getattr(h, attr, False):
                raise TypeError(f"Handle {h} is not validated for {attr}")
            return h

        self._stmt_handlers: dict[str, Callable[[Any], StmtDataType]] = {
            "Ist_WrTmp": self._handle_stmt_WrTmp,
            "Ist_Put": self._handle_stmt_Put,
            "Ist_PutI": self._handle_stmt_PutI,
            "Ist_Store": self._handle_stmt_Store,
            "Ist_StoreG": self._handle_stmt_StoreG,
            "Ist_LoadG": self._handle_stmt_LoadG,
            "Ist_CAS": self._handle_stmt_CAS,
            "Ist_LLSC": self._handle_stmt_LLSC,
            "Ist_MBE": self._handle_stmt_MBE,
            "Ist_Exit": self._handle_stmt_Exit,
            "Ist_NoOp": self._handle_stmt_NoOp,
            "Ist_IMark": self._handle_stmt_IMark,
            "Ist_AbiHint": self._handle_stmt_AbiHint,
            "Ist_Dirty": self._handle_stmt_Dirty,
        }
        self._expr_handlers: dict[str, Callable[[Any], DataType_co]] = {
            "IRTop": self._handle_expr_IRTop,
            "VECRET": self._handle_expr_VECRET,
            "GSPTR": self._handle_expr_GSPTR,
            "RdTmp": self._handle_expr_RdTmp,
            "Get": self._handle_expr_Get,
            "GetI": self._handle_expr_GetI,
            "Load": self._handle_expr_Load,
            "ITE": self._handle_expr_ITE,
            "Unop": self._handle_expr_Unop,
            "Binop": self._handle_expr_Binop,
            "Triop": self._handle_expr_Triop,
            "Qop": self._handle_expr_Qop,
            "CCall": self._handle_expr_CCall,
            "Const": self._handle_expr_Const,
        }
        self._unop_handlers: dict[str, Callable[[pyvex.expr.Unop], DataType_co]] = {
            name.split("_", 3)[-1]: checked(getattr(self, name), "unop_handler")
            for name in dir(self)
            if name.startswith("_handle_unop_")
        }
        self._binop_handlers: dict[str, Callable[[pyvex.expr.Binop], DataType_co]] = {
            name.split("_", 3)[-1]: checked(getattr(self, name), "binop_handler")
            for name in dir(self)
            if name.startswith("_handle_binop_")
        }
        self._binopv_handlers: dict[str, Callable[[int, int, pyvex.expr.Binop], DataType_co]] = {
            name.split("_", 3)[-1]: checked(getattr(self, name), "binopv_handler")
            for name in dir(self)
            if name.startswith("_handle_binopv_")
        }
        self._triop_handlers: dict[str, Callable[[pyvex.expr.Triop], DataType_co]] = {
            name.split("_", 3)[-1]: checked(getattr(self, name), "triop_handler")
            for name in dir(self)
            if name.startswith("_handle_triop_")
        }
        self._qop_handlers: dict[str, Callable[[pyvex.expr.Qop], DataType_co]] = {
            name.split("_", 3)[-1]: checked(getattr(self, name), "qop_handler")
            for name in dir(self)
            if name.startswith("_handle_qop_")
        }
        self._ccall_handlers: dict[str, Callable[[pyvex.expr.CCall], DataType_co]] = {
            name.split("_", 3)[-1]: checked(getattr(self, name), "ccall_handler")
            for name in dir(self)
            if name.startswith("_handle_ccall_")
        }
        self._dirty_handlers: dict[str, Callable[[pyvex.stmt.Dirty], StmtDataType]] = {
            name.split("_", 3)[-1]: checked(getattr(self, name), "dirty_handler")
            for name in dir(self)
            if name.startswith("_handle_dirty_")
        }

    def process(
        self, state: StateType, *, block: Block | None = None, whitelist: set[int] | None = None, **kwargs
    ) -> ResultType:
        # initialize local variables
        self.tmps = {}

        if block is None:
            block = self.lift(state)
        self.block = block
        self.state = state
        self.arch = self.project.arch
        self.tyenv = block.vex.tyenv
        self.stmt_idx = -1
        self.ins_addr = -1

        result = self._process_block(whitelist=whitelist)
        del self.stmt_idx
        del self.ins_addr
        del self.tmps
        del self.block
        del self.state
        del self.tyenv
        return result

    def _process_block(self, whitelist: set[int] | None = None) -> ResultType:
        result = []
        for stmt_idx, stmt in enumerate(self.block.vex.statements):
            if whitelist is not None and stmt_idx not in whitelist:
                continue
            self.stmt_idx = stmt_idx

            if type(stmt) is pyvex.IRStmt.IMark:
                # Note that we cannot skip IMarks as they are used later to trigger observation events
                # The bug caused by skipping IMarks is reported at https://github.com/angr/angr/pull/1150
                self.ins_addr = stmt.addr + stmt.delta

            result.append(self._stmt(stmt))

        return self._process_block_end(result, whitelist)

    def _stmt(self, stmt: pyvex.stmt.IRStmt) -> StmtDataType:
        return self._stmt_handlers[stmt.tag](stmt)

    @abstractmethod
    def _process_block_end(self, stmt_result: list[StmtDataType], whitelist: set[int] | None) -> ResultType: ...

    #
    # Statement handlers
    #

    @abstractmethod
    def _handle_stmt_WrTmp(self, stmt: pyvex.stmt.WrTmp) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_Put(self, stmt: pyvex.stmt.Put) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_PutI(self, stmt: pyvex.stmt.PutI) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_Store(self, stmt: pyvex.stmt.Store) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_StoreG(self, stmt: pyvex.stmt.StoreG) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_LoadG(self, stmt: pyvex.stmt.LoadG) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_CAS(self, stmt: pyvex.stmt.CAS) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_LLSC(self, stmt: pyvex.stmt.LLSC) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_MBE(self, stmt: pyvex.stmt.MBE) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_Exit(self, stmt: pyvex.stmt.Exit) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_NoOp(self, stmt: pyvex.stmt.NoOp) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_IMark(self, stmt: pyvex.stmt.IMark) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_AbiHint(self, stmt: pyvex.stmt.AbiHint) -> StmtDataType: ...

    def _handle_stmt_Dirty(self, stmt: pyvex.stmt.Dirty) -> StmtDataType:
        handler = longest_prefix_lookup(stmt.cee.name, self._dirty_handlers)
        if handler is not None:
            return handler(stmt)

        if once(stmt.cee.name) and self.l is not None:
            self.l.error("Unsupported Dirty %s.", stmt.cee.name)
        if stmt.tmp in (-1, 0xFFFFFFFF):
            return self._handle_stmt_NoOp(pyvex.stmt.NoOp())
        return self._handle_stmt_WrTmp(pyvex.stmt.WrTmp(stmt.tmp, IRTop(self.tyenv.lookup(stmt.tmp))))

    #
    # Expression handlers
    #

    def _expr(self, expr: IRExpr) -> DataType_co:
        handler = type(expr).__name__
        return self._expr_handlers[handler](expr)

    # not generated by vex
    def _handle_expr_IRTop(self, expr: IRTop) -> DataType_co:
        return self._top(pyvex.get_type_size(expr.result_type(self.tyenv)))

    @abstractmethod
    def _handle_expr_VECRET(self, expr: pyvex.expr.VECRET) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_GSPTR(self, expr: pyvex.expr.GSPTR) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_RdTmp(self, expr: pyvex.expr.RdTmp) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_Get(self, expr: pyvex.expr.Get) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_GetI(self, expr: pyvex.expr.GetI) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_Load(self, expr: pyvex.expr.Load) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_ITE(self, expr: pyvex.expr.ITE) -> DataType_co: ...

    def _handle_expr_Unop(self, expr: pyvex.expr.Unop) -> DataType_co:
        handler = None
        assert expr.op.startswith("Iop_")
        handler = longest_prefix_lookup(expr.op[4:], self._unop_handlers)
        if handler is not None:
            return handler(expr)

        # All conversions are handled by the Conversion handler
        try:
            simop = vexop_to_simop(expr.op)
        except (UnsupportedIROpError, SimOperationError):
            simop = None

        if simop is not None and "Reinterp" not in expr.op and simop.op_attrs.get("conversion", None):
            return self._handle_conversion(simop._from_size, simop._to_size, simop.is_signed, expr.args[0])

        if once(expr.op) and self.l is not None:
            self.l.error("Unsupported Unop %s.", expr.op)
        return self._top(pyvex.get_type_size(expr.result_type(self.tyenv)))

    @abstractmethod
    def _handle_conversion(self, from_size: int, to_size: int, signed: bool, operand: IRExpr) -> DataType_co: ...

    def _handle_expr_Binop(self, expr: pyvex.expr.Binop) -> DataType_co:
        assert expr.op.startswith("Iop_")

        # vector information
        m = re.match(r"Iop_[^\d]+(\d+)[SU]{0,1}x(\d+)", expr.op)
        if m is not None:
            vector_size = int(m.group(1))
            vector_count = int(m.group(2))
            handler_v = longest_prefix_lookup(expr.op[4:], self._binopv_handlers)
            if handler_v is not None:
                return handler_v(vector_size, vector_count, expr)

        handler = longest_prefix_lookup(expr.op[4:], self._binop_handlers)
        if handler is not None:
            return handler(expr)

        if once(expr.op) and self.l is not None:
            self.l.warning("Unsupported Binop %s.", expr.op)
        return self._top(pyvex.get_type_size(expr.result_type(self.tyenv)))

    def _handle_expr_Triop(self, expr: pyvex.expr.Triop) -> DataType_co:
        assert expr.op.startswith("Iop_")
        handler = longest_prefix_lookup(expr.op[4:], self._triop_handlers)
        if handler is not None:
            return handler(expr)

        # should we try dispatching some triops with roundingmode as binops?

        if once(expr.op) and self.l is not None:
            self.l.error("Unsupported Triop %s.", expr.op)
        return self._top(pyvex.get_type_size(expr.result_type(self.tyenv)))

    def _handle_expr_Qop(self, expr: pyvex.expr.Qop) -> DataType_co:
        assert expr.op.startswith("Iop_")
        handler = longest_prefix_lookup(expr.op[4:], self._qop_handlers)
        if handler is not None:
            return handler(expr)

        if once(expr.op) and self.l is not None:
            self.l.error("Unsupported Qop %s.", expr.op)
        return self._top(pyvex.get_type_size(expr.result_type(self.tyenv)))

    def _handle_expr_CCall(self, expr: pyvex.expr.CCall) -> DataType_co:  # pylint:disable=useless-return
        handler = longest_prefix_lookup(expr.cee.name, self._ccall_handlers)
        if handler is not None:
            return handler(expr)

        if once(expr.cee.name) and self.l is not None:
            self.l.error("Unsupported CCall %s.", expr.cee.name)
        return self._top(pyvex.get_type_size(expr.result_type(self.tyenv)))

    @abstractmethod
    def _handle_expr_Const(self, expr: pyvex.expr.Const) -> DataType_co: ...


class SimEngineNostmtVEX(
    Generic[StateType, DataType_co, ResultType], SimEngineLightVEX[StateType, DataType_co, ResultType, None]
):
    """
    A base class of SimEngineLightVEX that has default handlers for statements if they just need to return None, so you
    don't have to implement every single statement handler as ``return None``.
    """

    def _handle_stmt_WrTmp(self, stmt):
        pass

    def _handle_stmt_Put(self, stmt):
        pass

    def _handle_stmt_PutI(self, stmt):
        pass

    def _handle_stmt_Store(self, stmt):
        pass

    def _handle_stmt_StoreG(self, stmt):
        pass

    def _handle_stmt_LoadG(self, stmt):
        pass

    def _handle_stmt_CAS(self, stmt):
        pass

    def _handle_stmt_LLSC(self, stmt):
        pass

    def _handle_stmt_MBE(self, stmt):
        pass

    def _handle_stmt_Exit(self, stmt):
        pass

    def _handle_stmt_NoOp(self, stmt):
        pass

    def _handle_stmt_IMark(self, stmt):
        pass

    def _handle_stmt_AbiHint(self, stmt):
        pass


# noinspection PyPep8Naming
class SimEngineLightAIL(
    Generic[StateType, DataType_co, StmtDataType, ResultType],
    SimEngineLight[StateType, DataType_co, ailment.Block, ResultType],
):
    """
    A mixin for doing static analysis on AIL
    """

    def __init__(self, *args, **kwargs):
        self._stmt_handlers: dict[str, Callable[[Any], StmtDataType]] = {
            "Assignment": self._handle_stmt_Assignment,
            "CAS": self._handle_stmt_CAS,
            "WeakAssignment": self._handle_stmt_WeakAssignment,
            "Store": self._handle_stmt_Store,
            "Jump": self._handle_stmt_Jump,
            "ConditionalJump": self._handle_stmt_ConditionalJump,
            "Call": self._handle_stmt_Call,
            "Return": self._handle_stmt_Return,
            "DirtyStatement": self._handle_stmt_DirtyStatement,
            "Label": self._handle_stmt_Label,
        }
        self._expr_handlers: dict[str, Callable[[Any], DataType_co]] = {
            "Atom": self._handle_expr_Atom,
            "Const": self._handle_expr_Const,
            "Tmp": self._handle_expr_Tmp,
            "VirtualVariable": self._handle_expr_VirtualVariable,
            "Phi": self._handle_expr_Phi,
            "Op": self._handle_expr_Op,
            "UnaryOp": self._handle_expr_UnaryOp,
            "BinaryOp": self._handle_expr_BinaryOp,
            "Convert": self._handle_expr_Convert,
            "Reinterpret": self._handle_expr_Reinterpret,
            "Load": self._handle_expr_Load,
            "Register": self._handle_expr_Register,
            "ITE": self._handle_expr_ITE,
            "Call": self._handle_expr_Call,
            "DirtyExpression": self._handle_expr_DirtyExpression,
            "VEXCCallExpression": self._handle_expr_VEXCCallExpression,
            "MultiStatementExpression": self._handle_expr_MultiStatementExpression,
            "BasePointerOffset": self._handle_expr_BasePointerOffset,
            "StackBaseOffset": self._handle_expr_StackBaseOffset,
        }
        self._unop_handlers: dict[str, Callable[[ailment.UnaryOp], DataType_co]] = {
            "Not": self._handle_unop_Not,
            "Neg": self._handle_unop_Neg,
            "BitwiseNeg": self._handle_unop_BitwiseNeg,
            "Reference": self._handle_unop_Reference,
            "Dereference": self._handle_unop_Dereference,
            "Clz": self._handle_unop_Clz,
            "Ctz": self._handle_unop_Ctz,
            "GetMSBs": self._handle_unop_GetMSBs,
            "unpack": self._handle_unop_unpack,
            "Sqrt": self._handle_unop_Sqrt,
            "RSqrtEst": self._handle_unop_RSqrtEst,
        }
        self._binop_handlers: dict[str, Callable[[ailment.BinaryOp], DataType_co]] = {
            "Add": self._handle_binop_Add,
            "AddF": self._handle_binop_AddF,
            "AddV": self._handle_binop_AddV,
            "Sub": self._handle_binop_Sub,
            "SubF": self._handle_binop_SubF,
            "SubV": self._handle_binop_SubV,
            "Mul": self._handle_binop_Mul,
            "Mull": self._handle_binop_Mull,
            "MulF": self._handle_binop_MulF,
            "MulV": self._handle_binop_MulV,
            "MulHiV": self._handle_binop_MulHiV,
            "Div": self._handle_binop_Div,
            "DivF": self._handle_binop_DivF,
            "DivV": self._handle_binop_DivV,
            "Mod": self._handle_binop_Mod,
            "Xor": self._handle_binop_Xor,
            "And": self._handle_binop_And,
            "LogicalAnd": self._handle_binop_LogicalAnd,
            "Or": self._handle_binop_Or,
            "LogicalOr": self._handle_binop_LogicalOr,
            "Shl": self._handle_binop_Shl,
            "Shr": self._handle_binop_Shr,
            "Sar": self._handle_binop_Sar,
            "CmpF": self._handle_binop_CmpF,
            "CmpEQ": self._handle_binop_CmpEQ,
            "CmpNE": self._handle_binop_CmpNE,
            "CmpLT": self._handle_binop_CmpLT,
            "CmpLE": self._handle_binop_CmpLE,
            "CmpGT": self._handle_binop_CmpGT,
            "CmpGE": self._handle_binop_CmpGE,
            "Concat": self._handle_binop_Concat,
            "Ror": self._handle_binop_Ror,
            "Rol": self._handle_binop_Rol,
            "Carry": self._handle_binop_Carry,
            "SCarry": self._handle_binop_SCarry,
            "SBorrow": self._handle_binop_SBorrow,
            "InterleaveLOV": self._handle_binop_InterleaveLOV,
            "InterleaveHIV": self._handle_binop_InterleaveHIV,
            "CasCmpEQ": self._handle_binop_CasCmpEQ,
            "CasCmpNE": self._handle_binop_CasCmpNE,
            "ExpCmpNE": self._handle_binop_ExpCmpNE,
            "SarNV": self._handle_binop_SarNV,
            "ShrNV": self._handle_binop_ShrNV,
            "ShlNV": self._handle_binop_ShlNV,
            "CmpEQV": self._handle_binop_CmpEQV,
            "CmpNEV": self._handle_binop_CmpNEV,
            "CmpGEV": self._handle_binop_CmpGEV,
            "CmpGTV": self._handle_binop_CmpGTV,
            "CmpLEV": self._handle_binop_CmpLTV,
            "CmpLTV": self._handle_binop_CmpLEV,
            "MinV": self._handle_binop_MinV,
            "MaxV": self._handle_binop_MaxV,
            "QAddV": self._handle_binop_QAddV,
            "QNarrowBinV": self._handle_binop_QNarrowBinV,
            "PermV": self._handle_binop_PermV,
            "Set": self._handle_binop_Set,
        }
        super().__init__(*args, **kwargs)

    def process(
        self, state: StateType, *, block: ailment.Block | None = None, whitelist: set[int] | None = None, **kwargs
    ) -> ResultType:
        self.tmps = {}
        if block is None:
            block = self.lift(state)
        self.block = block
        self.state = state
        self.stmt_idx = 0
        self.ins_addr = 0

        stmt_data = self._process_stmts(whitelist=whitelist)
        result = self._process_block_end(block, stmt_data, whitelist)
        del self.tmps
        del self.block
        del self.state
        del self.stmt_idx
        del self.ins_addr
        return result

    @abstractmethod
    def _process_block_end(
        self, block: ailment.Block, stmt_data: list[StmtDataType], whitelist: set[int] | None
    ) -> ResultType: ...

    #
    # Helper methods
    #

    def _codeloc(self, block_only=False, context=None):
        return CodeLocation(
            self.block.addr,
            None if block_only else self.stmt_idx,
            ins_addr=None if block_only else self.ins_addr,
            context=context,
            block_idx=self.block.idx,
        )

    #
    # Statements
    #

    def _process_stmts(self, whitelist: set[int] | None) -> list[StmtDataType]:
        result = []

        for stmt_idx, stmt in enumerate(self.block.statements):
            if whitelist is not None and stmt_idx not in whitelist:
                continue

            self.stmt_idx = stmt_idx
            self.ins_addr = stmt.ins_addr
            result.append(self._stmt(stmt))

        return result

    def _stmt(self, stmt: ailment.statement.Statement) -> StmtDataType:
        stmt_type_name = type(stmt).__name__
        return self._stmt_handlers[stmt_type_name](stmt)

    @abstractmethod
    def _handle_stmt_Assignment(self, stmt: ailment.statement.Assignment) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_CAS(self, stmt: ailment.statement.CAS) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_WeakAssignment(self, stmt: ailment.statement.WeakAssignment) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_Store(self, stmt: ailment.statement.Store) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_Jump(self, stmt: ailment.statement.Jump) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_ConditionalJump(self, stmt: ailment.statement.ConditionalJump) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_Call(self, stmt: ailment.statement.Call) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_Return(self, stmt: ailment.statement.Return) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_DirtyStatement(self, stmt: ailment.statement.DirtyStatement) -> StmtDataType: ...

    @abstractmethod
    def _handle_stmt_Label(self, stmt: ailment.statement.Label) -> StmtDataType: ...

    #
    # Expressions
    #

    def _expr(self, expr: ailment.Expression) -> DataType_co:
        expr_type_name = type(expr).__name__
        return self._expr_handlers[expr_type_name](expr)

    def _handle_expr_Atom(self, expr: ailment.expression.Atom) -> DataType_co:
        raise TypeError("We should never see raw Atoms")

    @abstractmethod
    def _handle_expr_Const(self, expr: ailment.expression.Const) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_Tmp(self, expr: ailment.expression.Tmp) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_VirtualVariable(self, expr: ailment.expression.VirtualVariable) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_Phi(self, expr: ailment.expression.Phi) -> DataType_co: ...

    def _handle_expr_Op(self, expr: ailment.expression.Op) -> DataType_co:
        raise TypeError("We should never see raw Ops")

    def _handle_expr_UnaryOp(self, expr: ailment.expression.UnaryOp) -> DataType_co:
        return self._unop_handlers[expr.op](expr)

    def _handle_expr_BinaryOp(self, expr: ailment.expression.BinaryOp) -> DataType_co:
        return self._binop_handlers[expr.op](expr)

    @abstractmethod
    def _handle_expr_Convert(self, expr: ailment.expression.Convert) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_Reinterpret(self, expr: ailment.expression.Reinterpret) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_Load(self, expr: ailment.expression.Load) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_Register(self, expr: ailment.expression.Register) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_ITE(self, expr: ailment.expression.ITE) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_Call(self, expr: ailment.statement.Call) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_DirtyExpression(self, expr: ailment.expression.DirtyExpression) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_VEXCCallExpression(self, expr: ailment.expression.VEXCCallExpression) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_MultiStatementExpression(
        self, expr: ailment.expression.MultiStatementExpression
    ) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_BasePointerOffset(self, expr: ailment.expression.BasePointerOffset) -> DataType_co: ...

    @abstractmethod
    def _handle_expr_StackBaseOffset(self, expr: ailment.expression.StackBaseOffset) -> DataType_co: ...

    #
    # UnOps
    #

    @abstractmethod
    def _handle_unop_Not(self, expr: ailment.expression.UnaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_unop_Neg(self, expr: ailment.expression.UnaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_unop_BitwiseNeg(self, expr: ailment.expression.UnaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_unop_Reference(self, expr: ailment.expression.UnaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_unop_Dereference(self, expr: ailment.expression.UnaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_unop_Clz(self, expr: ailment.expression.UnaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_unop_Ctz(self, expr: ailment.expression.UnaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_unop_GetMSBs(self, expr: ailment.expression.UnaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_unop_unpack(self, expr: ailment.expression.UnaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_unop_Sqrt(self, expr: ailment.expression.UnaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_unop_RSqrtEst(self, expr: ailment.expression.UnaryOp) -> DataType_co: ...

    #
    # BinOps
    #
    @abstractmethod
    def _handle_binop_Add(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_AddF(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_AddV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Sub(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_SubF(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_SubV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Mul(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Mull(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_MulF(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_MulV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_MulHiV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Div(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_DivF(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_DivV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Mod(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Xor(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_And(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_LogicalAnd(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Or(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_LogicalOr(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Shl(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Shr(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Sar(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CmpF(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CmpEQ(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CmpNE(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CmpLT(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CmpLE(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CmpGT(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CmpGE(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Concat(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Ror(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Rol(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Carry(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_SCarry(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_SBorrow(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_InterleaveLOV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_InterleaveHIV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CasCmpEQ(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CasCmpNE(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_ExpCmpNE(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_SarNV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_ShrNV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_ShlNV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CmpEQV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CmpNEV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CmpGEV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CmpGTV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CmpLEV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_CmpLTV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_MinV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_MaxV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_QAddV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_QNarrowBinV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_PermV(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...

    @abstractmethod
    def _handle_binop_Set(self, expr: ailment.expression.BinaryOp) -> DataType_co: ...


class SimEngineNostmtAIL(
    Generic[StateType, DataType_co, StmtDataType, ResultType],
    SimEngineLightAIL[StateType, DataType_co, StmtDataType | None, ResultType],
):
    """
    A base class of SimEngineLightAIL that has default handlers for statements if they just need to return None, so you
    don't have to implement every single statement handler as ``return None``.
    """

    def _handle_stmt_Assignment(self, stmt) -> StmtDataType | None:
        pass

    def _handle_stmt_WeakAssignment(self, stmt) -> StmtDataType | None:
        pass

    def _handle_stmt_CAS(self, stmt) -> StmtDataType | None:
        pass

    def _handle_stmt_Store(self, stmt) -> StmtDataType | None:
        pass

    def _handle_stmt_Jump(self, stmt) -> StmtDataType | None:
        pass

    def _handle_stmt_ConditionalJump(self, stmt) -> StmtDataType | None:
        pass

    def _handle_stmt_Call(self, stmt) -> StmtDataType | None:
        pass

    def _handle_stmt_Return(self, stmt) -> StmtDataType | None:
        pass

    def _handle_stmt_DirtyStatement(self, stmt) -> StmtDataType | None:
        pass

    def _handle_stmt_Label(self, stmt) -> StmtDataType | None:
        pass


class SimEngineNoexprAIL(
    Generic[StateType, DataType_co, StmtDataType, ResultType],
    SimEngineLightAIL[StateType, DataType_co | None, StmtDataType, ResultType],
):
    """
    A base class of SimEngineLightAIL that has default handlers for expressions if they just need to return None, so you
    don't have to implement every single expression handler as ``return None``.
    """

    def _handle_expr_Atom(self, expr: ailment.expression.Atom) -> DataType_co | None:
        pass

    def _handle_expr_Const(self, expr: ailment.expression.Const) -> DataType_co | None:
        pass

    def _handle_expr_Tmp(self, expr: ailment.expression.Tmp) -> DataType_co | None:
        pass

    def _handle_expr_VirtualVariable(self, expr: ailment.expression.VirtualVariable) -> DataType_co | None:
        pass

    def _handle_expr_Phi(self, expr: ailment.expression.Phi) -> DataType_co | None:
        pass

    def _handle_expr_Convert(self, expr: ailment.expression.Convert) -> DataType_co | None:
        pass

    def _handle_expr_Reinterpret(self, expr: ailment.expression.Reinterpret) -> DataType_co | None:
        pass

    def _handle_expr_Load(self, expr: ailment.expression.Load) -> DataType_co | None:
        pass

    def _handle_expr_Register(self, expr: ailment.expression.Register) -> DataType_co | None:
        pass

    def _handle_expr_ITE(self, expr: ailment.expression.ITE) -> DataType_co | None:
        pass

    def _handle_expr_Call(self, expr: ailment.statement.Call) -> DataType_co | None:
        pass

    def _handle_expr_DirtyExpression(self, expr: ailment.expression.DirtyExpression) -> DataType_co | None:
        pass

    def _handle_expr_VEXCCallExpression(self, expr: ailment.expression.VEXCCallExpression) -> DataType_co | None:
        pass

    def _handle_expr_MultiStatementExpression(
        self, expr: ailment.expression.MultiStatementExpression
    ) -> DataType_co | None:
        pass

    def _handle_expr_BasePointerOffset(self, expr: ailment.expression.BasePointerOffset) -> DataType_co | None:
        pass

    def _handle_expr_StackBaseOffset(self, expr: ailment.expression.StackBaseOffset) -> DataType_co | None:
        pass

    def _handle_unop_Not(self, expr: ailment.expression.UnaryOp) -> DataType_co | None:
        pass

    def _handle_unop_Neg(self, expr: ailment.expression.UnaryOp) -> DataType_co | None:
        pass

    def _handle_unop_BitwiseNeg(self, expr: ailment.expression.UnaryOp) -> DataType_co | None:
        pass

    def _handle_unop_Reference(self, expr: ailment.expression.UnaryOp) -> DataType_co | None:
        pass

    def _handle_unop_Dereference(self, expr: ailment.expression.UnaryOp) -> DataType_co | None:
        pass

    def _handle_unop_GetMSBs(self, expr: ailment.expression.UnaryOp) -> DataType_co | None:
        pass

    def _handle_unop_unpack(self, expr: ailment.expression.UnaryOp) -> DataType_co | None:
        pass

    def _handle_unop_RSqrtEst(self, expr: ailment.expression.UnaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Add(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_AddF(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_AddV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Sub(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_SubF(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_SubV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Mul(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Mull(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_MulF(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_MulV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_MulHiV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Div(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_DivF(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_DivV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Mod(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Xor(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_And(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_LogicalAnd(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Or(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_LogicalOr(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Shl(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Shr(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Sar(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CmpF(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CmpEQ(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CmpNE(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CmpLT(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CmpLE(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CmpGT(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CmpGE(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Concat(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Ror(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Rol(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Carry(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_SCarry(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_SBorrow(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_InterleaveLOV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_InterleaveHIV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CasCmpNE(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_ExpCmpNE(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_SarNV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_ShrNV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_ShlNV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CmpEQV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CmpNEV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CmpGEV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CmpGTV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CmpLEV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_CmpLTV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_PermV(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_binop_Set(self, expr: ailment.expression.BinaryOp) -> DataType_co | None:
        pass

    def _handle_unop_Clz(self, expr: ailment.expression.UnaryOp) -> DataType_co | None:
        pass

    def _handle_unop_Ctz(self, expr: ailment.expression.UnaryOp) -> DataType_co | None:
        pass
