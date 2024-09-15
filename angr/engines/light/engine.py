# pylint:disable=no-self-use,isinstance-second-argument-not-valid-type,unused-argument
from __future__ import annotations
from typing import Any
import struct
import re
import logging

import ailment
import pyvex
import claripy
import archinfo

from ...misc.ux import once
from ...engines.vex.claripy.datalayer import value as claripy_value
from ...engines.vex.claripy.irop import UnsupportedIROpError, SimOperationError, vexop_to_simop
from ...code_location import CodeLocation
from ...utils.constants import DEFAULT_STATEMENT
from ..engine import SimEngine
import contextlib


class SimEngineLightMixin:
    """
    A mixin base class for engines meant to perform static analysis
    """

    def __init__(self, *args, logger=None, **kwargs):
        self.arch: archinfo.Arch | None = None
        self.l = logger
        super().__init__(*args, **kwargs)

    def _is_top(self, expr) -> bool:
        """
        Check if a given expression is a TOP value.

        :param expr:    The given expression.
        :return:        True if the expression is TOP, False otherwise.
        """
        return False

    def _top(self, size: int):
        """
        Return a TOP value. It will only be called if _is_top() has been implemented.

        :param size:    The size (in bits) of the TOP value.
        :return:        A TOP value.
        """
        raise NotImplementedError

    @staticmethod
    def sp_offset(bits: int, offset: int):
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
                    return spoffset_expr.args[1].args[0]
            elif spoffset_expr.op == "__sub__":
                if len(spoffset_expr.args) == 1:
                    # Unexpected but fine
                    return 0
                if isinstance(spoffset_expr.args[1], claripy.ast.Base) and spoffset_expr.args[1].op == "BVV":
                    return -spoffset_expr.args[1].args[0] & ((1 << spoffset_expr.size()) - 1)
        return None


class SimEngineLight(
    SimEngineLightMixin,
    SimEngine,
):
    """
    A full-featured engine base class, suitable for static analysis
    """

    def __init__(self):
        logger = logging.getLogger(self.__module__ + "." + self.__class__.__name__)
        super().__init__(logger=logger)

        # local variables
        self.state = None
        self.arch: archinfo.Arch = None
        self.block = None
        self._call_stack = None

        self.stmt_idx = None
        self.ins_addr = None
        self.tmps = None

        # for VEX blocks only
        self.tyenv = None

    def process(self, state, *args, **kwargs):
        # we are using a completely different state. Therefore, we directly call our _process() method before
        # SimEngine becomes flexible enough.
        self._process(state, None, block=kwargs.pop("block", None), whitelist=kwargs.pop("whitelist", None))

    def _process(self, new_state, successors, *args, **kwargs):
        raise NotImplementedError

    def _check(self, state, *args, **kwargs):
        return True

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


# noinspection PyPep8Naming
class SimEngineLightVEXMixin(SimEngineLightMixin):
    """
    A mixin for doing static analysis on VEX
    """

    def _process(self, state, successors, *args, block, whitelist=None, **kwargs):  # pylint:disable=arguments-differ
        # initialize local variables
        self.tmps = {}
        self.block = block
        self.state = state

        if state is not None:
            self.arch: archinfo.Arch = state.arch

        self.tyenv = block.vex.tyenv

        self._process_Stmt(whitelist=whitelist)

        self.stmt_idx = None
        self.ins_addr = None

    def _process_Stmt(self, whitelist=None):
        if whitelist is not None:
            # optimize whitelist lookups
            whitelist = set(whitelist)

        for stmt_idx, stmt in enumerate(self.block.vex.statements):
            if whitelist is not None and stmt_idx not in whitelist:
                continue
            self.stmt_idx = stmt_idx

            if type(stmt) is pyvex.IRStmt.IMark:
                # Note that we cannot skip IMarks as they are used later to trigger observation events
                # The bug caused by skipping IMarks is reported at https://github.com/angr/angr/pull/1150
                self.ins_addr = stmt.addr + stmt.delta

            self._handle_Stmt(stmt)

        self._process_block_end()

    def _process_block_end(self):
        # handle calls to another function
        # Note that without global information, we cannot handle cases where we *jump* to another function (jumpkind ==
        # "Ijk_Boring"). Users are supposed to overwrite this method, detect these cases with the help of global
        # information (such as CFG or symbol addresses), and handle them accordingly.
        if self.block.vex.jumpkind == "Ijk_Call":
            self.stmt_idx = DEFAULT_STATEMENT
            handler = "_handle_function"
            if hasattr(self, handler):
                func_addr = (
                    self.block.vex.next if isinstance(self.block.vex.next, int) else self._expr(self.block.vex.next)
                )
                if func_addr is None and self.l is not None:
                    self.l.debug("Cannot determine the callee address at %#x.", self.block.addr)
                getattr(self, handler)(func_addr)
            else:
                if self.l is not None:
                    self.l.warning("Function handler not implemented.")

    #
    # Statement handlers
    #

    def _handle_Stmt(self, stmt):
        handler = f"_handle_{type(stmt).__name__}"
        if hasattr(self, handler):
            getattr(self, handler)(stmt)
        elif type(stmt).__name__ not in ("IMark", "AbiHint") and self.l is not None:
            self.l.error("Unsupported statement type %s.", type(stmt).__name__)

    # synchronize with function _handle_WrTmpData()
    def _handle_WrTmp(self, stmt):
        data = self._expr(stmt.data)
        if data is None:
            return

        self.tmps[stmt.tmp] = data

    # invoked by LoadG
    def _handle_WrTmpData(self, tmp, data):
        if data is None:
            return
        self.tmps[tmp] = data

    def _handle_Dirty(self, stmt):
        if self.l is not None:
            self.l.error("Unimplemented Dirty node for current architecture.")

    def _handle_Put(self, stmt):
        raise NotImplementedError("Please implement the Put handler with your own logic.")

    def _handle_Store(self, stmt):
        raise NotImplementedError("Please implement the Store handler with your own logic.")

    def _handle_StoreG(self, stmt):
        raise NotImplementedError("Please implement the StoreG handler with your own logic.")

    def _handle_LLSC(self, stmt: pyvex.IRStmt.LLSC):
        raise NotImplementedError("Please implement the LLSC handler with your own logic.")

    #
    # Expression handlers
    #

    def _expr(self, expr):
        handler = f"_handle_{type(expr).__name__}"
        if hasattr(self, handler):
            return getattr(self, handler)(expr)
        if self.l is not None:
            self.l.error("Unsupported expression type %s.", type(expr).__name__)
        return None

    def _handle_Triop(self, expr: pyvex.IRExpr.Triop):  # pylint: disable=useless-return
        handler = None
        if expr.op.startswith("Iop_AddF") or expr.op.startswith("Iop_SubF"):
            handler = "_handle_AddF"
        elif expr.op.startswith("Iop_MulF"):
            handler = "_handle_MulF"
        elif expr.op.startswith("Iop_DivF"):
            handler = "_handle_DivF"
        elif expr.op.startswith("Iop_SinF"):
            handler = "_handle_SinF"
        elif expr.op.startswith("Iop_ScaleF"):
            handler = "_handle_ScaleF"

        if handler is not None and hasattr(self, handler):
            return getattr(self, handler)(expr)

        if once(expr.op) and self.l is not None:
            self.l.error("Unsupported Triop %s.", expr.op)

        return None

    def _handle_AddF(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_SubF(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_MulF(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_DivF(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_NegF(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_AbsF(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_SinF(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_CosF(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_ScaleF(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_RdTmp(self, expr):
        tmp = expr.tmp

        if tmp in self.tmps:
            return self.tmps[tmp]
        return None

    def _handle_Get(self, expr):
        raise NotImplementedError("Please implement the Get handler with your own logic.")

    def _handle_Load(self, expr):
        raise NotImplementedError("Please implement the Load handler with your own logic.")

    def _handle_LoadG(self, stmt):
        raise NotImplementedError("Please implement the LoadG handler with your own logic.")

    def _handle_Exit(self, stmt):
        self._expr(stmt.guard)
        self._expr(stmt.dst)

    def _handle_ITE(self, expr):
        # EDG says: Not sure how generic this is.
        cond = self._expr(expr.cond)
        if cond is True:
            return self._expr(expr.iftrue)
        if cond is False:
            return self._expr(expr.iffalse)
        return None

    def _handle_Unop(self, expr):
        handler = None

        # All conversions are handled by the Conversion handler
        simop = None
        with contextlib.suppress(UnsupportedIROpError, SimOperationError):
            simop = vexop_to_simop(expr.op)

        if simop is not None and simop.op_attrs.get("conversion", None):
            handler = "_handle_Conversion"
        # Notice order of "Not" comparisons
        elif expr.op == "Iop_Not1":
            handler = "_handle_Not1"
        elif expr.op.startswith("Iop_Not"):
            handler = "_handle_Not"
        elif expr.op.startswith("Iop_Clz"):
            handler = "_handle_Clz"
        elif expr.op.startswith("Iop_Ctz"):
            handler = "_handle_Ctz"
        elif expr.op.startswith("Iop_NegF"):
            handler = "_handle_NegF"
        elif expr.op.startswith("Iop_AbsF"):
            handler = "_handle_AbsF"

        if handler is not None and hasattr(self, handler):
            return getattr(self, handler)(expr)
        if self.l is not None:
            self.l.error("Unsupported Unop %s.", expr.op)
        return None

    def _handle_Binop(self, expr: pyvex.IRExpr.Binop):
        handler = None
        if expr.op.startswith("Iop_And"):
            handler = "_handle_And"
        elif expr.op.startswith("Iop_Mod"):
            handler = "_handle_Mod"
        elif expr.op.startswith("Iop_Or"):
            handler = "_handle_Or"
        elif expr.op.startswith("Iop_Add"):
            handler = "_handle_Add"
        elif expr.op.startswith("Iop_HAdd"):
            handler = "_handle_HAdd"
        elif expr.op.startswith("Iop_Sub"):
            handler = "_handle_Sub"
        elif expr.op.startswith("Iop_QSub"):
            handler = "_handle_QSub"
        elif expr.op.startswith("Iop_Mull"):
            handler = "_handle_Mull"
        elif expr.op.startswith("Iop_Mul"):
            handler = "_handle_Mul"
        elif expr.op.startswith("Iop_DivMod"):
            handler = "_handle_DivMod"
        elif expr.op.startswith("Iop_Div"):
            handler = "_handle_Div"
        elif expr.op.startswith("Iop_Xor"):
            handler = "_handle_Xor"
        elif expr.op.startswith("Iop_Shl"):
            handler = "_handle_Shl"
        elif expr.op.startswith("Iop_Shr"):
            handler = "_handle_Shr"
        elif expr.op.startswith("Iop_Sal"):
            # intended use of SHL
            handler = "_handle_Shl"
        elif expr.op.startswith("Iop_Sar"):
            handler = "_handle_Sar"
        elif expr.op.startswith("Iop_CmpEQ"):
            handler = "_handle_CmpEQ"
        elif expr.op.startswith("Iop_CmpNE"):
            handler = "_handle_CmpNE"
        elif expr.op.startswith("Iop_CmpLT"):
            handler = "_handle_CmpLT"
        elif expr.op.startswith("Iop_CmpLE"):
            handler = "_handle_CmpLE"
        elif expr.op.startswith("Iop_CmpGE"):
            handler = "_handle_CmpGE"
        elif expr.op.startswith("Iop_CmpGT"):
            handler = "_handle_CmpGT"
        elif expr.op.startswith("Iop_CmpORD"):
            handler = "_handle_CmpORD"
        elif expr.op.startswith("Iop_CmpF"):
            handler = "_handle_CmpF"
        elif expr.op == "Iop_32HLto64":
            handler = "_handle_32HLto64"
        elif expr.op.startswith("Const"):
            handler = "_handle_Const"
        elif expr.op.startswith("Iop_16HLto32"):
            handler = "_handle_16HLto32"
        elif expr.op.startswith("Iop_ExpCmpNE64"):
            handler = "_handle_ExpCmpNE64"
        elif expr.op.startswith("Iop_SinF"):
            handler = "_handle_SinF"
        elif expr.op.startswith("Iop_CosF"):
            handler = "_handle_CosF"

        vector_size, vector_count = None, None
        if handler is not None:
            # vector information
            m = re.match(r"Iop_[^\d]+(\d+)U{0,1}x(\d+)", expr.op)
            if m is not None:
                vector_size = int(m.group(1))
                vector_count = int(m.group(2))
                handler += "_v"

        if handler is not None and hasattr(self, handler):
            if vector_size is not None and vector_count is not None:
                return getattr(self, handler)(expr, vector_size, vector_count)
            return getattr(self, handler)(expr)
        if once(expr.op) and self.l is not None:
            self.l.warning("Unsupported Binop %s.", expr.op)

        return None

    def _handle_CCall(self, expr):  # pylint:disable=useless-return
        if self.l is not None:
            self.l.warning("Unsupported expression type CCall with callee %s.", str(expr.cee))
        return

    #
    # Unary operation handlers
    #

    def _handle_U64(self, expr):
        return claripy.BVV(expr.value, 64)

    def _handle_U32(self, expr):
        return claripy.BVV(expr.value, 32)

    def _handle_U16(self, expr):
        return claripy.BVV(expr.value, 16)

    def _handle_U8(self, expr):
        return claripy.BVV(expr.value, 8)

    def _handle_U1(self, expr):
        return claripy.BVV(expr.value, 1)

    def _handle_Const(self, expr):  # pylint:disable=no-self-use
        return claripy_value(expr.con.type, expr.con.value)

    def _handle_Conversion(self, expr):
        expr_ = self._expr(expr.args[0])
        if expr_ is None:
            return None
        to_size = expr.result_size(self.tyenv)
        if self._is_top(expr_):
            return self._top(to_size)

        if isinstance(expr_, claripy.ast.Base) and expr_.op == "BVV":
            if expr_.size() > to_size:
                # truncation
                return expr_[to_size - 1 : 0]
            if expr_.size() < to_size:
                # extension
                return claripy.ZeroExt(to_size - expr_.size(), expr_)
            return expr_

        return self._top(to_size)

    #
    # Binary operation handlers
    #

    def _binop_get_args(self, expr) -> tuple[Any, Any] | None | Any | None:
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None, None
        if self._is_top(expr_0):
            return None, self._top(expr_0.size())

        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None, None
        if self._is_top(expr_1):
            return None, self._top(expr_0.size())  # always use the size of expr_0

        return (expr_0, expr_1), None

    def _handle_And(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(expr_0.size())

        return expr_0 & expr_1

    def _handle_Or(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(expr_0.size())

        return expr_0 | expr_1

    def _handle_Not1(self, expr):
        return self._handle_Not(expr)

    def _handle_Not(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        if self._is_top(expr_0):
            return self._top(expr_0.size())

        try:
            return ~expr_0  # pylint:disable=invalid-unary-operand-type
        except TypeError as e:
            if self.l is not None:
                self.l.exception(e)
            return None

    def _handle_Clz(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        if self._is_top(expr_0):
            return self._top(expr_0.size())
        return self._top(expr_0.size())

    def _handle_Ctz(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        if self._is_top(expr_0):
            return self._top(expr_0.size())
        return self._top(expr_0.size())

    def _handle_Add(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(expr_0.size())

        return expr_0 + expr_1

    def _handle_Sub(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(expr_0.size())

        return expr_0 - expr_1

    def _handle_Mul(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(expr_0.size())

        return expr_0 * expr_1

    def _handle_Mull(self, expr):
        self._binop_get_args(expr)
        return self._top(expr.result_size(self.tyenv))

    def _handle_DivMod(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(expr.result_size(self.tyenv))

        signed = "U" in expr.op  # Iop_DivModU64to32 vs Iop_DivMod
        from_size = expr_0.size()
        to_size = expr_1.size()
        if signed:
            quotient = expr_0.SDiv(claripy.SignExt(from_size - to_size, expr_1))
            remainder = expr_0.SMod(claripy.SignExt(from_size - to_size, expr_1))
            quotient_size = to_size
            remainder_size = to_size
            return claripy.Concat(
                claripy.Extract(remainder_size - 1, 0, remainder), claripy.Extract(quotient_size - 1, 0, quotient)
            )
        quotient = expr_0 // claripy.ZeroExt(from_size - to_size, expr_1)
        remainder = expr_0 % claripy.ZeroExt(from_size - to_size, expr_1)
        quotient_size = to_size
        remainder_size = to_size
        return claripy.Concat(
            claripy.Extract(remainder_size - 1, 0, remainder), claripy.Extract(quotient_size - 1, 0, quotient)
        )

    def _handle_Div(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(expr_0.size())

        try:
            return expr_0 / expr_1
        except ZeroDivisionError:
            return self._top(expr_0.size())

    def _handle_Mod(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(expr_0.size())

        try:
            return expr_0 - (expr_1 // expr_1) * expr_1
        except ZeroDivisionError:
            return self._top(expr_0.size())

    def _handle_Xor(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(expr_0.size())

        try:
            return expr_0 ^ expr_1
        except TypeError as e:
            if self.l is not None:
                self.l.warning(e)
            return None

    def _handle_Shl(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(expr_0.size())

        if isinstance(expr_1, claripy.ast.Base) and expr_1.op == "BVV":
            # convert it to an int when possible
            expr_1 = expr_1.args[0]
        else:
            # make sure the sizes are the same - VEX does not care about it
            if expr_1.size() < expr_0.size():
                expr_1 = claripy.ZeroExt(expr_0.size() - expr_1.size(), expr_1)
            elif expr_1.size() > expr_0.size():
                expr_1 = claripy.Extract(expr_0.size() - 1, 0, expr_1)

        return expr_0 << expr_1

    def _handle_Shr(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(expr_0.size())

        if isinstance(expr_1, claripy.ast.Base) and expr_1.op == "BVV":
            # convert it to an int when possible
            expr_1 = expr_1.args[0]
        else:
            # make sure the sizes are the same - VEX does not care about it
            if expr_1.size() < expr_0.size():
                expr_1 = claripy.ZeroExt(expr_0.size() - expr_1.size(), expr_1)
            elif expr_1.size() > expr_0.size():
                expr_1 = claripy.Extract(expr_0.size() - 1, 0, expr_1)

        return claripy.LShR(expr_0, expr_1)

    def _handle_Sar(self, expr):
        # EDG asks: is this right?
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(expr_0.size())

        if isinstance(expr_1, claripy.ast.Base) and expr_1.op == "BVV":
            # convert it to an int when possible
            expr_1 = expr_1.args[0]
        else:
            # make sure the sizes are the same - VEX does not care about it
            if expr_1.size() < expr_0.size():
                expr_1 = claripy.ZeroExt(expr_0.size() - expr_1.size(), expr_1)
            elif expr_1.size() > expr_0.size():
                expr_1 = claripy.Extract(expr_0.size() - 1, 0, expr_1)

        return expr_0 >> expr_1

    def _handle_CmpEQ(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(1)

        return expr_0 == expr_1

    def _handle_CmpNE(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(1)

        return expr_0 != expr_1

    def _handle_CmpLE(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(1)

        return expr_0 <= expr_1

    def _handle_CmpGE(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(1)

        return expr_0 >= expr_1

    def _handle_CmpLT(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(1)

        return expr_0 < expr_1

    def _handle_CmpGT(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr_0, expr_1 = args

        if self._is_top(expr_0) or self._is_top(expr_1):
            return self._top(1)

        return expr_0 > expr_1

    def _handle_CmpEQ_v(self, expr, _vector_size, _vector_count):
        _, _ = self._binop_get_args(expr)
        return self._top(expr.result_size(self.tyenv))

    def _handle_CmpNE_v(self, expr, _vector_size, _vector_count):
        _, _ = self._binop_get_args(expr)
        return self._top(expr.result_size(self.tyenv))

    def _handle_CmpLE_v(self, expr, _vector_size, _vector_count):
        _, _ = self._binop_get_args(expr)
        return self._top(expr.result_size(self.tyenv))

    def _handle_CmpGE_v(self, expr, _vector_size, _vector_count):
        _, _ = self._binop_get_args(expr)
        return self._top(expr.result_size(self.tyenv))

    def _handle_CmpLT_v(self, expr, _vector_size, _vector_count):
        _, _ = self._binop_get_args(expr)
        return self._top(expr.result_size(self.tyenv))

    def _handle_CmpGT_v(self, expr, _vector_size, _vector_count):
        _, _ = self._binop_get_args(expr)
        return self._top(expr.result_size(self.tyenv))

    def _handle_MBE(self, _expr: pyvex.IRStmt.MBE):
        # Yeah.... no.
        return None

    def _handle_32HLto64(self, expr):
        args, r = self._binop_get_args(expr)
        if args is None:
            if r is not None:
                # the size of r should be 32 but we need to return a 64-bit expression
                assert r.size() == 32
                r = claripy.ZeroExt(32, r)
            return r

        return None

    def _handle_16HLto32(self, expr):
        _, _ = self._binop_get_args(expr)
        return self._top(expr.result_size(self.tyenv))

    def _handle_ExpCmpNE64(self, expr):
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        return self._top(expr.result_size(self.tyenv))


# noinspection PyPep8Naming
class SimEngineLightAILMixin(SimEngineLightMixin):
    """
    A mixin for doing static analysis on AIL
    """

    def _process(
        self, state, successors, *args, block=None, whitelist=None, **kwargs
    ):  # pylint:disable=arguments-differ
        self.tmps = {}
        self.block: ailment.Block = block
        self.state = state
        if self.arch is None:
            # we only access state.arch if the arch of this engine itself is not previously configured
            self.arch = state.arch

        self._process_Stmt(whitelist=whitelist)

        self.stmt_idx = None
        self.ins_addr = None

    def _process_Stmt(self, whitelist=None):
        if whitelist is not None:
            whitelist = set(whitelist)

        for stmt_idx, stmt in enumerate(self.block.statements):
            if whitelist is not None and stmt_idx not in whitelist:
                continue

            self.stmt_idx = stmt_idx
            self.ins_addr = stmt.ins_addr

            self._handle_Stmt(stmt)

    def _expr(self, expr):
        expr_type_name = type(expr).__name__
        if isinstance(expr, ailment.Stmt.Call):
            # Call can be both an expression and a statement. Add a suffix to make sure we are working on the expression
            # variant.
            expr_type_name += "Expr"

        h = None
        handler = f"_handle_{expr_type_name}"
        if hasattr(self, handler):
            h = getattr(self, handler)

        if h is None:
            handler = f"_ail_handle_{expr_type_name}"
            if hasattr(self, handler):
                h = getattr(self, handler)

        if h is not None:
            return h(expr)
        if self.l is not None:
            self.l.warning("Unsupported expression type %s.", type(expr).__name__)
        return None

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
    # Statement handlers
    #

    def _handle_Stmt(self, stmt):
        handler = f"_handle_{type(stmt).__name__}"
        if hasattr(self, handler):
            return getattr(self, handler)(stmt)

        # compatibility
        old_handler = f"_ail_handle_{type(stmt).__name__}"
        if hasattr(self, old_handler):
            return getattr(self, old_handler)(stmt)

        if self.l is not None:
            self.l.warning("Unsupported statement type %s.", type(stmt).__name__)
        return None

    def _ail_handle_Assignment(self, stmt):
        pass

    def _ail_handle_Label(self, stmt):
        pass

    def _ail_handle_Jump(self, stmt):
        pass

    def _ail_handle_Call(self, stmt):
        pass

    def _ail_handle_Return(self, stmt):
        pass

    #
    # Expression handlers
    #

    def _ail_handle_BV(self, expr: claripy.ast.Base):
        return expr

    def _ail_handle_Const(self, expr):  # pylint:disable=no-self-use
        return expr.value

    def _ail_handle_StackBaseOffset(self, expr: ailment.Expr.StackBaseOffset):
        return expr

    def _ail_handle_Tmp(self, expr):
        tmp_idx = expr.tmp_idx

        try:
            return self.tmps[tmp_idx]
        except KeyError:
            return None

    def _ail_handle_Load(self, expr: ailment.Expr.Load):
        self._expr(expr.addr)
        return expr

    def _ail_handle_CallExpr(self, expr: ailment.Stmt.Call):
        self._expr(expr.target)
        return expr

    def _ail_handle_Reinterpret(self, expr: ailment.Expr.Reinterpret):
        arg = self._expr(expr.operand)

        if isinstance(arg, int) and (
            expr.from_bits == 32 and expr.from_type == "I" and expr.to_bits == 32 and expr.to_type == "F"
        ):
            # int -> float
            b = struct.pack("<I", arg)
            return struct.unpack("<f", b)[0]
        if (
            isinstance(arg, float)
            and expr.from_bits == 32
            and expr.from_type == "F"
            and expr.to_bits == 32
            and expr.to_type == "I"
        ):
            # float -> int
            b = struct.pack("<f", arg)
            return struct.unpack("<I", b)[0]

        return expr

    def _ail_handle_UnaryOp(self, expr):
        handler_name = f"_handle_{expr.op}"
        try:
            handler = getattr(self, handler_name)
        except AttributeError:
            handler_name = f"_ail_handle_{expr.op}"
            try:
                handler = getattr(self, handler_name)
            except AttributeError:
                if self.l is not None:
                    self.l.warning("Unsupported UnaryOp %s.", expr.op)
                return None

        return handler(expr)

    def _ail_handle_BinaryOp(self, expr):
        handler_name = f"_handle_{expr.op}"
        try:
            handler = getattr(self, handler_name)
        except AttributeError:
            handler_name = f"_ail_handle_{expr.op}"
            try:
                handler = getattr(self, handler_name)
            except AttributeError:
                if self.l is not None:
                    self.l.warning("Unsupported BinaryOp %s.", expr.op)
                return None

        return handler(expr)

    def _ail_handle_TernaryOp(self, expr):
        handler_name = f"_handle_{expr.op}"
        try:
            handler = getattr(self, handler_name)
        except AttributeError:
            handler_name = f"_ail_handle_{expr.op}"
            try:
                handler = getattr(self, handler_name)
            except AttributeError:
                if self.l is not None:
                    self.l.warning("Unsupported Ternary %s.", expr.op)
                return None

        return handler(expr)

    #
    # Binary operation handlers
    #

    def _ail_handle_CmpEQ(self, expr):
        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)
        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            if isinstance(expr_0, ailment.Expr.Const) and isinstance(expr_1, ailment.Expr.Const):
                if expr_0.value == expr_1.value:
                    return ailment.Expr.Const(None, None, 1, 1)
                return ailment.Expr.Const(None, None, 0, 1)
        except TypeError:
            pass
        return ailment.Expr.BinaryOp(expr.idx, "CmpEQ", [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_CmpNE(self, expr):
        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)
        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            if isinstance(expr_0, ailment.Expr.Const) and isinstance(expr_1, ailment.Expr.Const):
                if expr_0.value != expr_1.value:
                    return ailment.Expr.Const(None, None, 1, 1)
                return ailment.Expr.Const(None, None, 0, 1)
        except TypeError:
            pass
        return ailment.Expr.BinaryOp(expr.idx, "CmpNE", [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_CmpLT(self, expr):
        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)
        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            if isinstance(expr_0, ailment.Expr.Const) and isinstance(expr_1, ailment.Expr.Const):
                if expr_0.value < expr_1.value:
                    return ailment.Expr.Const(None, None, 1, 1)
                return ailment.Expr.Const(None, None, 0, 1)
        except TypeError:
            pass
        return ailment.Expr.BinaryOp(expr.idx, "CmpLT", [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Add(self, expr):
        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)
        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 + expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(
                expr.idx,
                "Add",
                [expr_0, expr_1],
                expr.signed,
                floating_point=expr.floating_point,
                rounding_mode=expr.rounding_mode,
                **expr.tags,
            )

    def _ail_handle_Sub(self, expr):
        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0) if not isinstance(arg0, claripy.ast.Base) else arg0
        expr_1 = self._expr(arg1) if not isinstance(arg1, claripy.ast.Base) else self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 - expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(
                expr.idx,
                "Sub",
                [expr_0, expr_1],
                expr.signed,
                floating_point=expr.floating_point,
                rounding_mode=expr.rounding_mode,
                **expr.tags,
            )

    def _ail_handle_Div(self, expr):
        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 // expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(
                expr.idx,
                "Div",
                [expr_0, expr_1],
                expr.signed,
                floating_point=expr.floating_point,
                rounding_mode=expr.rounding_mode,
                **expr.tags,
            )

    def _ail_handle_DivMod(self, expr):
        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        return ailment.Expr.BinaryOp(
            expr.idx,
            "DivMod",
            [expr_0, expr_1],
            expr.signed,
            bits=expr.bits,
            from_bits=expr.from_bits,
            to_bits=expr.to_bits,
            **expr.tags,
        )

    def _ail_handle_Mod(self, expr):
        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 % expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(expr.idx, "Mod", [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Mul(self, expr):
        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 * expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(
                expr.idx,
                "Mul",
                [expr_0, expr_1],
                expr.signed,
                bits=expr.bits,
                floating_point=expr.floating_point,
                rounding_mode=expr.rounding_mode,
                **expr.tags,
            )

    def _ail_handle_Mull(self, expr):
        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 * expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(
                expr.idx,
                "Mull",
                [expr_0, expr_1],
                expr.signed,
                bits=expr.bits,
                floating_point=expr.floating_point,
                rounding_mode=expr.rounding_mode,
                **expr.tags,
            )

    def _ail_handle_And(self, expr):
        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 & expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(expr.idx, "And", [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Or(self, expr):
        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 | expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(expr.idx, "Or", [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Xor(self, expr):
        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 ^ expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(expr.idx, "Xor", [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Shr(self, expr):
        arg0, arg1 = expr.operands
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            if isinstance(expr_1, claripy.ast.BV) and expr_1.concrete:
                return expr_0 >> expr_1.concrete_value
        except TypeError:
            pass

        return ailment.Expr.BinaryOp(expr.idx, "Shr", [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Shl(self, expr):
        arg0, arg1 = expr.operands
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            if isinstance(expr_1, claripy.ast.BV) and expr_1.concrete:
                return expr_0 << expr_1.concrete_value
        except TypeError:
            pass

        return ailment.Expr.BinaryOp(expr.idx, "Shl", [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Sal(self, expr):
        return self._ail_handle_Shl(expr)

    def _ail_handle_Rol(self, expr):
        arg0, arg1 = expr.operands
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        return ailment.Expr.BinaryOp(expr.idx, "Rol", [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Ror(self, expr):
        arg0, arg1 = expr.operands
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        return ailment.Expr.BinaryOp(expr.idx, "Ror", [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Sar(self, expr):
        arg0, arg1 = expr.operands
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 >> expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(expr.idx, "Sar", [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Concat(self, expr):
        arg0, arg1 = expr.operands
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        return ailment.Expr.BinaryOp(expr.idx, "Concat", [expr_0, expr_1], expr.signed, **expr.tags)

    #
    # Unary operation handlers
    #

    def _ail_handle_Convert(self, expr):
        data = self._expr(expr.operand)
        if data is not None and type(data) is int:
            return data
        return None

    def _ail_handle_Not(self, expr):
        data = self._expr(expr.operand)
        if data is None:
            return None

        return ailment.Expr.UnaryOp(expr.idx, "Not", data, **expr.tags)

    def _ail_handle_Neg(self, expr):
        data = self._expr(expr.operand)
        if data is None:
            return None

        return ailment.Expr.UnaryOp(expr.idx, "Neg", data, **expr.tags)

    def _ail_handle_BitwiseNeg(self, expr):
        data = self._expr(expr.operand)
        if data is None:
            return None

        return ailment.Expr.UnaryOp(expr.idx, "BitwiseNeg", data, **expr.tags)


# Compatibility
SimEngineLightVEX = SimEngineLightVEXMixin
SimEngineLightAIL = SimEngineLightAILMixin
