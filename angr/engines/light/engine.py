# pylint:disable=no-self-use
from typing import Tuple, Optional
import logging

import ailment
import pyvex
import archinfo

from ...engines.vex.claripy.irop import UnsupportedIROpError, vexop_to_simop
from ...code_location import CodeLocation
from ...utils.constants import DEFAULT_STATEMENT
from ..engine import SimEngine


class SimEngineLight(SimEngine):
    def __init__(self):
        super(SimEngineLight, self).__init__()

        self.l = logging.getLogger(self.__module__ + "." + self.__class__.__name__)

        # local variables
        self.state = None
        self.arch = None
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
        self._process(state, None, block=kwargs.pop('block', None), whitelist=kwargs.pop('whitelist', None))

    def _process(self, new_state, successors, *args, **kwargs):
        raise NotImplementedError()

    def _check(self, state, *args, **kwargs):
        return True

    #
    # Helper methods
    #

    @property
    def _context(self) -> Optional[Tuple[int]]:
        if self._call_stack is None:
            # contextless mode
            return None

        if not self._call_stack:
            # contextful but the callstack is empty
            return tuple()

        # Convert to Tuple to make `context` hashable if not None
        call_stack_addresses = tuple(self._call_stack)
        return call_stack_addresses

    def _codeloc(self, block_only=False):
        return CodeLocation(self.block.addr,
                            None if block_only else self.stmt_idx,
                            ins_addr=None if block_only else self.ins_addr,
                            context=self._context
                            )


class SimEngineLightVEXMixin:

    def _process(self, state, successors, *args, block, whitelist=None, **kwargs):  # pylint:disable=arguments-differ,unused-argument

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
        if self.block.vex.jumpkind == 'Ijk_Call':
            self.stmt_idx = DEFAULT_STATEMENT
            handler = '_handle_function'
            if hasattr(self, handler):
                func_addr = self._expr(self.block.vex.next)
                if func_addr is not None:
                    getattr(self, handler)(func_addr)
                else:
                    self.l.debug('Cannot determine the callee address at %#x.', self.block.addr)
            else:
                self.l.warning('Function handler not implemented.')

    #
    # Statement handlers
    #

    def _handle_Stmt(self, stmt):
        handler = "_handle_%s" % type(stmt).__name__
        if hasattr(self, handler):
            getattr(self, handler)(stmt)
        elif type(stmt).__name__ not in ('IMark', 'AbiHint'):
            self.l.error('Unsupported statement type %s.', type(stmt).__name__)

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

    def _handle_Put(self, stmt):
        raise NotImplementedError('Please implement the Put handler with your own logic.')

    def _handle_Store(self, stmt):
        raise NotImplementedError('Please implement the Store handler with your own logic.')

    def _handle_StoreG(self, stmt):
        raise NotImplementedError('Please implement the StoreG handler with your own logic.')

    def _handle_LLSC(self, stmt: pyvex.IRStmt.LLSC):
        raise NotImplementedError('Please implement the LLSC handler with your own logic.')

    #
    # Expression handlers
    #

    def _expr(self, expr):

        handler = "_handle_%s" % type(expr).__name__
        if hasattr(self, handler):
            return getattr(self, handler)(expr)
        else:
            self.l.error('Unsupported expression type %s.', type(expr).__name__)
        return None

    def _handle_RdTmp(self, expr):
        tmp = expr.tmp

        if tmp in self.tmps:
            return self.tmps[tmp]
        return None

    def _handle_Get(self, expr):
        raise NotImplementedError('Please implement the Get handler with your own logic.')

    def _handle_Load(self, expr):
        raise NotImplementedError('Please implement the Load handler with your own logic.')

    def _handle_LoadG(self, stmt):
        raise NotImplementedError('Please implement the LoadG handler with your own logic.')

    def _handle_Exit(self, stmt):
        self._expr(stmt.guard)
        self._expr(stmt.dst)

    def _handle_ITE(self, expr):
        # EDG says: Not sure how generic this is.
        cond = self._expr(expr.cond)
        if cond is True:
            return self._expr(expr.iftrue)
        elif cond is False:
            return self._expr(expr.iffalse)
        else:
            return None

    def _handle_Unop(self, expr):
        handler = None

        # All conversions are handled by the Conversion handler
        simop = None
        try:
            simop = vexop_to_simop(expr.op)
        except UnsupportedIROpError:
            pass

        if simop is not None and simop.op_attrs.get('conversion', None):
            handler = '_handle_Conversion'
        # Notice order of "Not" comparisons
        elif expr.op == 'Iop_Not1':
            handler = '_handle_Not1'
        elif expr.op.startswith('Iop_Not'):
            handler = '_handle_Not'

        if handler is not None and hasattr(self, handler):
            return getattr(self, handler)(expr)
        else:
            self.l.error('Unsupported Unop %s.', expr.op)
            return None

    def _handle_Binop(self, expr):
        handler = None
        if expr.op.startswith('Iop_And'):
            handler = '_handle_And'
        elif expr.op.startswith('Iop_Mod'):
            handler = '_handle_Mod'
        elif expr.op.startswith('Iop_Or'):
            handler = '_handle_Or'
        elif expr.op.startswith('Iop_Add'):
            handler = '_handle_Add'
        elif expr.op.startswith('Iop_Sub'):
            handler = '_handle_Sub'
        elif expr.op.startswith('Iop_Mul'):
            handler = "_handle_Mul"
        elif expr.op.startswith('Iop_Div'):
            handler = "_handle_Div"
        elif expr.op.startswith('Iop_Xor'):
            handler = '_handle_Xor'
        elif expr.op.startswith('Iop_Shl'):
            handler = '_handle_Shl'
        elif expr.op.startswith('Iop_Shr'):
            handler = '_handle_Shr'
        elif expr.op.startswith('Iop_Sal'):
            # intended use of SHL
            handler = '_handle_Shl'
        elif expr.op.startswith('Iop_Sar'):
            handler = '_handle_Sar'
        elif expr.op.startswith('Iop_CmpEQ'):
            handler = '_handle_CmpEQ'
        elif expr.op.startswith('Iop_CmpNE'):
            handler = '_handle_CmpNE'
        elif expr.op.startswith('Iop_CmpLT'):
            handler = '_handle_CmpLT'
        elif expr.op.startswith('Iop_CmpLE'):
            handler = '_handle_CmpLE'
        elif expr.op.startswith('Iop_CmpGE'):
            handler = '_handle_CmpGE'
        elif expr.op.startswith('Iop_CmpGT'):
            handler = '_handle_CmpGT'
        elif expr.op.startswith('Iop_CmpORD'):
            handler = '_handle_CmpORD'
        elif expr.op == 'Iop_32HLto64':
            handler = '_handle_32HLto64'
        elif expr.op.startswith('Const'):
            handler = '_handle_Const'
        if handler is not None and hasattr(self, handler):
            return getattr(self, handler)(expr)
        else:
            self.l.error('Unsupported Binop %s.', expr.op)

        return None

    def _handle_CCall(self, expr):  # pylint:disable=useless-return
        self.l.warning('Unsupported expression type CCall with callee %s.', str(expr.cee))
        return None

    #
    # Unary operation handlers
    #

    def _handle_U32(self, expr):
        return expr.value

    def _handle_U64(self, expr):
        return expr.value

    def _handle_U16(self, expr):
        return expr.value

    def _handle_U8(self, expr):
        return expr.value

    def _handle_U1(self, expr):
        return expr.value

    def _handle_Const(self, expr):  # pylint:disable=no-self-use
        return expr.con.value

    def _handle_Conversion(self, expr):
        expr = self._expr(expr.args[0])
        if expr is None:
            return None

        # FIXME: implement real conversion
        return expr

    #
    # Binary operation handlers
    #

    def _handle_And(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 & expr_1
        except TypeError as e:
            self.l.warning(e)
            return None

    def _handle_Or(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 | expr_1
        except TypeError as e:
            self.l.warning(e)
            return None

    def _handle_Not1(self, expr):
        return self._handle_Not(expr)

    def _handle_Not(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        try:
            return ~expr_0  # pylint:disable=invalid-unary-operand-type
        except TypeError as e:
            self.l.exception(e)
            return None

    def _handle_Add(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            if isinstance(expr_0, int) and isinstance(expr_1, int):
                # self.tyenv is not used
                mask = (1 << expr.result_size(self.tyenv)) - 1
                return (expr_0 + expr_1) & mask
            else:
                return expr_0 + expr_1
        except TypeError as e:
            self.l.warning(e)
            return None

    def _handle_Sub(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            if isinstance(expr_0, int) and isinstance(expr_1, int):
                # self.tyenv is not used
                mask = (1 << expr.result_size(self.tyenv)) - 1
                return (expr_0 - expr_1) & mask
            else:
                return expr_0 - expr_1
        except TypeError as e:
            self.l.warning(e)
            return None

    def _handle_Mul(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            if isinstance(expr_0, int) and isinstance(expr_1, int):
                # self.tyenv is not used
                mask = (1 << expr.result_size(self.tyenv)) - 1
                return (expr_0 * expr_1) & mask
            else:
                return expr_0 * expr_1
        except TypeError as e:
            self.l.warning(e)
            return None

    def _handle_Div(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            # TODO: Probably should take care of the sign
            return expr_0 // expr_1
        except TypeError as e:
            self.l.warning(e)
            return None
        except ZeroDivisionError as e:
            self.l.warning(e)
            return None

    def _handle_Mod(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            # TODO: Probably should take care of the sign
            return expr_0 - (expr_0 // expr_1)*expr_1
        except TypeError as e:
            self.l.warning(e)
            return None

    def _handle_Xor(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 ^ expr_1
        except TypeError as e:
            self.l.warning(e)
            return None

    def _handle_Shl(self, expr):
        arg0, arg1 = expr.args

        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None
        #elif expr_1 < 0:
        #    expr.args = [expr_0, -1*expr_1]
         #   return self._handle_Shr(expr)
        try:
            if isinstance(expr_0, int) and isinstance(expr_1, int):
                # self.tyenv is not used
                mask = (1 << expr.result_size(self.tyenv)) - 1
                if expr_1 < 0:
                    return (expr_0 >> -expr_1) & mask
                else:
                    return (expr_0 << expr_1) & mask
            else:
                return expr_0 << expr_1
        except TypeError as e:
            self.l.warning(e)
            return None

    def _handle_Shr(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            if expr_1 < 0:
                return expr_0 << -expr_1
            else:
                return expr_0 >> expr_1
        except TypeError as e:
            self.l.warning(e)
            return None

    def _handle_Sar(self, expr):
        # EDG asks: is this right?
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None
        try:
            return expr_0 >> expr_1
        except TypeError as e:
            self.l.warning(e)
            return None

    def _handle_CmpEQ(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 == expr_1
        except TypeError as ex:
            self.l.warning(ex)
            return None

    def _handle_CmpNE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 != expr_1
        except TypeError as ex:
            self.l.warning(ex)
            return None

    def _handle_CmpLE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 <= expr_1
        except TypeError as ex:
            self.l.warning(ex)
            return None

    def _handle_CmpGE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 >= expr_1
        except TypeError as ex:
            self.l.warning(ex)
            return None

    def _handle_CmpLT(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 < expr_1
        except TypeError as ex:
            self.l.warning(ex)
            return None

    def _handle_CmpGT(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 > expr_1
        except TypeError as ex:
            self.l.warning(ex)
            return None

    def _handle_MBE(self, expr):  # pylint:disable=unused-argument
        # Yeah.... no.
        return None

    def _handle_32HLto64(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        return None


class SimEngineLightAILMixin:

    def _process(self, state, successors, *args, block=None, whitelist=None, **kwargs):  # pylint:disable=arguments-differ,unused-argument

        self.tmps = {}
        self.block: ailment.Block = block
        self.state = state
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
        handler = "_handle_%s" % expr_type_name
        if hasattr(self, handler):
            h = getattr(self, handler)

        if h is None:
            handler = "_ail_handle_%s" % expr_type_name
            if hasattr(self, handler):
                h = getattr(self, handler)

        if h is not None:
            return h(expr)
        self.l.warning('Unsupported expression type %s.', type(expr).__name__)
        return None

    #
    # Helper methods
    #

    def _codeloc(self):
        return CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr, context=self._context,
                            block_idx=self.block.idx)

    #
    # Statement handlers
    #

    def _handle_Stmt(self, stmt):
        handler = "_handle_%s" % type(stmt).__name__
        if hasattr(self, handler):
            getattr(self, handler)(stmt)
            return

        # compatibility
        old_handler = "_ail_handle_%s" % type(stmt).__name__
        if hasattr(self, old_handler):
            getattr(self, old_handler)(stmt)
            return

        self.l.warning('Unsupported statement type %s.', type(stmt).__name__)

    def _ail_handle_Jump(self, stmt):
        raise NotImplementedError('Please implement the Jump handler with your own logic.')

    def _ail_handle_Call(self, stmt):
        raise NotImplementedError('Please implement the Call handler with your own logic.')

    def _ail_handle_Return(self, stmt):
        raise NotImplementedError('Please implement the Return handler with your own logic.')

    #
    # Expression handlers
    #

    def _ail_handle_Const(self, expr):  # pylint:disable=no-self-use
        return expr.value

    def _ail_handle_Tmp(self, expr):
        tmp_idx = expr.tmp_idx

        try:
            return self.tmps[tmp_idx]
        except KeyError:
            return None

    def _ail_handle_Load(self, expr):
        raise NotImplementedError('Please implement the Load handler with your own logic.')

    def _ail_handle_CallExpr(self, expr):
        raise NotImplementedError('Please implement the CallExpr handler with your own logic.')

    def _ail_handle_UnaryOp(self, expr):
        handler_name = '_ail_handle_%s' % expr.op
        try:
            handler = getattr(self, handler_name)
        except AttributeError:
            self.l.warning('Unsupported UnaryOp %s.', expr.op)
            return None

        return handler(expr)

    def _ail_handle_BinaryOp(self, expr):
        handler_name = '_ail_handle_%s' % expr.op
        try:
            handler = getattr(self, handler_name)
        except AttributeError:
            self.l.warning('Unsupported BinaryOp %s.', expr.op)
            return None

        return handler(expr)

    #
    # Binary operation handlers
    #

    def _ail_handle_CmpLT(self, expr):

        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)
        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 <= expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(expr.idx, 'CmpLT', [expr_0, expr_1], expr.signed, **expr.tags)

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
            return ailment.Expr.BinaryOp(expr.idx, 'Add', [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Sub(self, expr):

        arg0, arg1 = expr.operands

        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 - expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(expr.idx, 'Sub', [expr_0, expr_1], expr.signed, **expr.tags)

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
            return ailment.Expr.BinaryOp(expr.idx, 'Div', [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_DivMod(self, expr):
        return self._ail_handle_Div(expr)

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
            return ailment.Expr.BinaryOp(expr.idx, 'Mul', [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Mull(self, expr):
        return self._ail_handle_Mul(expr)

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
            return ailment.Expr.BinaryOp(expr.idx, 'And', [expr_0, expr_1], expr.signed, **expr.tags)

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
            return ailment.Expr.BinaryOp(expr.idx, 'Or', [expr_0, expr_1], expr.signed, **expr.tags)

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
            return ailment.Expr.BinaryOp(expr.idx, 'Xor', [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Shr(self, expr):

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
            return ailment.Expr.BinaryOp(expr.idx, 'Shr', [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Shl(self, expr):

        arg0, arg1 = expr.operands
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        try:
            return expr_0 << expr_1
        except TypeError:
            return ailment.Expr.BinaryOp(expr.idx, 'Shl', [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Sal(self, expr):
        return self._ail_handle_Shl(expr)

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
            return ailment.Expr.BinaryOp(expr.idx, 'Sar', [expr_0, expr_1], expr.signed, **expr.tags)

    def _ail_handle_Concat(self, expr):

        arg0, arg1 = expr.operands
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        if expr_0 is None:
            expr_0 = arg0
        if expr_1 is None:
            expr_1 = arg1

        return ailment.Expr.BinaryOp(expr.idx, 'Concat', [expr_0, expr_1], expr.signed, **expr.tags)

    #
    # Unary operation handlers
    #

    def _ail_handle_Convert(self, expr):
        data = self._expr(expr.operand)
        if data is not None:
            if type(data) is int:
                return data
        return None

    def _ail_handle_Not(self, expr):

        data = self._expr(expr.operand)
        if data is None:
            return None

        try:
            return ~data  # pylint:disable=invalid-unary-operand-type
        except TypeError:
            return ailment.Expr.UnaryOp(expr.idx, 'Not', data, **expr.tags)


# Compatibility
SimEngineLightVEX = SimEngineLightVEXMixin
SimEngineLightAIL = SimEngineLightAILMixin
