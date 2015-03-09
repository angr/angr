
import pyvex

from .s_errors import SimSlicerError

class SimSlicer(object):
    """
    A super lightweight single-IRSB slicing class.
    """
    def __init__(self, statements, target_tmps=None, target_regs=None, inslice_callback=None, inslice_callback_infodict=None):
        self._statements = statements
        self._target_tmps = target_tmps if target_tmps else set()
        self._target_regs = target_regs if target_regs else set()

        self._inslice_callback = inslice_callback

        # It could be accessed publicly
        self.inslice_callback_infodict = inslice_callback_infodict

        self.stmts = [ ]
        self.stmt_indices = [ ]
        self.final_regs = set()

        if not self._target_tmps and not self._target_regs:
            raise SimSlicerError('Target temps and/or registers must be specified.')

        self._slice()

    def _slice(self):
        """
        Slice it!
        """

        regs = set(self._target_regs)
        tmps = set(self._target_tmps)

        for stmt_idx, stmt in reversed(list(enumerate(self._statements))):
            if self._backward_handler_stmt(stmt, tmps, regs):
                self.stmts.insert(0, stmt)
                self.stmt_indices.insert(0, stmt_idx)

                if self._inslice_callback:
                    self._inslice_callback(stmt_idx, stmt, self.inslice_callback_infodict)

            if not regs and not tmps:
                break

        self.final_regs = regs

    #
    # Backward slice IRStmt handlers
    #

    def _backward_handler_stmt(self, stmt, temps, regs):
        funcname = "_backward_handler_stmt_%s" % type(stmt).__name__

        in_slice = False
        if hasattr(self, funcname):
            in_slice = getattr(self, funcname)(stmt, temps, regs)

        return in_slice

    def _backward_handler_stmt_WrTmp(self, stmt, temps, regs):
        tmp = stmt.tmp

        if tmp not in temps:
            return False

        temps.remove(tmp)

        self._backward_handler_expr(stmt.data, temps, regs)

        return True

    def _backward_handler_stmt_Put(self, stmt, temps, regs):
        reg = stmt.offset

        if reg in regs:
            regs.remove(reg)

            self._backward_handler_expr(stmt.data, temps, regs)

            return True

        else:
            return False

    #
    # Backward slice IRExpr handlers
    #

    def _backward_handler_expr(self, expr, temps, regs):
        funcname = "_backward_handler_expr_%s" % type(expr).__name__
        in_slice = False
        if hasattr(self, funcname):
            in_slice = getattr(self, funcname)(expr, temps, regs)

        return in_slice

    def _backward_handler_expr_RdTmp(self, expr, temps, regs):
        tmp = expr.tmp

        temps.add(tmp)

    def _backward_handler_expr_Get(self, expr, temps, regs):
        reg = expr.offset

        regs.add(reg)

    def _backward_handler_expr_Load(self, expr, temps, regs):
        addr = expr.addr

        if type(addr) is pyvex.IRExpr.RdTmp:
            # FIXME: Process other types
            self._backward_handler_expr(addr, temps, regs)

    def _backward_handler_expr_Unop(self, expr, temps, regs):
        arg = expr.args[0]

        if type(arg) is pyvex.IRExpr.RdTmp:
            self._backward_handler_expr(arg, temps, regs)

    def _backward_handler_expr_CCall(self, expr, temps, regs):

        for arg in expr.args:
            if type(arg) is pyvex.IRExpr.RdTmp:
                self._backward_handler_expr(arg, temps, regs)

    def _backward_handler_expr_Binop(self, expr, temps, regs):

        for arg in expr.args:
            if type(arg) is pyvex.IRExpr.RdTmp:
                self._backward_handler_expr(arg, temps, regs)
