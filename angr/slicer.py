# pylint:disable=no-self-use
from __future__ import annotations
import pyvex

from .errors import SimSlicerError


class SimLightState:
    """
    Represents a program state. Only used in SimSlicer.
    """

    __slots__ = (
        "temps",
        "regs",
        "stack_offsets",
        "options",
    )

    def __init__(self, temps=None, regs=None, stack_offsets=None, options=None):
        self.temps = temps if temps is not None else set()
        self.regs = regs if regs is not None else set()
        self.stack_offsets = stack_offsets if stack_offsets is not None else set()
        self.options = {} if options is None else options


class SimSlicer:
    """
    A super lightweight intra-IRSB slicing class.
    """

    def __init__(
        self,
        arch,
        statements,
        target_tmps=None,
        target_regs=None,
        target_stack_offsets=None,
        inslice_callback=None,
        inslice_callback_infodict=None,
        include_imarks: bool = True,
    ):
        self._arch = arch
        self._statements = statements
        self._target_tmps = target_tmps if target_tmps is not None else set()
        self._target_regs = target_regs if target_regs is not None else set()
        self._target_stack_offsets = target_stack_offsets if target_stack_offsets is not None else set()

        self._inslice_callback = inslice_callback
        self._include_imarks = include_imarks

        # It could be accessed publicly
        self.inslice_callback_infodict = inslice_callback_infodict

        self.stmts = []
        self.stmt_indices = []
        self.final_regs = set()
        self.final_stack_offsets = set()

        if not self._target_tmps and not self._target_regs and not self._target_stack_offsets:
            raise SimSlicerError(
                'You must specify at least one of the following: "'
                "target temps, target registers, and/or target stack offsets."
            )

        # convert target registers to base registers
        target_base_regs = set()
        for target_reg in self._target_regs:
            base_reg = self._arch.get_base_register(target_reg)
            if base_reg is None:
                target_base_regs.add(target_reg)
            else:
                target_base_regs.add(base_reg[0])
        self._target_regs = target_base_regs

        self._aliases = {}

        self._alias_analysis()
        self._slice()

    def _alias_analysis(self, mock_sp=True, mock_bp=True):
        """
        Perform a forward execution and perform alias analysis. Note that this analysis is fast, light-weight, and by no
        means complete. For instance, most arithmetic operations are not supported.

        - Depending on user settings, stack pointer and stack base pointer will be mocked and propagated to individual
          tmps.

        :param bool mock_sp: propagate stack pointer or not
        :param bool mock_bp: propagate stack base pointer or not
        :return: None
        """

        state = SimLightState(
            regs={
                self._arch.sp_offset: self._arch.initial_sp,
                # TODO: take care of the relation between sp and bp
                self._arch.bp_offset: self._arch.initial_sp + 0x2000,
            },
            temps={},
            options={
                "mock_sp": mock_sp,
                "mock_bp": mock_bp,
            },
        )

        for stmt in self._statements:
            self._forward_handler_stmt(stmt, state)

    #
    # Forward execution IRStmt handlers
    #

    def _forward_handler_stmt(self, stmt, state):
        """

        :param stmt:
        :param SimLightState state:
        :return:
        """

        funcname = f"_forward_handler_stmt_{type(stmt).__name__}"

        if hasattr(self, funcname):
            getattr(self, funcname)(stmt, state)

    def _forward_handler_stmt_WrTmp(self, stmt, state):
        tmp = stmt.tmp

        val = self._forward_handler_expr(stmt.data, state)

        if val is not None:
            state.temps[tmp] = val
            self._aliases[tmp] = val

    #
    # Forward execution IRExpr handlers
    #

    def _forward_handler_expr(self, expr, state):
        """

        :param stmt:
        :param SimLightState state:
        :return:
        """

        funcname = f"_forward_handler_expr_{type(expr).__name__}"

        if hasattr(self, funcname):
            return getattr(self, funcname)(expr, state)

        return None

    def _forward_handler_expr_Get(self, expr, state):
        reg = expr.offset

        if (
            state.options["mock_sp"]
            and reg == self._arch.sp_offset
            or state.options["mock_bp"]
            and reg == self._arch.bp_offset
        ):
            return state.regs[reg]

        return None

    def _forward_handler_expr_RdTmp(self, expr, state):
        tmp = expr.tmp

        if tmp in state.temps:
            return state.temps[tmp]

        return None

    def _forward_handler_expr_Const(self, expr, state):  # pylint:disable=unused-argument
        return expr.con.value

    def _forward_handler_expr_Binop(self, expr, state):
        funcname = "_forward_handler_expr_binop_{}".format(expr.op.strip("Iop_"))

        if hasattr(self, funcname):
            op0_val = self._forward_handler_expr(expr.args[0], state)
            op1_val = self._forward_handler_expr(expr.args[1], state)
            if op0_val is not None and op1_val is not None:
                return getattr(self, funcname)(op0_val, op1_val, state)

        return None

    def _forward_handler_expr_binop_Add64(self, op0, op1, state):  # pylint:disable=unused-argument
        return (op0 + op1) & (2**64 - 1)

    def _forward_handler_expr_binop_Add32(self, op0, op1, state):  # pylint:disable=unused-argument
        return (op0 + op1) & (2**32 - 1)

    #
    # Backward slicing
    #

    def _slice(self):
        """
        Slice it!
        """

        regs = set(self._target_regs)
        tmps = set(self._target_tmps)
        stack_offsets = set(self._target_stack_offsets)

        state = SimLightState(regs=regs, temps=tmps, stack_offsets=stack_offsets)

        for stmt_idx, stmt in reversed(list(enumerate(self._statements))):
            if self._backward_handler_stmt(stmt, state):
                self.stmts.insert(0, stmt)
                self.stmt_indices.insert(0, stmt_idx)

                if self._inslice_callback:
                    self._inslice_callback(stmt_idx, stmt, self.inslice_callback_infodict)

            if not regs and not tmps and not stack_offsets:
                break

        self.final_regs = state.regs
        self.final_stack_offsets = state.stack_offsets

    #
    # Backward slice IRStmt handlers
    #

    def _backward_handler_stmt(self, stmt, state):
        funcname = f"_backward_handler_stmt_{type(stmt).__name__}"

        in_slice = False
        if hasattr(self, funcname):
            in_slice = getattr(self, funcname)(stmt, state)

        return in_slice

    def _backward_handler_stmt_IMark(self, stmt, state) -> bool:  # pylint:disable=unused-argument
        # include all IMark statements
        return self._include_imarks

    def _backward_handler_stmt_WrTmp(self, stmt, state):
        tmp = stmt.tmp

        if tmp not in state.temps:
            return False

        state.temps.remove(tmp)

        self._backward_handler_expr(stmt.data, state)

        return True

    def _backward_handler_stmt_Put(self, stmt: pyvex.IRStmt.Put, state):
        reg = stmt.offset
        # convert it to its base register
        base_reg = self._arch.get_base_register(reg)
        if base_reg is not None:
            reg = base_reg[0]

        if reg in state.regs:
            state.regs.remove(reg)

            self._backward_handler_expr(stmt.data, state)

            return True

        return False

    def _backward_handler_stmt_Store(self, stmt, state):
        addr = stmt.addr

        if type(addr) is pyvex.IRExpr.RdTmp:
            tmp = addr.tmp

            if tmp in self._aliases:
                # We know its value
                concrete_addr = self._aliases[tmp]
                if concrete_addr in state.stack_offsets:
                    # It's written at this statement
                    state.stack_offsets.remove(concrete_addr)
                    self._backward_handler_expr(addr, state)
                    self._backward_handler_expr(stmt.data, state)

                    return True

        return False

    def _backward_handler_stmt_LoadG(self, expr, state):
        if expr.dst not in state.temps:
            return False

        state.temps.remove(expr.dst)

        self._backward_handler_expr(expr.guard, state)
        self._backward_handler_expr(expr.addr, state)
        self._backward_handler_expr(expr.alt, state)

        return True

    #
    # Backward slice IRExpr handlers
    #

    def _backward_handler_expr(self, expr, state):
        funcname = f"_backward_handler_expr_{type(expr).__name__}"
        if hasattr(self, funcname):
            getattr(self, funcname)(expr, state)

    def _backward_handler_expr_RdTmp(self, expr, state):
        tmp = expr.tmp

        state.temps.add(tmp)

    def _backward_handler_expr_Get(self, expr, state):
        reg = expr.offset
        # convert it to its base register
        base_reg = self._arch.get_base_register(reg)
        if base_reg is not None:
            reg = base_reg[0]

        state.regs.add(reg)

    def _backward_handler_expr_Load(self, expr, state):
        addr = expr.addr

        if type(addr) is pyvex.IRExpr.RdTmp:
            self._backward_handler_expr(addr, state)

            # Do we know the concrete value of this tmp?
            tmp = addr.tmp
            if tmp in self._aliases:
                # awesome!
                state.stack_offsets.add(self._aliases[tmp])

    def _backward_handler_expr_Unop(self, expr, state):
        arg = expr.args[0]

        if type(arg) is pyvex.IRExpr.RdTmp:
            self._backward_handler_expr(arg, state)

    def _backward_handler_expr_CCall(self, expr, state):
        for arg in expr.args:
            if type(arg) is pyvex.IRExpr.RdTmp:
                self._backward_handler_expr(arg, state)

    def _backward_handler_expr_Binop(self, expr, state):
        for arg in expr.args:
            if type(arg) is pyvex.IRExpr.RdTmp:
                self._backward_handler_expr(arg, state)

    def _backward_handler_expr_ITE(self, expr, state):
        self._backward_handler_expr(expr.cond, state)
        self._backward_handler_expr(expr.iftrue, state)
        self._backward_handler_expr(expr.iffalse, state)
