import logging
from functools import reduce
from pytcg import TcgOp, TcgCall
from pyvex.const import get_type_size
l = logging.getLogger("angr.engines.vex.statements.base")

class SimIRStmt(object):
    """A class for symbolically translating VEX IRStmts."""

    def __init__(self, stmt, state):
        self.stmt = stmt
        self.state = state
        self.type = None
        # references by the statement
        self.actions = []
        self._constraints = [ ]
        # initialize args
        self._init_args(self)

    @staticmethod
    def _init_args(self):
        if type(self.stmt) == TcgOp:
            iargs = self.stmt.iargs
            cargs = self.stmt.cargs

            if len(iargs):
                # get iargs values in t1-tn
                for i in range(len(iargs)):
                    if 'tmp' in iargs[i]:
                        setattr(self, 't'+str(i+1), self.state.scratch.temps[iargs[i][3:]])
                    else:
                        setattr(self, 't'+str(i+1), getattr(self.state.regs, iargs[i]))

            elif len(cargs):
                # get cargs values
                for i in range(len(cargs)):
                    setattr(self, 't'+str(i+1), int(cargs[i]))
            # get oargs value
            self.t0 = self.stmt.oargs[0]

        elif type(self.stmt) == TcgCall:
            self.cc_src = self.state.regs.cc_src
            self.cc_src2 = self.state.regs.cc_src2
            self.cc_op = self.state.regs.cc_op
            self.cc_dst = self.state.regs.cc_dst
            self.helper = 'helper_' + self.stmt.helper

        else:
            pass


    def size_bits(self, ty=None):
        if not ty:
            if self.type is not None:
                return get_type_size(self.type)
            return len(self.stmt)
        else:
            # Allow subclasses to define which parameter they consider their size
            return get_type_size(ty)

    def size_bytes(self, ty=None):
        s = self.size_bits(ty)
        if s % self.state.arch.byte_width != 0:
            raise Exception("SimIRExpr.size_bytes() called for a non-byte size!")
        return s/self.state.arch.byte_width


    def process(self):
        """
        Process the statement, applying its effects on the state.
        """
        # this is where we would choose between different analysis modes
        self._execute()

    def _set_value(self, v):
        if 'tmp' in self.t0:
            self.state.scratch.temps[self.t0[3:]] = v
        else:
            setattr(self.state.regs, self.t0, v)

    def _execute(self):
        raise NotImplementedError()

    def _translate_expr(self, expr):
        """Translates an IRExpr into a SimIRExpr."""
        e = translate_expr(expr, self.state)
        self._record_expr(e)
        return e

    def _translate_exprs(self, exprs):
        """Translates a sequence of IRExprs into SimIRExprs."""
        return [ self._translate_expr(e) for e in exprs ]

    def _record_expr(self, expr):
        """Records the references of an expression."""
        self.actions.extend(expr.actions)

    def _add_constraints(self, *constraints):
        """Adds constraints to the state."""
        self._constraints.extend(constraints)
        self.state.add_constraints(*constraints)

    def _write_tmp(self, tmp, v, reg_deps, tmp_deps):
        """
        Writes an expression to a tmp.
        """
        self.state.scratch.store_tmp(tmp, v, reg_deps, tmp_deps)


