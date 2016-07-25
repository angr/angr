
from pyvex.expr import RdTmp, Get

from .base import SimIRExpr
from ... import s_options as o
from ...s_errors import UnsupportedIROpError, SimOperationError
from ..irop import translate
from ...s_action import SimActionOperation, SimActionObject

class SimIRExpr_Op(SimIRExpr):
    def _execute(self):
        exprs = self._translate_exprs(self._expr.args)

        try:
            self.expr = translate(self.state, self._expr.op, [ e.expr for e in exprs ])

            if o.TRACK_OP_ACTIONS in self.state.options:
                action_objects = [ ]
                for arg, ex in zip(self._expr.args, exprs):
                    if isinstance(arg, RdTmp):
                        action_objects.append(SimActionObject(ex.expr, tmp_deps=frozenset({arg.tmp})))
                    elif isinstance(arg, Get):
                        action_objects.append(SimActionObject(ex.expr, reg_deps=frozenset({arg.offset})))
                    else:
                        action_objects.append(SimActionObject(ex.expr))
                r = SimActionOperation(self.state, self._expr.op, action_objects)
                self.actions.append(r)

        except UnsupportedIROpError as e:
            if o.BYPASS_UNSUPPORTED_IROP in self.state.options:
                self.state.log.add_event('resilience', resilience_type='irop', op=self._expr.op, message='unsupported IROp')
                if o.UNSUPPORTED_BYPASS_ZERO_DEFAULT in self.state.options:
                    self.expr = self.state.se.BVV(0, self.size_bits())
                else:
                    self.expr = self.state.se.Unconstrained(type(self._expr).__name__, self.size_bits())
                if self.type.startswith('Ity_F'):
                    self.expr = self.expr.raw_to_fp()
            else:
                raise
        except SimOperationError as e:
            e.bbl_addr = self.state.scratch.bbl_addr
            e.stmt_idx = self.state.scratch.stmt_idx
            e.ins_addr = self.state.scratch.ins_addr
            e.executed_instruction_count = self.state.scratch.executed_instruction_count
            raise

class SimIRExpr_Unop(SimIRExpr_Op): pass
class SimIRExpr_Binop(SimIRExpr_Op): pass
class SimIRExpr_Triop(SimIRExpr_Op): pass
class SimIRExpr_Qop(SimIRExpr_Op): pass
