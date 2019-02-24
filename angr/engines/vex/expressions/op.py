from pyvex.const import get_type_size
from pyvex.expr import RdTmp, Get, get_op_retty

from ..irop import translate
from .... import sim_options as o
from ....errors import UnsupportedIROpError, SimOperationError
from ....state_plugins.sim_action import SimActionOperation, SimActionObject


def SimIRExpr_Op(engine, state, expr):
    exprs = [engine.handle_expression(state, e) for e in expr.args]

    try:
        result = translate(state, expr.op, exprs)

        if o.TRACK_OP_ACTIONS in state.options:
            action_objects = []
            for arg, ex in zip(expr.args, exprs):
                if isinstance(arg, RdTmp):
                    action_objects.append(SimActionObject(ex, tmp_deps=frozenset({arg.tmp})))
                elif isinstance(arg, Get):
                    action_objects.append(SimActionObject(ex, reg_deps=frozenset({arg.offset})))
                else:
                    action_objects.append(SimActionObject(ex))
            r = SimActionOperation(state, expr.op, action_objects, result)
            state.history.add_action(r)

    except UnsupportedIROpError:
        if o.BYPASS_UNSUPPORTED_IROP in state.options:
            state.history.add_event('resilience', resilience_type='irop', op=expr.op, message='unsupported IROp')
            res_type = get_op_retty(expr.tag)
            res_size = get_type_size(res_type)
            if o.UNSUPPORTED_BYPASS_ZERO_DEFAULT in state.options:
                result = state.solver.BVV(0, res_size)
            else:
                result = state.solver.Unconstrained(type(expr).__name__, res_size)
            if res_type.startswith('Ity_F'):
                result = result.raw_to_fp()
        else:
            raise
    except SimOperationError as e:
        e.bbl_addr = state.scratch.bbl_addr
        e.stmt_idx = state.scratch.stmt_idx
        e.ins_addr = state.scratch.ins_addr
        e.executed_instruction_count = state.history.recent_instruction_count
        raise

    return result

SimIRExpr_Unop = SimIRExpr_Op
SimIRExpr_Binop = SimIRExpr_Op
SimIRExpr_Triop = SimIRExpr_Op
SimIRExpr_Qop = SimIRExpr_Op
