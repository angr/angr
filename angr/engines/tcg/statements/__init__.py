from ....errors import UnsupportedIRStmtError, UnsupportedDirtyError, SimStatementError
from .... import sim_options as o

from .base import SimIRStmt
from .noop import SimIRStmt_NoOp
from .imark import SimIRStmt_IMark
from .abihint import SimIRStmt_AbiHint
from .wrtmp import SimIRStmt_WrTmp
from .put import SimIRStmt_Put
from .store import SimIRStmt_Store
from .mbe import SimIRStmt_MBE
from .dirty import SimIRStmt_Dirty
from .exit import SimIRStmt_Exit
from .cas import SimIRStmt_CAS
from .storeg import SimIRStmt_StoreG
from .loadg import SimIRStmt_LoadG
from .llsc import SimIRStmt_LLSC
from .puti import SimIRStmt_PutI

import logging
l = logging.getLogger("angr.engines.vex.statements.")

# def translate_stmt(stmt, state):
    # stmt_name = 'SimIRStmt_' +  type(stmt).__name__

    # if stmt_name in globals():
        # stmt_class = globals()[stmt_name]
        # s = stmt_class(stmt, state)
        # s.process()
        # return s
    # else:
        # l.error("Unsupported statement type %s", (type(stmt)))
        # if o.BYPASS_UNSUPPORTED_IRSTMT not in state.options:
            # raise UnsupportedIRStmtError("Unsupported statement type %s" % (type(stmt)))
        # state.history.add_event('resilience', resilience_type='irstmt', stmt=type(stmt).__name__, message='unsupported IRStmt')

def translate_stmt(stmt, state):
    stmt_name = 'INDEX_op_' + stmt.__name__

    if stmt_name == 'INDEX_op_mov_i64':
        pass
    elif stmt_name == 'INDEX_op_movi_i64':
        pass
    elif stmt_name == 'INDEX_op_mov_i32':
        pass
    elif stmt_name == 'INDEX_op_movi_i32':
        pass
    elif stmt_name == 'INDEX_op_call':
        pass
    elif stmt_name == 'INDEX_op_br':
        pass
    elif stmt_name == 'INDEX_op_setcond_i32':
        pass
    elif stmt_name == 'INDEX_op_setcond2_i32':
        pass
    elif stmt_name == 'INDEX_op_setcond_i64':
        pass
    elif stmt_name == 'INDEX_op_setcond2_i64':
        pass

    # Load/Store operations (32 bit)

    elif stmt_name == 'INDEX_op_ld8u_i32':
        pass
    elif stmt_name == 'INDEX_op_ld_i32':
        pass
    elif stmt_name == 'INDEX_op_st8_i32':
        pass
    elif stmt_name == 'INDEX_op_st16_i32':
        pass
    elif stmt_name == 'INDEX_op_st_i32':
        pass

    # Arithmatic operations (32 bit)

    elif stmt_name == 'INDEX_op_add_i32':
        pass
    elif stmt_name == 'INDEX_op_sub_i32':
        pass
    elif stmt_name == 'INDEX_op_mul_i32':
        pass
    elif stmt_name == 'INDEX_op_div_i32':
        pass
    elif stmt_name == 'INDEX_op_divu_i32':
        pass
    elif stmt_name == 'INDEX_op_rem_i32':
        pass
    elif stmt_name == 'INDEX_op_remu_i32':
        pass
    elif stmt_name == 'INDEX_op_and_i32':
        pass
    elif stmt_name == 'INDEX_op_or_i32':
        pass
    elif stmt_name == 'INDEX_op_xor_i32':
        pass

    # Shift/rotate operations (32 bit)

    elif stmt_name == 'INDEX_op_shl_i32':
        pass
    elif stmt_name == 'INDEX_op_shr_i32':
        pass
    elif stmt_name == 'INDEX_op_sar_i32':
        pass
    elif stmt_name == 'INDEX_op_rotl_i32':
        pass
    elif stmt_name == 'INDEX_op_rotr_i32':
        pass
    elif stmt_name == 'INDEX_op_deposit_i32':
        pass
    elif stmt_name == 'INDEX_op_brcond_i32':
        pass
    elif stmt_name == 'INDEX_op_add2_i32':
        pass
    elif stmt_name == 'INDEX_op_sub2_i32':
        pass
    elif stmt_name == 'INDEX_op_mul2_i32':
        pass
    elif stmt_name == 'INDEX_op_ext8s_i32':
        pass
    elif stmt_name == 'INDEX_op_ext16s_i32':
        pass
    elif stmt_name == 'INDEX_op_ext8u_i32':
        pass
    elif stmt_name == 'INDEX_op_ext16u_i32':
        pass
    elif stmt_name == 'INDEX_op_bswap16_i32':
        pass
    elif stmt_name == 'INDEX_op_bswap32_i32':
        pass
    elif stmt_name == 'INDEX_op_not_i32':
        pass
    elif stmt_name == 'INDEX_op_neg_i32':
        pass
    elif stmt_name == 'INDEX_op_exit_tb':
        pass
    elif stmt_name == 'INDEX_op_goto_tb':
        pass
    elif stmt_name == 'INDEX_op_qemu_ld_i32':
        pass
    elif stmt_name == 'INDEX_op_qemu_st_i32':
        pass
    elif stmt_name == 'INDEX_op_mb':
        pass
    else:
        # TODO
