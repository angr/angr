import claripy
import pyvex

from ....engines.vex.heavy.heavy import HeavyVEXMixin

class DataSensitiveHeavyVEXMixin(HeavyVEXMixin):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _handle_vex_defaultexit(self, expr, jumpkind):
        if isinstance(expr, pyvex.expr.RdTmp):
            self.state.globals['cur_block_id'] = expr.block_id
        else:
            self.state.globals['cur_block_id'] = expr.con.block_id
        super()._handle_vex_defaultexit(expr, jumpkind)

    def _handle_vex_stmt_Exit(self, stmt):
        self.state.globals['cur_block_id'] = stmt.dst.block_id
        super()._handle_vex_stmt_Exit(stmt)
