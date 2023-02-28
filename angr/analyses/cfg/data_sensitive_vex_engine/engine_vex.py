import claripy
import pyvex

from ....engines.vex.heavy.heavy import HeavyVEXMixin

class DataSensitiveHeavyVEXMixin(HeavyVEXMixin):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _handle_vex_defaultexit(self, expr, jumpkind):
        super()._handle_vex_defaultexit(expr, jumpkind)
        if isinstance(expr, pyvex.expr.RdTmp):
            if expr.block_id:
                self.state.globals['cur_block_id'] = expr.block_id
        else:
            if expr.con.block_id:
                self.state.globals['cur_block_id'] = expr.con.block_id

    def _handle_vex_stmt_Exit(self, stmt):
        super()._handle_vex_stmt_Exit(stmt)
        if stmt.dst.block_id:
            self.state.globals['cur_block_id'] = stmt.dst.block_id
