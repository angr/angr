import pyvex
import claripy

from ..light.slicing import VEXSlicingMixin
from .... import sim_options as o

class SuperFastpathMixin(VEXSlicingMixin):
    def handle_vex_block(self, irsb):
        # This option makes us only execute the last four instructions
        if o.SUPER_FASTPATH in self.state.options:
            imark_counter = 0
            for i in range(len(irsb.statements) - 1, -1, -1):
                if type(irsb.statements[i]) is pyvex.IRStmt.IMark:
                    imark_counter += 1
                if imark_counter >= 4:
                    self._skip_stmts = max(self._skip_stmts, i)
                    break

        super().handle_vex_block(irsb)

    def _perform_vex_expr_RdTmp(self, tmp):
        try:
            return super()._perform_vex_expr_RdTmp(tmp)
        except LookupError:
            if o.SUPER_FASTPATH in self.state.options:
                return claripy.BVV(0, pyvex.get_type_size(self.irsb.tyenv.lookup(tmp)))
            else:
                raise

