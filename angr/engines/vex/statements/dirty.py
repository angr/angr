from . import SimIRStmt
from .. import dirty
from .... import sim_options as o
from ....errors import UnsupportedDirtyError

import logging
l = logging.getLogger("angr.engines.vex.statements.dirty")

class SimIRStmt_Dirty(SimIRStmt):
    # Example:
    # t1 = DIRTY 1:I1 ::: ppcg_dirtyhelper_MFTB{0x7fad2549ef00}()
    def _execute(self):
        exprs = self._translate_exprs(self.stmt.args)

        if hasattr(dirty, self.stmt.cee.name):
            s_args = [ex.expr for ex in exprs]

            if o.ACTION_DEPS in self.state.options:
                if len(exprs) == 0:
                    reg_deps = frozenset()
                    tmp_deps = frozenset()
                else:
                    reg_deps = frozenset.union(*[e.reg_deps() for e in exprs])
                    tmp_deps = frozenset.union(*[e.tmp_deps() for e in exprs])
            else:
                reg_deps = None
                tmp_deps = None

            func = getattr(dirty, self.stmt.cee.name)
            retval, retval_constraints = func(self.state, *s_args)

            self._add_constraints(*retval_constraints)

            if self.stmt.tmp not in (0xffffffff, -1):
                self.state.scratch.store_tmp(self.stmt.tmp, retval, reg_deps, tmp_deps)
        else:
            l.error("Unsupported dirty helper %s", self.stmt.cee.name)
            raise UnsupportedDirtyError("Unsupported dirty helper %s" % self.stmt.cee.name)
