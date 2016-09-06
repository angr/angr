from . import SimIRStmt
from ... import s_options as o
from .. import size_bits
from .. import dirty
from ...s_errors import UnsupportedDirtyError

import logging
l = logging.getLogger('simuvex.vex.statements.dirty')

class SimIRStmt_Dirty(SimIRStmt):
    # Example:
    # t1 = DIRTY 1:I1 ::: ppcg_dirtyhelper_MFTB{0x7fad2549ef00}()
    def _execute(self):
        exprs = self._translate_exprs(self.stmt.args)
        if self.stmt.tmp not in (0xffffffff, -1):
            retval_size = size_bits(self.irsb.tyenv.types[self.stmt.tmp])

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
                self._write_tmp(self.stmt.tmp, retval, retval_size, reg_deps, tmp_deps)
        else:
            l.error("Unsupported dirty helper %s", self.stmt.cee.name)
            if o.BYPASS_UNSUPPORTED_IRDIRTY not in self.state.options:
                raise UnsupportedDirtyError("Unsupported dirty helper %s" % self.stmt.cee.name)
            elif self.stmt.tmp not in (0xffffffff, -1):
                retval = self.state.se.Unconstrained("unsupported_dirty_%s" % self.stmt.cee.name, retval_size)
                self._write_tmp(self.stmt.tmp, retval, retval_size, None, None)

            self.state.log.add_event('resilience', resilience_type='dirty', dirty=self.stmt.cee.name, message='unsupported Dirty call')

