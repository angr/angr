from ....errors import UnsupportedIRStmtError, UnsupportedDirtyError, SimStatementError
from .... import sim_options as o
from .base import SimIRStmt
from .cc_helper import helper_cc_compute_c

import logging
import claripy
import IPython
l = logging.getLogger("angr.engines.vex.statements.")

class insn_start(SimIRStmt):
    def _execute(self):
        self.state.history.recent_instruction_count += 1


class mov_i64(SimIRStmt):
    def _execute(self):
        '''
        t1 = self.stmt.iargs[0]
        t0 = self.stmt.oargs[0]
        if 'tmp' in t0:
            if 'tmp' not in t1 and t1 in dir(self.state.regs):
                idx = int(t0[3:])
                self.state.scratch.temps[idx] = getattr(self.state.regs, t1)
        else:
            IPython.embed()
        '''
        self._set_value(self.t1)


class movi_i64(SimIRStmt):
    def _execute(self):
        '''
        t1 = self.stmt.cargs[0]
        t0 = self.stmt.oargs[0]
        if 'tmp' in t0:
            idx = int(t0[3:])
            self.state.scratch.temps[idx] = int(t1)
        else:
            IPython.embed()
        '''
        self._set_value(claripy.BVV(self.t1, 64))

class add_i64(SimIRStmt):
    def _execute(self):
        '''
        iargs = self.stmt.iargs
        t0 = self.stmt.oargs[0]
        import ipdb
        ipdb.set_trace()
        map(lambda i: setattr(self, 't'+str(i+1), iargs[i]), (i for i in range(len(iargs))))
        if 'tmp' in t0:
            idx = int(t0[3:])
            if 'tmp' in (t1, t2):
                val1, val2 = map(lambda x: self.state.scratch.temps[int(x[3:])], (x for x in iargs))
            else:
                val1 , val2 = map(lambda x: getattr(self.state.regs, x), (x for x in iargs))
            self.state.scratch.temps[idx] = val1 + val2
            '''
        self._set_value(self.t1 + self.t2)

class extu_i32_i64(SimIRStmt):
    def _execute(self):
        # extract lower 32 bytes
        if self.t1.length == 64:
            low = claripy.Extract(31, 0, self.t1)
            self._set_value(claripy.ZeroExt(32, low))
        else:
            self._set_value(claripy.ZeroExt(32, self.t1))

class ext32u_i64(extu_i32_i64):
        pass

class call(SimIRStmt):
    def _execute(self):
        if self.helper in globals():
            cc_helper = globals()[self.helper]
            return cc_helper(self.cc_dst, self.cc_src, self.cc_src2, self.cc_op)

def translate_stmt(stmt, state):
    stmt_name = stmt.__name__

    if stmt_name in globals():
        stmt_class = globals()[stmt_name]
        s = stmt_class(stmt, state)
        s.process()
        return s
    else:
        IPython.embed()
        l.error("Unsupported statement type %s", (type(stmt)))
        if o.BYPASS_UNSUPPORTED_IRSTMT not in state.options:
            raise UnsupportedIRStmtError("Unsupported statement type %s" % (type(stmt)))
        state.history.add_event('resilience', resilience_type='irstmt', stmt=type(stmt).__name__, message='unsupported IRStmt')

