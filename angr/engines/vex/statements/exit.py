from . import SimIRStmt
from .. import translate_irconst

from .... import sim_options as o
from ....state_plugins.sim_action_object import SimActionObject
from ....state_plugins.sim_action import SimActionExit

class SimIRStmt_Exit(SimIRStmt):
    def __init__(self, stmt, state):
        SimIRStmt.__init__(self, stmt, state)

        self.guard = None
        self.target = None
        self.jumpkind = None

    def _execute(self):
        guard_irexpr = self._translate_expr(self.stmt.guard)
        self.guard = guard_irexpr.expr != 0

        # get the destination
        self.target = translate_irconst(self.state, self.stmt.dst)
        self.jumpkind = self.stmt.jumpkind

        if o.TRACK_JMP_ACTIONS in self.state.options:
            guard_ao = SimActionObject(self.guard, reg_deps=guard_irexpr.reg_deps(), tmp_deps=guard_irexpr.tmp_deps())
            self.actions.append(SimActionExit(self.state, target=self.target, condition=guard_ao, exit_type=SimActionExit.CONDITIONAL))
