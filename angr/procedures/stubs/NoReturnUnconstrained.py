from __future__ import annotations
import angr


class NoReturnUnconstrained(angr.SimProcedure):  # pylint:disable=redefined-builtin
    """
    Use in places you would put ReturnUnconstrained as a default action but the function shouldn't actually return.
    """

    NO_RET = True

    def run(self, **kwargs):  # pylint:disable=unused-argument
        self.exit(self.state.solver.Unconstrained("unconstrained_exit_code", self.state.arch.bits))
