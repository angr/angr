from __future__ import annotations
import angr


# pylint:disable=redefined-builtin,arguments-differ
class syscall(angr.SimProcedure):
    def run(self, *args, resolves=None):
        self.resolves = resolves  # pylint:disable=attribute-defined-outside-init

        if self.successors is not None:
            self.successors.artifacts["resolves"] = resolves

        # code duplicated from ReturnUnconstrained
        size = self.prototype.returnty.size
        if size is None:
            return None
        return self.state.solver.Unconstrained(
            f"syscall_stub_{self.display_name}", size, key=("syscall", "?", self.display_name)
        )

    def __repr__(self):
        if "resolves" in self.kwargs:
            return "<Syscall stub ({})>".format(self.kwargs["resolves"])
        return "<Syscall stub>"
