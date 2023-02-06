import angr

######################################
# stub, for unsupported syscalls
######################################


# pylint:disable=redefined-builtin,arguments-differ
class syscall(angr.SimProcedure):
    def run(self, *args, resolves=None):
        self.resolves = resolves  # pylint:disable=attribute-defined-outside-init

        if self.successors is not None:
            self.successors.artifacts["resolves"] = resolves

        # code duplicated from ReturnUnconstrained
        size = self.prototype.returnty.size
        # ummmmm do we really want to rely on this behavior?
        if size is NotImplemented:
            return None
        else:
            return self.state.solver.Unconstrained(
                "syscall_stub_%s" % self.display_name, size, key=("syscall", "?", self.display_name)
            )

    def __repr__(self):
        if "resolves" in self.kwargs:
            return "<Syscall stub (%s)>" % self.kwargs["resolves"]
        else:
            return "<Syscall stub>"
