import angr

######################################
# Unresolvable Jump Target
######################################


class UnresolvableJumpTarget(angr.SimProcedure):
    NO_RET = True

    def run(self):
        return
