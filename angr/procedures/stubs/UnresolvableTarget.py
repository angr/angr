import angr

######################################
# Unresolvable Target
######################################


class UnresolvableTarget(angr.SimProcedure):
    NO_RET = True

    def run(self):
        return
