import angr

######################################
# Unresolvable Call Target
######################################


class UnresolvableCallTarget(angr.SimProcedure):
    NO_RET = False

    def run(self):
        return
