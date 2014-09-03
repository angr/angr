import simuvex

######################################
# exit
######################################

class exit(simuvex.SimProcedure):
    def __init__(self):
        # FIXME: code ref: Where is it the address of the current statment?
        # self.add_refs(simuvex.SimCodeRef(self.addr, self.stmt_from, current_addr, (), ()))

        # no exits from this block
        return

