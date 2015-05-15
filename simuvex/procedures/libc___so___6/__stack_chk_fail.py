import simuvex

######################################
# __stack_chk_fail
######################################


class __stack_chk_fail(simuvex.SimProcedure):

    NO_RET = True

    def run(self, exit_code): #pylint:disable=unused-argument
        return
