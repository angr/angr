import angr

######################################
# exit
######################################

#pylint:disable=redefined-builtin,arguments-differ
class exit(angr.SimProcedure):
    NO_RET = True
    IS_SYSCALL = True

    def run(self, exit_code):
        self.exit(exit_code)

