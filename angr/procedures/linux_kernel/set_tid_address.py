import angr

######################################
# set_tid_address
######################################

#pylint:disable=redefined-builtin,arguments-differ
class set_tid_address(angr.SimProcedure):
    def run(self, tidptr):
        return 0  # Assume it's single-threaded, so only tid 0 exists
