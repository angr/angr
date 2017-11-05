import angr
import logging

l = logging.getLogger('angr.procedures.stubs.CallReturn')

class CallReturn(angr.SimProcedure):
    NO_RET = True

    def run(self):
        l.info("A factory.call_state-created path returned!")
        return
