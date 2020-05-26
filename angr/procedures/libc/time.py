import angr
import time as _time

class time(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, time_ptr):
        linux_time = angr.SIM_PROCEDURES['linux_kernel']['time']
        ts_bv = linux_time.run(time_ptr)
        self.state.memory.store(time_ptr, ts_bv)
