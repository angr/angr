from __future__ import annotations
import angr


class time(angr.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, time_ptr):
        linux_time = angr.SIM_PROCEDURES["linux_kernel"]["time"]
        return self.inline_call(linux_time, time_ptr).ret_expr
