from __future__ import annotations
import angr


class vsnprintf(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, str_ptr, size, fmt, ap):  # pylint:disable=unused-argument
        # This function returns
        # Add another exit to the retn_addr that is at the top of the stack now

        if self.state.solver.eval(size) == 0:
            return 0

        self.state.memory.store(str_ptr, b"\x00")

        return 1
