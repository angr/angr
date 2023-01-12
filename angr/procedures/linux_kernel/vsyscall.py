import angr
import claripy


class _vsyscall(angr.SimProcedure):
    NO_RET = True

    # This is pretty much entirely copied from SimProcedure.ret
    def run(self):  # pylint: disable=arguments-differ
        if self.state.arch.call_pushes_ret:
            ret_addr = self.state.stack_pop()
        else:
            ret_addr = self.state.registers.load(self.state.arch.lr_offset, self.state.arch.bytes)

        self.successors.add_successor(self.state, ret_addr, claripy.true, "Ijk_Sys")
