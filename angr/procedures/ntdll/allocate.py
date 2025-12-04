from __future__ import annotations
from angr.sim_procedure import SimProcedure
from angr.procedures.win32.VirtualAlloc import VirtualAlloc


class NtAllocateVirtualMemory(SimProcedure):
    def run(self, proc, addr_p, zerobits, size, ty, prot):
        # assume for now proc is current process. lord have mercy otherwise
        (oldval,) = self.state.solver.eval_atmost(self.state.mem[addr_p].uintptr_t.resolved, 1)
        r = self.inline_call(VirtualAlloc, oldval, size, ty, prot)
        if r.ret_expr == 0:  # returns an int, thanks
            return 1
        self.state.mem[addr_p].uintptr_t = r.ret_expr
        return 0
