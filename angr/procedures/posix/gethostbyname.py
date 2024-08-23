from __future__ import annotations
import angr


class gethostbyname(angr.SimProcedure):
    def run(self, name):
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
        int_size_bits = self.arch.sizeof["int"]
        int_size = int_size_bits // 8
        ptr_size_bits = self.arch.bits
        ptr_size = ptr_size_bits // 8
        hostent_size = (2 * int_size) + (3 * ptr_size)
        place = self.inline_call(malloc, hostent_size).ret_expr
        self.state.memory.store(
            place,
            self.state.solver.BVS("h_name", ptr_size_bits, key=("api", "gethostbyname", "h_name")),
            endness="Iend_LE",
        )
        next_addr = place + ptr_size
        self.state.memory.store(
            next_addr,
            self.state.solver.BVS("h_aliases", ptr_size_bits, key=("api", "gethostbyname", "h_aliases")),
            endness="Iend_LE",
        )
        next_addr += ptr_size
        self.state.memory.store(
            next_addr,
            self.state.solver.BVS("h_addrtype", int_size_bits, key=("api", "gethostbyname", "h_addrtype")),
            endness="Iend_LE",
        )
        next_addr += int_size
        self.state.memory.store(
            next_addr,
            self.state.solver.BVS("h_length", int_size_bits, key=("api", "gethostbyname", "h_length")),
            endness="Iend_LE",
        )
        next_addr += int_size
        self.state.memory.store(
            next_addr,
            self.state.solver.BVS("h_addr_list", ptr_size_bits, key=("api", "gethostbyname", "h_addr_list")),
            endness="Iend_LE",
        )
        return place
