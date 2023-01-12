import angr


class gethostbyname(angr.SimProcedure):
    def run(self, name):
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
        place = self.inline_call(malloc, 32).ret_expr
        self.state.memory.store(
            place, self.state.solver.BVS("h_name", 64, key=("api", "gethostbyname", "h_name")), endness="Iend_LE"
        )
        self.state.memory.store(
            place, self.state.solver.BVS("h_aliases", 64, key=("api", "gethostbyname", "h_aliases")), endness="Iend_LE"
        )
        self.state.memory.store(
            place,
            self.state.solver.BVS("h_addrtype", 64, key=("api", "gethostbyname", "h_addrtype")),
            endness="Iend_LE",
        )
        self.state.memory.store(
            place, self.state.solver.BVS("h_length", 64, key=("api", "gethostbyname", "h_length")), endness="Iend_LE"
        )
        self.state.memory.store(
            place,
            self.state.solver.BVS("h_addr_list", 64, key=("api", "gethostbyname", "h_addr_list")),
            endness="Iend_LE",
        )
        return place
