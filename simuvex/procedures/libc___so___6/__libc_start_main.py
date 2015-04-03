import simuvex

######################################
# __libc_start_main
######################################
class __libc_start_main(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    ADDS_EXITS = True

    def run(self, main_addr, argc, argv, exit_addr=0):
        # TODO: handle symbolic and static modes
        # TODO: add argument types

        initial_registers = { }

        if self.state.arch.name == "PPC32":
            # for some dumb reason, PPC32 passes arguments to libc_start_main in some completely absurd way
            argv = argc
            argc = main_addr
            main_addr = self.state.mem_expr(self.state.regs.r8 + 4, 4, endness=self.state.arch.memory_endness)

            # TODO: Properly set up R2 as well, just as in PPC64

        elif self.state.arch.name == "PPC64":
            main_addr = self.state.mem_expr(self.state.regs.r8 + 8, 8, endness=self.state.arch.memory_endness)
            if self.state.libc.abiv == 'ppc64_1':
                main_addr_ref = main_addr
                main_addr = self.state.mem_expr(main_addr_ref, 8, endness=self.state.arch.memory_endness)
                initial_registers['r2'] = self.state.mem_expr(main_addr_ref + 8, 8, endness=self.state.arch.memory_endness)

        elif self.state.arch.name == "MIPS32":
            initial_registers['t9'] = main_addr

        if self.state.arch.name == "ARM":
            if self.state.se.any_int(main_addr) %2 == 1:
                thumb = self.state.BVV(1)
                self.state.regs.thumb = thumb

        # set argc and argv
        self.set_args((argc, argv))

        # Create the new state as well
        new_state = self.state
        word_len = self.state.arch.bits

        # Manually return to exit() in order to force the program to terminate
        retn_addr_expr = self.state.se.BVV(exit_addr, word_len)

        if self.state.arch.name in ("AMD64", "X86"):
            new_state.stack_push(retn_addr_expr)
        elif self.state.arch.name in ('MIPS32',):
            new_state.regs.ra = retn_addr_expr
        else:
            # TODO: Other architectures
            pass

        # Set the initial values of those registers
        for r, v in initial_registers.items():
            new_state.store_reg(r, v)

        self.add_successor(new_state, main_addr, new_state.se.true, 'Ijk_Call')
