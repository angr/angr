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

        if self.state.arch.name == "PPC32":
            # for some dumb reason, PPC32 passes arguments to libc_start_main in some completely absurd way
            main_addr = self.state.mem_expr(self.state.reg_expr(48) + 4, 4, endness=self.state.arch.memory_endness)
        elif self.state.arch.name == "PPC64":
            main_addr = self.state.mem_expr(self.state.reg_expr(80) + 8, 8, endness=self.state.arch.memory_endness)
            if self.state.abiv == 'ppc64_1':
                main_addr = self.state.mem_expr(main_addr, 8, endness=self.state.arch.memory_endness)

        # set argc and argv
        self.set_args((argc, argv))

        # Create the new state as well
        new_state = self.state.copy()
        word_len = self.state.arch.bits

        # Manually return to exit() in order to force the program to terminate
        retn_addr_expr = self.state.se.BVV(exit_addr, word_len)

        if self.state.arch.name in ("AMD64", "X86"):
            new_state.stack_push(retn_addr_expr)
        elif self.state.arch.name in ('MIPS32'):
            new_state.store_reg('ra', retn_addr_expr)
        else:
            # TODO: Other architectures
            pass

        if self.state.arch.name == "MIPS32":
            new_state.store_reg('t9', main_addr)

        self.add_exits(simuvex.s_exit.SimExit(expr=main_addr, state=new_state, jumpkind='Ijk_Call'))
