import simuvex
import symexec

######################################
# __uClibc_main
######################################
class __uClibc_main(simuvex.SimProcedure):
    def __init__(self):
        # TODO: handle symbolic and static modes

        if self.state.arch.name == "PPC32":
            # for some dumb reason, PPC32 passes arguments to libc_start_main in some completely absurd way
            main_addr = self.state.mem_expr(self.state.reg_expr(48) + 4, 4)

        elif self.state.arch.name == "MIPS32":
            # Get main pc from register v0
            main_addr = self.state.reg_expr(2)

        else:
            # Get main pc from arguments
            main_addr = self.get_arg_value(0)

        self.exit_return(main_addr)

        # Create the new state as well
        # TODO: This is incomplete and is something just works
        # for example. it doesn't support argc and argc correctly
        new_state=self.state.copy()
        # Pushes 24 words and the retn addressb
        word_len = self.state.arch.bits
        # Read the existing retn address
        retn_addr_expr = self.state.stack_read(0, word_len / 8, bp=False)
        for i in range(0, 24):
            new_state.stack_push(symexec.BitVecVal(0, word_len))
        new_state.stack_push(retn_addr_expr)

        self.add_exits(simuvex.s_exit.SimExit(expr=main_addr.expr, state=new_state))
        self.add_refs(simuvex.SimCodeRef(self.addr, self.stmt_from, main_addr, [], []))
