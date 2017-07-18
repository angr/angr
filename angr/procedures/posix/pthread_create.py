import angr
import pyvex

######################################
# pthread_create
# obviously adapted from __libc_start_main
######################################
class pthread_create(angr.SimProcedure):
    ADDS_EXITS = True

    def run(self):

        # Get main pc from arguments
        code_addr = self.arg(2)
        func_arg = self.arg(3)

        # Create the new state as well
        new_state=self.state.copy()
        new_state.stack_push(func_arg)
        # This is a stupid hack, but it should cause the simulated execution to halt on returning, which is correct
        new_state.stack_push(self.state.se.BVV(0, self.state.arch.bits))

        self.successors.add_successor(new_state, code_addr, new_state.se.true, 'Ijk_Call')
        return self.state.se.BVV(0, self.state.arch.bits)

    def static_exits(self, blocks):
        # Execute those blocks with a blank state, and then dump the arguments
        blank_state = angr.SimState(project=self.project, mode="fastpath")

        # Execute each block
        state = blank_state
        for b in blocks:
            irsb = angr.SimEngineVEX().process(state, b,
                    force_addr=next(iter(stmt for stmt in b.statements if isinstance(stmt, pyvex.IRStmt.IMark))).addr
                                                  )
            if irsb.successors:
                state = irsb.successors[0]
            else:
                break

        cc = angr.DEFAULT_CC[self.arch.name](self.arch)
        callfunc = cc.arg(state, 2)
        retaddr = state.memory.load(state.regs.sp, self.arch.bytes)

        all_exits = [
            (callfunc, 'Ijk_Call'),
            (retaddr, 'Ijk_Ret')
        ]

        return all_exits
