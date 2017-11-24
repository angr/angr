import angr
import pyvex

######################################
# pthread_create
# simulates the new thread as an equally viable branch of symbolic execution
######################################
class pthread_create(angr.SimProcedure):
    ADDS_EXITS = True

    # pylint: disable=unused-argument,arguments-differ
    def run(self, thread, attr, start_routine, arg):
        self.call(start_routine, (arg,), 'terminate_thread')
        self.ret(self.state.se.BVV(0, self.state.arch.bits))

    def terminate_thread(self, thread, attr, start_routine, arg):
        self.exit(0)

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
