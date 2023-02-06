import angr

# pylint: disable=arguments-differ,unused-argument,no-self-use,inconsistent-return-statements


######################################
# pthread_create
# simulates the new thread as an equally viable branch of symbolic execution
######################################
class pthread_create(angr.SimProcedure):
    ADDS_EXITS = True

    # pylint: disable=unused-argument,arguments-differ
    def run(self, thread, attr, start_routine, arg):
        self.call(start_routine, (arg,), "terminate_thread", prototype="void *start_routine(void*)")
        return 0

    def terminate_thread(self, thread, attr, start_routine, arg):
        self.exit(0)

    def static_exits(self, blocks, **kwargs):
        # Execute those blocks with a blank state, and then dump the arguments
        blank_state = angr.SimState(project=self.project, mode="fastpath", cle_memory_backer=self.project.loader.memory)

        # Execute each block
        state = blank_state
        for b in blocks:
            irsb = self.project.factory.default_engine.process(state, b, force_addr=b.addr)
            if irsb.successors:
                state = irsb.successors[0]
            else:
                break

        callfunc = self.cc.get_args(state, self.prototype)[2]
        retaddr = state.memory.load(state.regs.sp, size=self.arch.bytes)

        all_exits = [
            {"address": callfunc, "jumpkind": "Ijk_Call", "namehint": "thread_entry"},
            {"address": retaddr, "jumpkind": "Ijk_Ret", "namehint": None},
        ]

        return all_exits


######################################
# pthread_cond_signal
# a no-op
######################################


class pthread_cond_signal(angr.SimProcedure):
    def run(self, arg):
        pass


######################################
# pthread_mutex_lock
# also a no-op
######################################


class pthread_mutex_lock(angr.SimProcedure):
    def run(self, arg):
        pass


######################################
# pthread_mutex_unlock
# also a no-op
######################################


class pthread_mutex_unlock(angr.SimProcedure):
    def run(self, arg):
        pass


######################################
# pthread_once
######################################


class pthread_once(angr.SimProcedure):
    def run(self, control, func):
        controlword = self.state.mem[control].char.resolved
        if (controlword & 2).symbolic:
            raise angr.errors.SimProcedureError("Cannot handle symbolic control data for pthread_once")
        if self.state.solver.is_true(controlword & 2 != 0):
            return 0

        controlword |= 2
        self.state.mem[control].char = controlword
        self.call(func, (), "retsite", prototype="void x()")

    def retsite(self, control, func):
        return 0

    # TODO: static exits
