from __future__ import annotations

import logging

import angr
from angr.errors import AngrError, SimError

# pylint: disable=arguments-differ,unused-argument,no-self-use,inconsistent-return-statements

_l = logging.getLogger(name=__name__)


class pthread_create(angr.SimProcedure):
    """
    Simulates the new thread as an equally viable branch of symbolic execution.
    """

    ADDS_EXITS = True

    # pylint: disable=unused-argument,arguments-differ
    def run(self, thread, attr, start_routine, arg):
        self.call(start_routine, (arg,), "terminate_thread", prototype="void *start_routine(void*)")
        return 0

    def terminate_thread(self, thread, attr, start_routine, arg):
        self.exit(0)

    def static_exits(self, blocks, **kwargs):
        # the caller (CFG recovery) sets self.project before calling this method
        assert self.project is not None
        # Speculatively execute the blocks CFGFast lifted ahead of the callsite
        # with a blank state, and then dump the arguments. This is best-effort
        # throughout: the blocks need not even lie on a path to the call, and
        # executing them can fail in every way concrete execution can. A failure
        # here says nothing about the rest of the program, so it must degrade to
        # "no extra exits discovered" rather than abort recovery of the binary.
        blank_state = angr.SimState(project=self.project, mode="fastpath", cle_memory_backer=self.project.loader.memory)

        # Execute each block
        state = blank_state
        for b in blocks:
            try:
                irsb = self.project.factory.default_engine.process(state, b, force_addr=b.addr)
            except (AngrError, SimError) as ex:
                _l.debug("pthread_create.static_exits: cannot execute block %#x: %s", b.addr, ex)
                break
            # VEX turns every aligned SSE access into a guarded Ijk_SigSEGV exit,
            # so an -O2 block routinely yields several fault successors *before*
            # its real one, and they sort first. Continuing from a faulted state
            # is meaningless (its argument registers describe a path that traps),
            # and the failure engine refuses to execute Ijk_Sig* at all -- which
            # is what used to abort the whole CFG one block later.
            succ = next((s for s in irsb.successors if not s.history.jumpkind.startswith("Ijk_Sig")), None)
            if succ is None:
                break
            state = succ

        try:
            callfunc = self.cc.get_args(state, self.prototype)[2]
            retaddr = state.memory.load(state.regs.sp, size=self.arch.bytes)
        except (AngrError, SimError) as ex:
            _l.debug("pthread_create.static_exits: cannot recover the thread entry point: %s", ex)
            return []

        return [
            {"address": callfunc, "jumpkind": "Ijk_Call", "namehint": "thread_entry"},
            {"address": retaddr, "jumpkind": "Ijk_Ret", "namehint": None},
        ]


class pthread_cond_signal(angr.SimProcedure):
    """
    A no-op.
    """

    def run(self, arg):
        pass


class pthread_mutex_lock(angr.SimProcedure):
    """
    Always returns 0 (SUCCESS).
    """

    def run(self, arg):
        return 0


class pthread_mutex_unlock(angr.SimProcedure):
    """
    Always returns 0 (SUCCESS).
    """

    def run(self, arg):
        return 0


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
        return None

    def retsite(self, control, func):
        return 0

    # TODO: static exits
