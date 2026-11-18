from __future__ import annotations

import angr
from angr import claripy


class sigprocmask(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, how, set_, oldset, sigsetsize=None):
        if sigsetsize is None:
            # sys_sigprocmask, the pre-realtime syscall, carries a one-word
            # old_sigset_t and no size argument; sys_rt_sigprocmask takes the
            # size as its fourth.
            sigsetsize = claripy.BVV(self.state.arch.bytes, self.state.arch.bits)
        self.state.memory.store(oldset, self.state.posix.sigmask(sigsetsize=sigsetsize), condition=oldset != 0)
        self.state.posix.sigprocmask(how, self.state.memory.load(set_, sigsetsize), sigsetsize, valid_ptr=set_ != 0)

        # TODO: EFAULT
        return claripy.If(
            claripy.And(
                how != self.state.posix.SIG_BLOCK,
                how != self.state.posix.SIG_UNBLOCK,
                how != self.state.posix.SIG_SETMASK,
            ),
            claripy.BVV(self.state.posix.EINVAL, self.arch.sizeof["int"]),
            0,
        )
