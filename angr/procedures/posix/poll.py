from __future__ import annotations
import select

import claripy

import angr


class poll(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, fds, nfds, timeout):  # pylint: disable=unused-argument
        try:
            nfds_v = self.state.solver.eval_one(nfds)
        except angr.errors.SimSolverError as e:
            raise angr.errors.SimProcedureArgumentError("Can't handle symbolic pollfd arguments") from e
        ###
        # struct pollfd {
        #     int   fd;         /* file descriptor */
        #     short events;     /* requested events */
        #     short revents;    /* returned events */
        # };
        size_of_pollfd = 8
        offset_fd = 0
        offset_events = 4
        offset_revents = 6

        pollfd_array = []
        for offset in range(nfds_v):
            pollfd = {
                "fd": self.state.memory.load(
                    fds + offset * size_of_pollfd + offset_fd, 4, endness=self.arch.memory_endness
                ),
                "events": self.state.memory.load(
                    fds + offset * size_of_pollfd + offset_events, 2, endness=self.arch.memory_endness
                ),
                "revents": self.state.memory.load(
                    fds + offset * size_of_pollfd + offset_revents, 2, endness=self.arch.memory_endness
                ),
            }
            pollfd_array.append(pollfd)
        for offset, pollfd in enumerate(pollfd_array):
            try:
                fd = self.state.solver.eval_one(pollfd["fd"])
                events = self.state.solver.eval_one(pollfd["events"])
            except angr.errors.SimSolverError as e:
                raise angr.errors.SimProcedureArgumentError("Can't handle symbolic pollfd arguments") from e

            if events & select.POLLIN and fd >= 0:
                revents = pollfd["revents"][self.arch.sizeof["short"] - 1 : 1].concat(claripy.BVS("fd_POLLIN", 1))
                self.state.memory.store(
                    fds + offset * size_of_pollfd + offset_revents, revents, endness=self.arch.memory_endness
                )

        return claripy.BVV(0, 1).concat(claripy.BVS("poll_ret", self.state.arch.bits - 1))
