from socket import inet_ntoa as _inet_ntoa
from typing import List, Optional

from claripy import BVS, BVV, Concat
from claripy.ast import BV

import angr
from angr.procedures.posix.mmap import (MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ,
                                        PROT_WRITE)
from angr.sim_type import SimStructValue


class inet_ntoa(angr.SimProcedure):
    """
    inet_ntoa simprocedure
    """

    # inet_ntoa is for ipv4 addresses, so we do not need 4(6|8) bytes to store it
    INET_INADDRSTRLEN = 16
    # inet_ntoa internal static buffer
    static_buffer: Optional[BV] = None

    def run(  # type: ignore # pylint:disable=arguments-differ,unused-argument
        self, addr_in: SimStructValue
    ):
        """
        Run the simprocedure

        :param addr_in: inet_addr struct (which is just a 32-bit int)
        """

        mmap: angr.SimProcedure = angr.SIM_PROCEDURES["posix"]["mmap"]

        if self.static_buffer is None:
            # inet_ntoa uses an internal static buffer for its return value
            # that is overwritten on subsequent calls -- I think this is an
            # okay way to emulate that behavior
            self.static_buffer = self.inline_call(
                mmap,
                0,
                self.INET_INADDRSTRLEN,
                PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE,
                -1,
                0,
            ).ret_expr

        rv_exprs: List[BV] = []
        addr_s_in = addr_in["s_addr"]

        if addr_s_in.concrete:
            addr_in_i32 = self.state.solver.eval_one(addr_s_in, default=0)
            inet_str = (
                # "big" is network byte ordering, we want to preserve it in net order
                # because `inet_ntoa` expects to be given that ordering (but in bytes
                # and not a python int)
                bytes(_inet_ntoa(addr_in_i32.to_bytes(4, "big")), "utf-8")
                + b"\x00"
            )
            rv_exprs.extend(
                map(lambda b: BVV(b, size=self.state.arch.byte_width), inet_str)
            )
        else:
            rv_exprs.extend(
                map(
                    lambda i: BVS(f"inet_ntoa_{i}", size=self.state.arch.byte_width),
                    range(self.INET_INADDRSTRLEN),
                )
            )

            rv_exprs.append(BVV(0, size=self.state.arch.byte_width))

        buf_data = Concat(*rv_exprs)

        self.state.memory.store(
            # No endness here -- would store it backward (nul-first)
            self.static_buffer,
            buf_data,
        )

        return self.static_buffer
