from __future__ import annotations
import itertools

import claripy

import angr
from angr.state_plugins.sim_action_object import SimActionObject

rand_count = itertools.count()


class random(angr.SimProcedure):
    # pylint:disable=arguments-differ,missing-class-docstring

    def run(self, buf, count, rnd_bytes, concrete_data=None):
        if isinstance(rnd_bytes, SimActionObject):
            rnd_bytes = rnd_bytes.ast

        if self.state.mode == "fastpath":
            # Special case for CFG
            if (
                not self.state.solver.symbolic(count)
                and not self.state.solver.symbolic(buf)
                and not self.state.solver.symbolic(rnd_bytes)
            ):
                if (
                    self.state.solver.is_true(rnd_bytes != 0) and self.state.cgc.addr_invalid(rnd_bytes)
                ) or self.state.cgc.addr_invalid(buf):
                    return self.state.cgc.EFAULT

                max_count = self.state.solver.eval_one(count)
                random_num = self.state.solver.Unconstrained(f"random_{next(rand_count)}", max_count * 8)
                self.state.memory.store(buf, random_num, size=count)
                if self.state.solver.is_true(rnd_bytes != 0):
                    self.state.memory.store(rnd_bytes, count, endness="Iend_LE")

            # We always return something in fastpath mode
            return claripy.BVV(0, self.state.arch.bits)

        # return code
        r = claripy.ite_cases(
            (
                (self.state.cgc.addr_invalid(buf), self.state.cgc.EFAULT),
                (claripy.And(rnd_bytes != 0, self.state.cgc.addr_invalid(rnd_bytes)), self.state.cgc.EFAULT),
            ),
            claripy.BVV(0, self.state.arch.bits),
        )

        if self.state.satisfiable(extra_constraints=[count != 0]):
            max_size = min(
                self.state.solver.max_int(count * 8),
                0x10000,
            )

            if concrete_data:
                value = claripy.BVS(f"random_{next(rand_count)}", max_size)
                self.state.preconstrainer.preconstrain(concrete_data, value)
            else:
                value = self.state.solver.Unconstrained(
                    f"random_{next(rand_count)}", max_size, key=("syscall", "random")
                )

            self.state.memory.store(buf, value, size=count)

        self.state.memory.store(rnd_bytes, count, endness="Iend_LE", condition=rnd_bytes != 0)

        return r
