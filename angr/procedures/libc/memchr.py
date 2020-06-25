import angr
import logging

l = logging.getLogger(name=__name__)


class memchr(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, a_addr, b_int, limit):  # pylint:disable=arguments-differ
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        a_strlen = self.inline_call(strlen, a_addr)
        a_len = a_strlen.ret_expr

        b = b_int[7:0]
        # b = self.state.solver.BVV(203, 8)

        match_constraints = []
        ret_expr = self.state.solver.Unconstrained(
            "memchr_ret", self.state.arch.bits, key=('api', 'memchr'))

        concrete_run = False
        if self.state.solver.single_valued(a_len) and self.state.solver.single_valued(limit):
            c_a_len = self.state.solver.eval(a_len)
            c_limit = self.state.solver.eval(limit)
            maxlen = min(c_a_len, c_limit)
            concrete_run = True
        else:
            if self.state.solver.single_valued(limit):
                c_limit = self.state.solver.eval(limit)
                maxlen = min(a_strlen.max_null_index, c_limit)
            else:
                maxlen = a_strlen.max_null_index

        if maxlen == 0:
            return self.state.solver.BVV(0, self.state.arch.bits)

        # the string bytes
        a_bytes = self.state.memory.load(a_addr, maxlen, endness='Iend_BE')

        for i in range(maxlen):
            l.debug("Processing byte %d", i)
            maxbit = (maxlen-i)*8
            a_byte = a_bytes[maxbit-1:maxbit-8]

            if concrete_run and self.state.solver.single_valued(a_byte) and self.state.solver.single_valued(b):
                a_conc = self.state.solver.eval(a_byte)
                b_conc = self.state.solver.eval(b)

                if a_conc == b_conc:
                    l.debug(
                        "... found matched concrete bytes 0x%x and 0x%x", a_conc, b_conc)
                    return a_addr + self.state.solver.BVV(i, self.state.arch.bits)
            else:
                concrete_run = False

            byte_constraint = self.state.solver.And(a_byte == b, ret_expr == (
                a_addr + self.state.solver.BVV(i, self.state.arch.bits)))
            match_constraints.append(byte_constraint)

        if concrete_run:
            l.debug("concrete run made it to the end!")
            return self.state.solver.BVV(0, self.state.arch.bits)

        l.debug("returning symbolic")
        match_constraint = self.state.solver.Or(*match_constraints)
        nomatch_constraint = self.state.solver.Not(match_constraint)

        match_case = self.state.solver.And(
            maxlen != 0, match_constraint)
        nomatch_case = self.state.solver.And(
            nomatch_constraint, ret_expr == self.state.solver.BVV(0, self.state.arch.bits))

        self.state.add_constraints(
            self.state.solver.Or(match_case, nomatch_case))

        return ret_expr
