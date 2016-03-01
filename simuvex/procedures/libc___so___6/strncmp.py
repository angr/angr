import simuvex
from simuvex.s_type import SimTypeString, SimTypeLength, SimTypeInt

import logging
l = logging.getLogger("simuvex.procedures.libc.strncmp")

class strncmp(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, a_addr, b_addr, limit, a_len=None, b_len=None): #pylint:disable=arguments-differ
        # TODO: smarter types here?
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                       1: self.ty_ptr(SimTypeString()),
                       2: SimTypeLength(self.state.arch)}
        self.return_type = SimTypeInt(32, True)

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']

        a_strlen = a_len if a_len is not None else self.inline_call(strlen, a_addr)
        b_strlen = b_len if b_len is not None else self.inline_call(strlen, b_addr)

        a_len = a_strlen.ret_expr
        b_len = b_strlen.ret_expr

        match_constraints = [ ]
        variables = a_len.variables | b_len.variables | limit.variables
        ret_expr = self.state.se.Unconstrained("strncmp_ret", self.state.arch.bits)

        # determine the maximum number of bytes to compare
        concrete_run = False
        #if not self.state.se.symbolic(a_len) and not self.state.se.symbolic(b_len) and not self.state.se.symbolic(limit):
        if self.state.se.single_valued(a_len) and self.state.se.single_valued(b_len) and self.state.se.single_valued(limit):
            c_a_len = self.state.se.any_int(a_len)
            c_b_len = self.state.se.any_int(b_len)
            c_limit = self.state.se.any_int(limit)

            l.debug("everything is concrete: a_len %d, b_len %d, limit %d", c_a_len, c_b_len, c_limit)

            if (c_a_len < c_limit or c_b_len < c_limit) and c_a_len != c_b_len:
                l.debug("lengths < limit and unmatched")

            concrete_run = True
            maxlen = min(c_a_len, c_b_len, c_limit)
        else:
            if self.state.se.single_valued(limit):
                c_limit = self.state.se.any_int(limit)
                maxlen = min(a_strlen.max_null_index, b_strlen.max_null_index, c_limit)
            else:
                maxlen = max(a_strlen.max_null_index, b_strlen.max_null_index)

            match_constraints.append(self.state.se.Or(a_len == b_len, self.state.se.And(self.state.se.UGE(a_len, limit), self.state.se.UGE(b_len, limit))))

        if maxlen == 0:
            l.debug("returning equal for 0-length maximum strings")
            return self.state.se.BVV(0, self.state.arch.bits, variables=variables)

        # the bytes
        a_bytes = self.state.memory.load(a_addr, maxlen, endness='Iend_BE')
        b_bytes = self.state.memory.load(b_addr, maxlen, endness='Iend_BE')

        # TODO: deps

        # all possible return values in static mode
        return_values = [ ]

        for i in range(maxlen):
            l.debug("Processing byte %d", i)
            maxbit = (maxlen-i)*8
            a_byte = a_bytes[maxbit-1:maxbit-8]
            b_byte = b_bytes[maxbit-1:maxbit-8]

            if concrete_run and self.state.se.single_valued(a_byte) and self.state.se.single_valued(b_byte):
                a_conc = self.state.se.any_int(a_byte)
                b_conc = self.state.se.any_int(b_byte)
                variables |= a_byte.variables
                variables |= b_byte.variables

                if a_conc != b_conc:
                    l.debug("... found mis-matching concrete bytes 0x%x and 0x%x", a_conc, b_conc)
                    if a_conc < b_conc:
                        return self.state.se.BVV(-1, self.state.arch.bits, variables=variables)
                    else:
                        return self.state.se.BVV(1, self.state.arch.bits, variables=variables)
            else:

                if self.state.mode == 'static':
                    return_values.append(a_byte - b_byte)

                concrete_run = False

            if self.state.mode != 'static':
                byte_constraint = self.state.se.Or(a_byte == b_byte, self.state.se.ULT(a_len, i), self.state.se.ULT(limit, i))
                match_constraints.append(byte_constraint)

        if concrete_run:
            l.debug("concrete run made it to the end!")
            return self.state.se.BVV(0, self.state.arch.bits, variables=variables)

        if self.state.mode == 'static':
            ret_expr = self.state.se.ESI(8)
            for expr in return_values:
                ret_expr = ret_expr.union(expr)

            ret_expr = ret_expr.sign_extend(self.state.arch.bits - 8)

        else:
            # make the constraints

            l.debug("returning symbolic")
            match_constraint = self.state.se.And(*match_constraints)
            nomatch_constraint = self.state.se.Not(match_constraint)

            #l.debug("match constraints: %s", match_constraint)
            #l.debug("nomatch constraints: %s", nomatch_constraint)

            match_case = self.state.se.And(limit != 0, match_constraint, ret_expr == 0)
            nomatch_case = self.state.se.And(limit != 0, nomatch_constraint, ret_expr == 1)
            l0_case = self.state.se.And(limit == 0, ret_expr == 0)
            empty_case = self.state.se.And(a_strlen.ret_expr == 0, b_strlen.ret_expr == 0, ret_expr == 0)

            self.state.add_constraints(self.state.se.Or(match_case, nomatch_case, l0_case, empty_case))

        return ret_expr
