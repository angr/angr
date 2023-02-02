import angr

import logging

l = logging.getLogger(name=__name__)


class strncmp(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(
        self, a_addr, b_addr, limit, a_len=None, b_len=None, wchar=False, ignore_case=False
    ):  # pylint:disable=arguments-differ
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        char_size = 1 if not wchar else 2

        a_strlen = a_len if a_len is not None else self.inline_call(strlen, a_addr, wchar=wchar)
        b_strlen = b_len if b_len is not None else self.inline_call(strlen, b_addr, wchar=wchar)

        a_len = a_strlen.ret_expr
        b_len = b_strlen.ret_expr

        match_constraints = []
        variables = a_len.variables | b_len.variables | limit.variables
        ret_expr = self.state.solver.Unconstrained("strncmp_ret", 32, key=("api", "strncmp"))

        # determine the maximum number of bytes to compare
        concrete_run = False
        if (
            self.state.solver.single_valued(a_len)
            and self.state.solver.single_valued(b_len)
            and self.state.solver.single_valued(limit)
        ):
            c_a_len = self.state.solver.eval(a_len)
            c_b_len = self.state.solver.eval(b_len)
            c_limit = self.state.solver.eval(limit)

            l.debug("everything is concrete: a_len %d, b_len %d, limit %d", c_a_len, c_b_len, c_limit)

            if (c_a_len < c_limit or c_b_len < c_limit) and c_a_len != c_b_len:
                l.debug("lengths < limit and unmatched")

            concrete_run = True
            maxlen = min(c_a_len, c_b_len, c_limit)
        else:
            if self.state.solver.single_valued(limit):
                c_limit = self.state.solver.eval(limit)
                maxlen = min(a_strlen.max_null_index, b_strlen.max_null_index, c_limit)
            else:
                maxlen = max(a_strlen.max_null_index, b_strlen.max_null_index)

            match_constraints.append(
                self.state.solver.Or(
                    a_len == b_len,
                    self.state.solver.And(self.state.solver.UGE(a_len, limit), self.state.solver.UGE(b_len, limit)),
                )
            )

        if maxlen == 0:
            # there is a corner case: if a or b are not both empty string, and limit is greater than 0, we should return
            # non-equal. Basically we only return equal when limit is 0, or a_len == b_len == 0
            if self.state.solver.single_valued(limit) and self.state.solver.eval(limit) == 0:
                # limit is 0
                l.debug("returning equal for 0-limit")
                return self.state.solver.BVV(0, 32)
            elif (
                self.state.solver.single_valued(a_len)
                and self.state.solver.single_valued(b_len)
                and self.state.solver.eval(a_len) == self.state.solver.eval(b_len) == 0
            ):
                # two empty strings
                l.debug("returning equal for two empty strings")
                return self.state.solver.BVV(0, 32)
            else:
                # all other cases fall into this branch
                l.debug("returning non-equal for comparison of an empty string and a non-empty string")
                if a_strlen.max_null_index == 0:
                    return self.state.solver.BVV(-1, 32)
                else:
                    return self.state.solver.BVV(1, 32)

        # the bytes
        max_byte_len = maxlen * char_size
        a_bytes = self.state.memory.load(a_addr, max_byte_len, endness="Iend_BE")
        b_bytes = self.state.memory.load(b_addr, max_byte_len, endness="Iend_BE")

        # TODO: deps

        # all possible return values in static mode
        return_values = []

        for i in range(max_byte_len):
            l.debug("Processing byte %d", i)
            maxbit = (max_byte_len - i) * 8
            a_byte = a_bytes[maxbit - 1 : maxbit - 8]
            b_byte = b_bytes[maxbit - 1 : maxbit - 8]

            if concrete_run and self.state.solver.single_valued(a_byte) and self.state.solver.single_valued(b_byte):
                a_conc = self.state.solver.eval(a_byte)
                b_conc = self.state.solver.eval(b_byte)
                variables |= a_byte.variables
                variables |= b_byte.variables

                if ignore_case:
                    # convert both to lowercase
                    if ord("a") <= a_conc <= ord("z"):
                        a_conc -= ord(" ")
                    if ord("a") <= b_conc <= ord("z"):
                        b_conc -= ord(" ")

                if a_conc != b_conc:
                    l.debug("... found mis-matching concrete bytes 0x%x and 0x%x", a_conc, b_conc)
                    if a_conc < b_conc:
                        return self.state.solver.BVV(-1, 32)
                    else:
                        return self.state.solver.BVV(1, 32)
            else:
                if self.state.mode == "static":
                    return_values.append(a_byte - b_byte)

                concrete_run = False

            if self.state.mode != "static":
                if ignore_case:
                    byte_constraint = self.state.solver.Or(
                        self.state.solver.Or(
                            a_byte == b_byte,
                            self.state.solver.And(
                                ord("A") <= a_byte,
                                a_byte <= ord("Z"),
                                ord("a") <= b_byte,
                                b_byte <= ord("z"),
                                b_byte - ord(" ") == a_byte,
                            ),
                            self.state.solver.And(
                                ord("A") <= b_byte,
                                b_byte <= ord("Z"),
                                ord("a") <= a_byte,
                                a_byte <= ord("z"),
                                a_byte - ord(" ") == b_byte,
                            ),
                        ),
                        self.state.solver.ULT(a_len, i),
                        self.state.solver.ULT(limit, i),
                    )
                else:
                    byte_constraint = self.state.solver.Or(
                        a_byte == b_byte, self.state.solver.ULT(a_len, i), self.state.solver.ULT(limit, i)
                    )
                match_constraints.append(byte_constraint)

        if concrete_run:
            l.debug("concrete run made it to the end!")
            return self.state.solver.BVV(0, 32)

        if self.state.mode == "static":
            ret_expr = self.state.solver.ESI(8)
            for expr in return_values:
                ret_expr = ret_expr.union(expr)

            ret_expr = ret_expr.sign_extend(24)

        else:
            # make the constraints

            l.debug("returning symbolic")
            match_constraint = self.state.solver.And(*match_constraints)
            nomatch_constraint = self.state.solver.Not(match_constraint)

            # l.debug("match constraints: %s", match_constraint)
            # l.debug("nomatch constraints: %s", nomatch_constraint)

            match_case = self.state.solver.And(limit != 0, match_constraint, ret_expr == 0)
            nomatch_case = self.state.solver.And(limit != 0, nomatch_constraint, ret_expr == 1)
            l0_case = self.state.solver.And(limit == 0, ret_expr == 0)
            empty_case = self.state.solver.And(a_strlen.ret_expr == 0, b_strlen.ret_expr == 0, ret_expr == 0)

            self.state.add_constraints(self.state.solver.Or(match_case, nomatch_case, l0_case, empty_case))

        return ret_expr
