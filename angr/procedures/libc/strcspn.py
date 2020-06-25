import angr
import logging

l = logging.getLogger(name=__name__)


class strcspn(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, a_addr, b_addr):  # pylint:disable=arguments-differ
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        a_strlen = self.inline_call(strlen, a_addr)
        b_strlen = self.inline_call(strlen, b_addr)

        a_len = a_strlen.ret_expr
        b_len = b_strlen.ret_expr

        concrete_run = False
        if self.state.solver.single_valued(a_len):
            max_a_len = self.state.solver.eval(a_len)
            concrete_run = True
        else:
            max_a_len = a_strlen.max_null_index

        if self.state.solver.single_valued(b_len):
            max_b_len = self.state.solver.eval(b_len)
        else:
            max_b_len = b_strlen.max_null_index
            concrete_run = False

        a_bytes = self.state.memory.load(a_addr, max_a_len, endness='Iend_BE')
        b_bytes = self.state.memory.load(b_addr, max_b_len, endness='Iend_BE')

        match_constraints = []
        ret_expr = self.state.solver.Unconstrained(
            "strcspn_ret", self.state.arch.bits, key=('api', 'strcspn'))

        for i in range(max_a_len):
            a_maxbit = (max_a_len-i)*8
            a_byte = a_bytes[a_maxbit-1:a_maxbit-8]
            for j in range(max_b_len):
                b_maxbit = (max_b_len-j)*8
                b_byte = b_bytes[b_maxbit-1:b_maxbit-8]

                if concrete_run and self.state.solver.single_valued(a_byte) and self.state.solver.single_valued(b_byte):
                    a_conc = self.state.solver.eval(a_byte)
                    b_conc = self.state.solver.eval(b_byte)

                    if a_conc == b_conc:
                        return self.state.solver.BVV(i, self.state.arch.bits)
                else:
                    concrete_run = False

                byte_constraint = self.state.solver.And(
                    a_byte == b_byte, ret_expr == self.state.solver.BVV(i, self.state.arch.bits))
                match_constraints.append(byte_constraint)

        if concrete_run:
            return self.state.solver.BVV(max_a_len, self.state.arch.bits)

        match_constraint = self.state.solver.Or(*match_constraints)
        nomatch_constraint = self.state.solver.Not(match_constraint)

        match_case = self.state.solver.And(
            max_a_len != 0, max_b_len != 0, match_constraint)
        nomatch_case = self.state.solver.And(
            nomatch_constraint, ret_expr == self.state.solver.BVV(max_a_len, self.state.arch.bits))

        self.state.add_constraints(
            self.state.solver.Or(match_case, nomatch_case))

        return ret_expr
