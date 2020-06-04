import angr
import logging

l = logging.getLogger(name=__name__)


class strpbrk(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, a_addr, b_addr):  # pylint:disable=arguments-differ
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        # strlen and len expr
        a_strlen = self.inline_call(strlen, a_addr)
        b_strlen = self.inline_call(strlen, b_addr)
        a_len_expr = a_strlen.ret_expr
        b_len_expr = b_strlen.ret_expr

        l.debug("'a' addr: %s", a_addr)
        l.debug("'b' addr: %s", b_addr)
        l.debug("'a' len expr: %s", a_len_expr)
        l.debug("'b' len expr: %s", b_len_expr)

        # single value or not
        sv_a_len = self.state.solver.single_valued(a_len_expr)
        sv_b_len = self.state.solver.single_valued(b_len_expr)

        # length of a and b
        a_len = self.state.solver.eval(a_len_expr) if sv_a_len else a_strlen.max_null_index
        b_len = self.state.solver.eval(b_len_expr) if sv_b_len else b_strlen.max_null_index

        l.debug("'a' len: %s", a_len)
        l.debug("'b' len: %s", b_len)

        # 0 expr when return
        ret_0 = self.state.solver.BVV(0, self.state.arch.bits)

        concrete_run = False
        if sv_a_len and sv_b_len:
            concrete_run = True
        if a_len == 0 or b_len == 0:
            return ret_0

        # match constraints and return expr
        match_constraints_list = []
        ret_expr = self.state.solver.Unconstrained(
            "strpbrk_ret", self.state.arch.bits, key=('api', 'strpbrk'))

        # the string bytes
        a_bytes = self.state.memory.load(a_addr, a_len, endness='Iend_BE')
        b_bytes = self.state.memory.load(b_addr, b_len, endness='Iend_BE')

        l.debug("'a' bytes: %s", a_bytes)

        # compare a bytes and b bytes
        for i in range(a_len):
            a_bit_index = (a_len - i) * 8
            a_byte = a_bytes[a_bit_index - 1: a_bit_index - 8]
            a_addr_offset = a_addr + self.state.solver.BVV(i, self.state.arch.bits)

            l.debug("Processing 'a' byte: %s", a_byte)

            sv_a_byte = self.state.solver.single_valued(a_byte)

            for j in range(b_len):
                b_bit_index = (b_len - j) * 8
                b_byte = b_bytes[b_bit_index - 1: b_bit_index - 8]

                if concrete_run and sv_a_byte and self.state.solver.single_valued(b_byte):
                    a_conc = self.state.solver.eval(a_byte)
                    b_conc = self.state.solver.eval(b_byte)

                    if a_conc == b_conc:
                        l.debug(
                            "... found matched concrete bytes 0x%x and 0x%x", a_conc, b_conc)
                        return a_addr_offset
                else:
                    concrete_run = False

                byte_constraint = self.state.solver.And(
                    a_byte == b_byte, ret_expr == (a_addr_offset))
                match_constraints_list.append(byte_constraint)

        if concrete_run:
            l.debug("concrete run made it to the end!")
            return ret_0

        l.debug("returning symbolic")

        match_constraints = self.state.solver.Or(*match_constraints_list)
        nomatch_constraints = self.state.solver.Not(match_constraints)

        # add constraints of the lengths of a and b
        if not sv_a_len:
            match_constraints = self.state.solver.And(a_len != 0, match_constraints)
        if not sv_b_len:
            match_constraints = self.state.solver.And(b_len != 0, match_constraints)

        nomatch_constraints = self.state.solver.And(nomatch_constraints, ret_expr == ret_0)

        self.state.add_constraints(self.state.solver.Or(match_constraints, nomatch_constraints))

        return ret_expr
