import simuvex
import symexec
import itertools

import logging
l = logging.getLogger("simuvex.procedures.libc_legacy.strncmp")

strncmp_counter = itertools.count()

######################################
# strncmp
######################################

# TODO: bigger
max_str_size = 16

def analyze_str(str_base, state):
    symbolic = [ ]
    nonzero = [ ]
    zero = [ ]

    for i in range(0, max_str_size):
        b = state.mem_value(str_base.expr + i, 1)
        if b.is_symbolic():
            symbolic.append(i)
        elif b.any() != 0:
            nonzero.append(i)
        else:
            zero.append(i)

    return symbolic, nonzero, zero

class strncmp(simuvex.SimProcedure):
    def __init__(self):
        # TODO: Finish the implementation
        a = self.get_arg_value(0)
        b = self.get_arg_value(1)
        num = self.get_arg_value(2)

        # figure out the list of symbolic bytes, concrete bytes, and concrete \0 bytes in the strings
        # a_symbolic, _, a_zero = analyze_str(a, self.state)
        # b_symbolic, _, b_zero = analyze_str(b, self.state)

        # any_zeroes = a_zero + b_zero
        # all_symbolic = sorted(tuple((set(a_symbolic) & set(b_symbolic))))
        # any_symbolic = a_symbolic + b_symbolic

        # TODO: Support string which is less than num chars
        # TODO: Support cases that num cannot be concretized
        if num.is_symbolic():
            raise Exception("strncmp doesn't support symbolic string length.")
        str_size = num.any()

        l.debug("Determined a str_size of %d", str_size)

        # the bytes
        a_bytes = [ ]
        b_bytes = [ ]
        for i in range(str_size + 1):
            a_bytes.append(self.state.mem_expr(a.expr + i, 1))
            b_bytes.append(self.state.mem_expr(b.expr + i, 1))

        # make the constraints
        match_constraint = None
        for i in range(0, str_size + 1):
            if i > 0:
                match_until_n = symexec.And(*[ a_byte == b_byte for a_byte, b_byte in zip(a_bytes[ : i], b_bytes[ : i]) ])
            else:
                match_until_n = True
            if i != str_size + 1:
                match_until_n = symexec.And(match_until_n, a_bytes[i] == 0)
                match_until_n = symexec.And(match_until_n, b_bytes[i] == 0)
            if match_constraint is None:
                match_constraint = match_until_n
            else:
                match_constraint = symexec.Or(match_constraint, match_until_n)
        nomatch_constraint = symexec.Not(match_constraint)

        #l.debug("match constraints: %s", match_constraint)
        #l.debug("nomatch constraints: %s", nomatch_constraint)

        ret_expr = symexec.BitVec("strncmp_ret_%d" % strncmp_counter.next(), self.state.arch.bits)
        self.state.add_constraints(symexec.Or(symexec.And(match_constraint, ret_expr == 0), symexec.And(nomatch_constraint, ret_expr == 1)))
        self.exit_return(ret_expr)
