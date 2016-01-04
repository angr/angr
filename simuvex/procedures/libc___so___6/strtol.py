import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt
from simuvex.s_procedure import SimProcedureError

import logging
l = logging.getLogger("simuvex.procedures.libc.strtol")


# note: this does not handle skipping white space

class strtol(simuvex.SimProcedure):

    @staticmethod
    def strtol_inner(s, state, region, base, signed, read_length=None):
        """
        :param s: the string address/offset
        :param state: SimState
        :param region: memory, file, etc
        :param base: the base to use to interpret the number
        note: all numbers may start with +/- and base 16 may start with 0x
        :param signed: boolean, true means the result will be signed, otherwise unsigned
        :param read_length: int, the number of bytes parsed in strtol
        :return: expression, value, num_bytes
        the returned expression is a symbolic boolean indicating success, value will be set to 0 on failure
        value is the returned value (set to min/max on overflow)
        num_bytes is the number of bytes read in the string
        """

        # sanity check
        if base < 2 or base > 36:
            raise SimProcedureError("base should be in the range [2,36]")

        # order matters here since we will use an if then else tree, and -0x will have precedence over -
        prefixes = ["-", "+", ""]
        if base == 16:
            prefixes = ["0x", "-0x", "+0x"] + prefixes

        cases = []
        conditions = []
        possible_num_bytes = []

        for prefix in prefixes:
            condition, value, num_bytes = strtol._load_num_with_prefix(prefix, s, region, state, base, signed, read_length)
            conditions.append(condition)
            cases.append((condition, value))
            possible_num_bytes.append(num_bytes)

        # only one of the cases needed to match
        result = state.se.ite_cases(cases[:-1], cases[-1][1])
        expression = state.se.Or(*conditions)
        num_bytes = state.se.ite_cases(zip(conditions, possible_num_bytes), 0)
        return expression, result, num_bytes

    @staticmethod
    def _load_num_with_prefix(prefix, addr, region, state, base, signed, read_length=None):
        """
        loads a number from addr, and returns a condition that addr must start with the prefix
        """
        length = len(prefix)
        read_length = (read_length-length) if read_length else None
        condition, value, num_bytes = strtol._string_to_int(addr+length, state, region, base, signed, read_length)

        # the prefix must match
        if len(prefix) > 0:
            loaded_prefix = region.load(addr, length)
            condition = state.se.And(loaded_prefix == state.se.BVV(prefix), condition)
        total_num_bytes = num_bytes + length

        # negatives
        if prefix.startswith("-"):
            value = state.se.BVV(0, state.arch.bits) - value
        return condition, value, total_num_bytes

    @staticmethod
    def _string_to_int(s, state, region, base, signed, read_length=None):
        """
        reads values from s and generates the symbolic number that it would equal
        the first char is either a number in the given base, or the result is 0
        expression indicates whether or not it was successful
        """

        # if length wasn't provided, read the maximum bytes
        cutoff = (read_length == None)
        length = state.libc.max_strtol_len if cutoff else read_length

        # expression whether or not it was valid at all
        expression, _ = strtol._char_to_val(region.load(s, 1), state, base)

        cases = []

        # to detect overflows we keep it in a larger bv and extract it at the end
        num_bits = min(state.arch.bits*2, 128)
        current_val = state.se.BVV(0, num_bits)
        num_bytes = state.se.BVS("num_bytes", state.arch.bits)
        constraints_num_bytes = []
        conditions = []

        # we need all the conditions to hold except the last one to have found a value
        for i in range(length):
            char = region.load(s + i, 1)
            condition, value = strtol._char_to_val(char, state, base)

            # if it was the end we'll get the current val
            cases.append((num_bytes == i, current_val))
            case_constraints = conditions + [state.se.Not(condition)] + [num_bytes == i]
            constraints_num_bytes.append(state.se.And(*case_constraints))

            # add the value and the condition
            current_val = current_val*base + value.zero_extend(num_bits-8)
            conditions.append(condition)

        # the last one is unterminated, let's ignore it
        if not cutoff:
            cases.append((num_bytes == length, current_val))
            case_constraints = conditions + [num_bytes == length]
            constraints_num_bytes.append(state.se.And(*case_constraints))

        # only one of the constraints need to hold
        # since the constraints look like (num_bytes == 2 and the first 2 chars are valid, and the 3rd isn't)
        state.add_constraints(state.se.Or(*constraints_num_bytes))

        result = state.se.ite_cases(cases, 0)

        # overflow check
        max_bits = state.arch.bits-1 if signed else state.arch.bits
        max_val = 2**max_bits - 1
        result = state.se.If(result < max_val, state.se.Extract(state.arch.bits-1, 0, result),
                             state.se.BVV(max_val, state.arch.bits))

        return expression, result, num_bytes

    @staticmethod
    def _char_to_val(char, state, base):
        """
        converts a symbolic char to a number in the given base
        returns expression, result
        expression is a symbolic boolean indicating whether or not it was a valid number
        result is the value
        """
        cases = []
        # 0-9
        max_digit = state.se.BVV("9", 8)
        min_digit = state.se.BVV("0", 8)
        if base < 10:
            max_digit = state.se.BVV(chr(ord("0") + base), 8)
        is_digit = state.se.And(char >= min_digit, char <= max_digit)
        # return early here so we don't add unnecessary statements
        if base <= 10:
            return is_digit, char - min_digit

        # handle alphabetic chars
        max_char_lower = state.se.BVV(chr(ord("a") + base-10 - 1), 8)
        max_char_upper = state.se.BVV(chr(ord("A") + base-10 - 1), 8)
        min_char_lower = state.se.BVV(chr(ord("a")), 8)
        min_char_upper = state.se.BVV(chr(ord("A")), 8)

        cases.append((is_digit, char - min_digit))
        is_alpha_lower = state.se.And(char >= min_char_lower, char <= max_char_lower)
        cases.append((is_alpha_lower, char - min_char_lower + 10))
        is_alpha_upper = state.se.And(char >= min_char_upper, char <= max_char_upper)
        cases.append((is_alpha_upper, char - min_char_upper + 10))

        expression = state.se.Or(is_digit, is_alpha_lower, is_alpha_upper)
        # use the last case as the default, the expression will encode whether or not it's satisfiable
        result = state.se.ite_cases(cases[:-1], cases[-1][1])

        return expression, result

    def run(self, nptr, endptr, base):

        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(self.ty_ptr(SimTypeString())),
                               2: SimTypeInt(self.state.arch, True)}

        self.return_type = SimTypeInt(self.state.arch, True)

        if self.state.se.symbolic(base):
            l.warning("Concretizing symbolic base in strtol")
            base_concrete = self.state.se.any_int(base)
            self.state.add_constraints(base == base_concrete)

        base = self.state.se.any_int(base)

        if base == 0:
            # in this case the base is 16 if it starts with 0x, 8 if it starts with 0, 10 otherwise
            # here's the possibilities
            base_16_pred = self.state.se.Or(
                self.state.memory.load(nptr, 2) == self.state.se.BVV("0x"),
                self.state.memory.load(nptr, 3) == self.state.se.BVV("+0x"),
                self.state.memory.load(nptr, 3) == self.state.se.BVV("-0x"))
            base_8_pred = self.state.se.And(
                self.state.se.Or(
                    self.state.memory.load(nptr, 1) == self.state.se.BVV("0"),
                    self.state.memory.load(nptr, 2) == self.state.se.BVV("+0"),
                    self.state.memory.load(nptr, 2) == self.state.se.BVV("-0")),
                self.state.se.Not(base_16_pred))
            base_10_pred = self.state.se.And(
                self.state.se.Not(base_16_pred),
                self.state.se.Not(base_8_pred)
            )
            expressions = []
            values = []
            num_bytes_arr = []

            # read a string to long for each possibility
            pred_base = zip([base_16_pred, base_10_pred, base_8_pred], [16, 10, 8])
            for pred, base in pred_base:
                expression, value, num_bytes = self.strtol_inner(nptr, self.state, self.state.memory, base, True)
                expressions.append(self.state.se.And(expression, pred))
                values.append(value)
                num_bytes_arr.append(num_bytes)

            # we would return the Or(expressions) as the indicator whether or not it succeeded, but it's not needed
            # for strtol
            # expression = self.state.se.Or(expressions)
            value = self.state.se.ite_cases(zip(expressions, values), 0)
            num_bytes = self.state.se.ite_cases(zip(expressions, num_bytes_arr), 0)

            self.state.memory.store(endptr, nptr+num_bytes,
                                    condition=(endptr != 0), endness=self.state.arch.memory_endness)

            return value

        expression, value, num_bytes = self.strtol_inner(nptr, self.state, self.state.memory, base, True)
        self.state.memory.store(endptr, nptr+num_bytes, condition=(endptr != 0), endness=self.state.arch.memory_endness)
        return self.state.se.If(expression, value, 0)
