import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt
from simuvex.s_procedure import SimProcedureError

import logging
l = logging.getLogger("simuvex.procedures.libc.strtol")


class strtol(simuvex.SimProcedure):

    @staticmethod
    def strtol_inner(s, state, region, base):
        """
        :param s: the string address/offset
        :param state: SimState
        :param region: memory, file, etc
        :param base: the base to use to interpret the number
        note: all numbers may start with +/- and base 16 may start with 0x
        :return: expression, value, num_bytes
        the returned expression is a symbolic boolean indicating success, value will be set to 0 on failure
        value is the returned value
        num_bytes is the number of bytes read in the string
        """

        # sanity check
        if base < 2 or base > 36:
            raise SimProcedureError("base should be in the range [2,36]")

        cases = []
        conditions = []
        possible_num_bytes = []
        if base == 16:
            # cases +0x
            char_pm_0x = region.load(s, 3)
            condition, case_pm_0x, num_bytes = strtol._string_to_int(s+3, state, region, base)
            condition_plus = state.se.And(char_pm_0x == state.se.BVV("+0x", 24), condition)
            cases.append((condition_plus, case_pm_0x))
            conditions.append(condition_plus)
            possible_num_bytes.append(num_bytes+3)
            # case -0x
            condition_minus = state.se.And(char_pm_0x == state.se.BVV("-0x", 24), condition)
            cases.append((condition_minus, case_pm_0x * -1))
            conditions.append(condition_minus)
            # case 0x
            char_0x = region.load(s, 2)
            condition, case_0x, num_bytes = strtol._string_to_int(s+2, state, region, base)
            condition = char_0x == state.se.BVV("0x", 16)
            cases.append((condition, case_0x))
            conditions.append(condition)
            possible_num_bytes.append(num_bytes+2)

        # case +
        char_pm = region.load(s, 1)
        condition, case_pm, num_bytes = strtol._string_to_int(s+1, state, region, base)
        condition_plus = state.se.And(char_pm == state.se.BVV("+", 8), condition)
        cases.append((condition_plus, case_pm))
        conditions.append(condition_plus)
        possible_num_bytes.append(num_bytes+1)
        # case -
        condition_minus = state.se.And(char_pm == state.se.BVV("-", 8), condition)
        cases.append((condition_minus, case_pm * -1))
        conditions.append(condition_minus)
        # case digit
        condition, case_else, num_bytes = strtol._string_to_int(s, state, region, base)
        conditions.append(condition)
        possible_num_bytes.append(num_bytes)

        result = state.se.ite_cases(cases, case_else)

        # only one of the cases needed to match
        expression = state.se.Or(*conditions)
        num_bytes = state.se.ite_cases(zip(conditions, possible_num_bytes), 0)
        return expression, result, num_bytes

    @staticmethod
    def _string_to_int(s, state, region, base):

        # TODO detect overflows past state.arch.bits

        # expression whether or not it was valid at all
        expression, _ = strtol._char_to_val(region.load(s, 1), state, base)

        cases = []

        current_val = state.se.BVV(0, state.arch.bits)
        num_bytes = state.se.BVS("num_bytes", state.arch.bits)
        constraints_num_bytes = []
        conditions = []

        # we need all the conditions to hold except the last one to have found a value
        for i in range(state.libc.max_strtol_len):
            char = region.load(s + i, 1)
            condition, value = strtol._char_to_val(char, state, base)

            # if it was the end we'll get the current val
            cases.append((num_bytes == i, current_val))
            case_constraints = conditions + [state.se.Not(condition)] + [num_bytes == i]
            constraints_num_bytes.append(state.se.And(*case_constraints))

            # add the value and the condition
            current_val = current_val*base + value.zero_extend(state.arch.bits-8)
            conditions.append(condition)

        # the last one is unterminated, but should be okay
        cases.append((num_bytes == state.libc.max_strtol_len, current_val))
        case_constraints = conditions + [num_bytes == state.libc.max_strtol_len]
        constraints_num_bytes.append(state.se.And(*case_constraints))

        # only one of the constraints need to hold
        # since the constraints look like (num_bytes == 2 and the first 2 chars are valid, and the 3rd isn't)
        state.add_constraints(state.se.Or(*constraints_num_bytes))

        result = state.se.ite_cases(cases, 0)

        return expression, result, num_bytes

    @staticmethod
    def _char_to_val(char, state, base):
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

        max_char_lower = state.se.BVV(chr(ord("a") + base-10), 8)
        max_char_upper = state.se.BVV(chr(ord("A") + base-10), 8)
        min_char_lower = state.se.BVV(chr(ord("a")), 8)
        min_char_upper = state.se.BVV(chr(ord("A")), 8)

        cases.append((is_digit, char - min_digit))
        is_alpha_lower = state.se.And(char >= min_char_lower, char <= max_char_lower)
        cases.append((is_alpha_lower, char - min_char_lower + 10))
        is_alpha_upper = state.se.And(char >= min_char_upper, char <= max_char_upper)
        cases.append((is_alpha_upper, char - min_char_upper + 10))

        expression = state.se.Or(is_digit, is_alpha_lower, is_alpha_upper)
        # use the last case as the default
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
            expression, value, num_bytes = self.strtol_inner(nptr, self.state, self.state.memory, 16)
            expressions.append(self.state.se.And(expression, base_16_pred))
            values.append(value)
            num_bytes_arr.append(num_bytes)
            expression, value, num_bytes = self.strtol_inner(nptr, self.state, self.state.memory, 8)
            expressions.append(self.state.se.And(expression, base_8_pred))
            values.append(value)
            num_bytes_arr.append(num_bytes)
            expression, value, num_bytes = self.strtol_inner(nptr, self.state, self.state.memory, 10)
            expressions.append(self.state.se.And(expression, base_10_pred))
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

        expression, value, num_bytes = self.strtol_inner(nptr, self.state, self.state.memory, base)
        self.state.memory.store(endptr, nptr+num_bytes, condition=(endptr != 0), endness=self.state.arch.memory_endness)
        return self.state.se.If(expression, value, 0)
