from __future__ import annotations
from typing import TYPE_CHECKING
from string import digits as ascii_digits
import logging
import math
import claripy

from angr.errors import SimProcedureArgumentError, SimProcedureError, SimSolverError
from angr import sim_type
from angr.sim_procedure import SimProcedure
from angr.storage.file import SimPackets

if TYPE_CHECKING:
    from angr.sim_type import SimType


l = logging.getLogger(name=__name__)
ascii_digits = ascii_digits.encode()


class FormatString:
    """
    Describes a format string.
    """

    SCANF_DELIMITERS = [b"\x09", b"\x0a", b"\x0b", b"\x0d", b"\x20"]

    def __init__(self, parser, components):
        """
        Takes a list of components which are either just strings or a FormatSpecifier.
        """
        self.components = components
        self.parser = parser
        self.string = None

    @property
    def state(self):
        return self.parser.state

    @staticmethod
    def _add_to_string(string, c):
        if c is None:
            return string
        if string is None:
            return c
        return string.concat(c)

    def _get_str_at(self, str_addr, max_length=None):
        if max_length is None:
            strlen = self.parser._sim_strlen(str_addr)

            # TODO: we probably could do something more fine-grained here.

            # throw away strings which are just the NULL terminator
            max_length = self.parser.state.solver.max_int(strlen)
            if max_length == 0:
                return claripy.BVV(b"")

        return self.parser.state.memory.load(str_addr, max_length)

    def replace(self, va_arg):
        """
        Implement printf - based on the stored format specifier information, format the values from the arg getter
        function `args` into a string.

        :param va_arg:          A function which takes a type and returns the next argument of that type
        :return:                The result formatted string
        """

        string = None

        for component in self.components:
            # if this is just concrete data
            if isinstance(component, bytes):
                string = self._add_to_string(string, claripy.BVV(component))
            elif isinstance(component, str):
                raise Exception("this branch should be impossible?")
            elif isinstance(component, claripy.ast.BV):  # pylint:disable=isinstance-second-argument-not-valid-type
                string = self._add_to_string(string, component)
            else:
                # okay now for the interesting stuff
                # what type of format specifier is it?
                fmt_spec = component
                if fmt_spec.spec_type == b"s":
                    str_length = va_arg("size_t") if fmt_spec.length_spec == b".*" else None
                    str_ptr = va_arg("char*")
                    string = self._add_to_string(string, self._get_str_at(str_ptr, max_length=str_length))
                # integers, for most of these we'll end up concretizing values..
                else:
                    # ummmmmmm this is a cheap translation but I think it should work
                    i_val = va_arg("void*")
                    c_val = int(self.parser.state.solver.eval(i_val))
                    c_val &= (1 << (fmt_spec.size * 8)) - 1
                    if fmt_spec.signed and (c_val & (1 << ((fmt_spec.size * 8) - 1))):
                        c_val -= 1 << fmt_spec.size * 8

                    if fmt_spec.spec_type in (b"d", b"i") or fmt_spec.spec_type == b"u":
                        s_val = str(c_val)
                    elif fmt_spec.spec_type == b"c":
                        s_val = chr(c_val & 0xFF)
                    elif fmt_spec.spec_type == b"x":
                        s_val = hex(c_val)[2:]
                    elif fmt_spec.spec_type == b"o":
                        s_val = oct(c_val)[2:]
                    elif fmt_spec.spec_type == b"p":
                        s_val = hex(c_val)
                    else:
                        raise SimProcedureError(f"Unimplemented format specifier '{fmt_spec.spec_type}'")

                    if isinstance(fmt_spec.length_spec, int):
                        s_val = s_val.rjust(fmt_spec.length_spec, fmt_spec.pad_chr)

                    string = self._add_to_string(string, claripy.BVV(s_val.encode()))

        return string

    def interpret(self, va_arg, addr=None, simfd=None):
        """
        implement scanf - extract formatted data from memory or a file according to the stored format
        specifiers and store them into the pointers extracted from `args`.

        :param va_arg:      A function which, given a type, returns the next argument of that type
        :param addr:        The address in the memory to extract data from, or...
        :param simfd:       A file descriptor to use for reading data from
        :return:            The number of arguments parsed
        """
        num_args = 0
        if simfd is not None and isinstance(simfd.read_storage, SimPackets):
            for component in self.components:
                if type(component) is bytes:
                    sdata, _ = simfd.read_data(len(component), short_reads=False)
                    self.state.add_constraints(sdata == component)
                elif isinstance(component, claripy.ast.Bits):
                    sdata, _ = simfd.read_data(len(component) // 8, short_reads=False)
                    self.state.add_constraints(sdata == component)
                elif component.spec_type == b"s":
                    if component.length_spec is None:
                        sdata, slen = simfd.read_data(self.state.libc.buf_symbolic_bytes)
                    else:
                        sdata, slen = simfd.read_data(component.length_spec)
                    for byte in sdata.chop(8):
                        self.state.add_constraints(claripy.And(*[byte != char for char in self.SCANF_DELIMITERS]))
                    ptr = va_arg("char*")
                    self.state.memory.store(ptr, sdata, size=slen)
                    self.state.memory.store(ptr + slen, claripy.BVV(0, 8))
                    num_args += 1
                elif component.spec_type == b"c":
                    sdata, _ = simfd.read_data(1, short_reads=False)
                    self.state.memory.store(va_arg("char*"), sdata)
                    num_args += 1
                else:
                    bits = component.size * 8
                    if component.spec_type == b"x":
                        base = 16
                    elif component.spec_type == b"o":
                        base = 8
                    else:
                        base = 10

                    # here's the variable representing the result of the parsing
                    target_variable = self.state.solver.BVS(
                        "scanf_" + component.string.decode(), bits, key=("api", "scanf", num_args, component.string)
                    )
                    negative = claripy.SLT(target_variable, 0)

                    # how many digits does it take to represent this variable fully?
                    max_digits = math.ceil(math.log(2**bits, base))

                    # how many digits does the format specify?
                    spec_digits = component.length_spec

                    # how many bits can we specify as input?
                    available_bits = float("inf") if spec_digits is None else spec_digits * math.log2(base)
                    not_enough_bits = available_bits < bits

                    # how many digits will we model this input as?
                    digits = max_digits if spec_digits is None else spec_digits

                    # constrain target variable range explicitly if it can't take on all possible values
                    if not_enough_bits:
                        self.state.add_constraints(
                            claripy.And(
                                claripy.SLE(target_variable, (base**digits) - 1),
                                claripy.SGE(target_variable, -(base ** (digits - 1) - 1)),
                            )
                        )

                    # perform the parsing in reverse - constrain the input digits to be the string version of the input
                    # this only works because we're reading from a packet stream and therefore nobody has the ability
                    # to add other constraints to this data!
                    # this makes z3's job EXTREMELY easy
                    sdata, _ = simfd.read_data(digits, short_reads=False)
                    for i, digit in enumerate(reversed(sdata.chop(8))):
                        digit_value = (target_variable // (base**i)) % base
                        digit_ascii = digit_value + ord("0")
                        if base > 10:
                            digit_ascii = claripy.If(digit_value >= 10, digit_value + (-10 + ord("a")), digit_ascii)

                        # if there aren't enough bits, we can increase the range by accounting for the possibility that
                        # the first digit is a minus sign
                        if not_enough_bits:
                            if i == digits - 1:
                                neg_digit_ascii = ord("-")
                            else:
                                neg_digit_value = (-target_variable // (base**i)) % base
                                neg_digit_ascii = neg_digit_value + ord("0")
                                if base > 10:
                                    neg_digit_ascii = claripy.If(
                                        neg_digit_value >= 10, neg_digit_value + (-10 + ord("a")), neg_digit_ascii
                                    )

                            digit_ascii = claripy.If(negative, neg_digit_ascii, digit_ascii)

                        self.state.add_constraints(digit == digit_ascii[7:0])

                    # again, a cheap hack
                    self.state.memory.store(va_arg("void*"), target_variable, endness=self.state.arch.memory_endness)
                    num_args += 1

            return num_args

        if simfd is not None:
            region = simfd.read_storage
            addr = simfd._pos if hasattr(simfd, "_pos") else simfd._read_pos  # XXX THIS IS BAD
        else:
            region = self.parser.state.memory

        bits = self.parser.state.arch.bits
        failed = claripy.BVV(0, 32)
        position = addr
        for component in self.components:
            if isinstance(component, bytes):
                # TODO we skip non-format-specifiers in format string interpretation for now
                # if the region doesn't match the concrete component, we need to return immediately
                pass
            else:
                fmt_spec = component
                try:
                    dest = va_arg("void*")
                except SimProcedureArgumentError:
                    dest = None
                if fmt_spec.spec_type == b"s":
                    # set some limits for the find
                    max_str_len = self.parser.state.libc.max_str_len
                    max_sym_bytes = self.parser.state.libc.buf_symbolic_bytes

                    # has the length of the format been limited by the string itself?
                    if fmt_spec.length_spec is not None:
                        max_str_len = fmt_spec.length_spec
                        max_sym_bytes = fmt_spec.length_spec

                    # TODO: look for limits on other characters which scanf is sensitive to, '\x00', '\x20'
                    result, _, _ = region.find(
                        position,
                        claripy.BVV(b"\n"),
                        max_str_len,
                        max_symbolic_bytes=max_sym_bytes,
                        default=claripy.BVV(position + max_str_len, 64),
                    )

                    # concretize the length
                    length = self.parser.state.solver.max_int(result - position)
                    src_str = region.load(position, length)

                    # TODO all of these should be delimiters we search for above
                    # add that the contents of the string cannot be any scanf %s string delimiters
                    for delimiter in set(FormatString.SCANF_DELIMITERS):
                        delim_bvv = claripy.BVV(delimiter)
                        for i in range(length):
                            self.parser.state.add_constraints(region.load(position + i, 1) != delim_bvv)

                    # write it out to the pointer
                    self.parser.state.memory.store(dest, src_str)
                    # store the terminating null byte
                    self.parser.state.memory.store(dest + length, claripy.BVV(0, 8))

                    position += length

                else:
                    # XXX: atoi only supports strings of one byte
                    if fmt_spec.spec_type in [b"d", b"i", b"u", b"x"]:
                        base = 16 if fmt_spec.spec_type == b"x" else 10
                        status, i, num_bytes = self.parser._sim_atoi_inner(
                            position, region, base=base, read_length=fmt_spec.length_spec
                        )
                        # increase failed count if we were unable to parse it
                        failed = claripy.If(status, failed, failed + 1)
                        position += num_bytes
                    elif fmt_spec.spec_type == b"c":
                        i = region.load(position, 1)
                        i = i.zero_extend(bits - 8)
                        position += 1
                    else:
                        raise SimProcedureError(f"unsupported format spec '{fmt_spec.spec_type}' in interpret")

                    i = claripy.Extract(fmt_spec.size * 8 - 1, 0, i)
                    self.parser.state.memory.store(
                        dest, i, size=fmt_spec.size, endness=self.parser.state.arch.memory_endness
                    )

                num_args += 1

        if simfd is not None:
            _, realsize = simfd.read_data(position - addr)
            self.state.add_constraints(realsize == position - addr)

        return num_args - failed

    def __repr__(self):
        outstr = ""
        for comp in self.components:
            if isinstance(comp, bytes):
                outstr += comp.decode("ascii")
            else:
                outstr += str(comp)

        return outstr


class FormatSpecifier:
    """
    Describes a format specifier within a format string.
    """

    __slots__ = (
        "length_spec",
        "pad_chr",
        "signed",
        "size",
        "string",
    )

    def __init__(self, string, length_spec, pad_chr, size, signed):
        self.string = string
        self.size = size
        self.signed = signed
        self.length_spec = length_spec
        self.pad_chr = pad_chr

    @property
    def spec_type(self):
        return self.string[-1:].lower()

    def __str__(self):
        return f"%{self.string.decode()}"

    def __len__(self):
        return len(self.string)


class FormatParser(SimProcedure):
    """
    For SimProcedures relying on printf-style format strings.
    """

    ARGS_MISMATCH = True

    # Basic conversion specifiers for format strings, mapped to sim_types
    # TODO: support for C and S that are deprecated.
    # TODO: We only consider POSIX locales here.
    basic_spec = {
        b"d": sim_type.SimTypeInt(),  # 'int',
        b"i": sim_type.SimTypeInt(),  # 'int',
        b"o": sim_type.SimTypeInt(signed=False),  # 'unsigned int',
        b"u": sim_type.SimTypeInt(signed=False),  # 'unsigned int',
        b"x": sim_type.SimTypeInt(signed=False),  # 'unsigned int',
        b"X": sim_type.SimTypeInt(signed=False),  # 'unsigned int',
        b"e": sim_type.SimTypeDouble(),  # 'double',
        b"E": sim_type.SimTypeDouble(),  # 'double',
        b"f": sim_type.SimTypeDouble(),  # 'double',
        b"F": sim_type.SimTypeDouble(),  # 'double',
        b"g": sim_type.SimTypeDouble(),  # 'double',
        b"G": sim_type.SimTypeDouble(),  # 'double',
        b"a": sim_type.SimTypeDouble(),  # 'double',
        b"A": sim_type.SimTypeDouble(),  # 'double',
        b"c": sim_type.SimTypeChar(),  # 'char',
        b"s": sim_type.SimTypePointer(sim_type.SimTypeChar()),  # 'char*',
        b"p": sim_type.SimTypePointer(sim_type.SimTypeInt(signed=False)),  # 'uintptr_t',
        b"n": sim_type.SimTypePointer(
            sim_type.SimTypeInt(signed=False)
        ),  # 'uintptr_t', # pointer to num bytes written so far
        # b'm': None, # Those don't expect any argument
        # b'%': None, # Those don't expect any argument
    }

    # Signedness of integers
    int_sign = {"signed": [b"d", b"i"], "unsigned": [b"o", b"u", b"x", b"X"]}

    # Length modifiers and how they apply to integer conversion (signed / unsigned).
    int_len_mod = {
        b"hh": (sim_type.SimTypeChar(), sim_type.SimTypeChar(signed=False)),  # ('char', 'uint8_t'),
        b"h": (sim_type.SimTypeShort(), sim_type.SimTypeShort(signed=False)),  # ('int16_t', 'uint16_t'),
        b"l": (sim_type.SimTypeLong(), sim_type.SimTypeLong(signed=False)),  # ('long', 'unsigned long'),
        # FIXME: long long is 64bit according to stdint.h on Linux,  but that might not always be the case
        b"ll": (sim_type.SimTypeLongLong(), sim_type.SimTypeLongLong(signed=False)),  # ('int64_t', 'uint64_t'),
        # FIXME: intmax_t seems to be always 64 bit, but not too sure
        b"j": (sim_type.SimTypeLongLong(), sim_type.SimTypeLongLong(signed=False)),  # ('int64_t', 'uint64_t'),
        b"z": (sim_type.SimTypeLength(signed=True), sim_type.SimTypeLength(signed=False)),  # ('ssize', 'size_t'),
        b"t": (sim_type.SimTypeLong(), sim_type.SimTypeLong()),  # ('ptrdiff_t', 'ptrdiff_t'),
    }

    # Types that are not known by sim_types
    # Maps to (size, signedness)
    other_types = {("string",): lambda _: (0, True)}  # special value for strings, we need to count

    # Those flags affect the formatting the output string
    flags = ["#", "0", r"\-", r" ", r"\+", r"\'", "I"]

    _MOD_SPEC = None
    _ALL_SPEC = None

    @property
    def _mod_spec(self):
        """
        Modified length specifiers: mapping between length modifiers and conversion specifiers. This generates all the
        possibilities, i.e. hhd, etc.
        """
        if FormatParser._MOD_SPEC is None:
            mod_spec = {}

            for mod, sizes in self.int_len_mod.items():
                for conv in self.int_sign["signed"]:
                    mod_spec[mod + conv] = sizes[0]
                for conv in self.int_sign["unsigned"]:
                    mod_spec[mod + conv] = sizes[1]

            FormatParser._MOD_SPEC = mod_spec

        return FormatParser._MOD_SPEC

    @property
    def _all_spec(self) -> dict[bytes, SimType]:
        """
        All specifiers and their lengths.
        """

        if FormatParser._ALL_SPEC is None:
            base = dict(self._mod_spec)

            for spec in self.basic_spec:
                base[spec] = self.basic_spec[spec]

            FormatParser._ALL_SPEC = base

        return FormatParser._ALL_SPEC

    # Tricky stuff
    # Note that $ is not C99 compliant (but posix specific).

    def _match_spec(self, nugget):
        """
        match the string `nugget` to a format specifier.
        """
        # TODO: handle positional modifiers and other similar format string tricks.
        all_spec = self._all_spec

        # iterate through nugget throwing away anything which is an int
        # TODO store this in a size variable

        original_nugget = nugget
        length_str = []
        length_spec = None
        length_spec_str_len = 0
        pad_chr = " "

        if nugget.startswith(b".*"):
            # ".*": precision is specified as an argument
            nugget = nugget[2:]
            length_spec = b".*"
            length_spec_str_len = 2
        elif nugget.startswith(b"0"):
            pad_chr = "0"
        elif nugget.startswith(b"."):
            pad_chr = "0"
            nugget = nugget[1:]

        for j, c in enumerate(nugget):
            if c in ascii_digits:
                length_str.append(c)
            else:
                nugget = nugget[j:]
                if length_spec is None:
                    length_spec = None if len(length_str) == 0 else int(bytes(length_str))
                break

        # we need the length of the format's length specifier to extract the format and nothing else
        if length_spec_str_len == 0 and length_str:
            length_spec_str_len = len(length_str)
        # is it an actual format?
        for spec in all_spec:
            if nugget.startswith(spec):
                # this is gross coz sim_type is gross..
                nugget = nugget[: len(spec)]
                original_nugget = original_nugget[: (length_spec_str_len + len(spec))]
                nugtype: SimType = all_spec[nugget]
                try:
                    typeobj = nugtype.with_arch(self.state.arch if self.state is not None else self.project.arch)
                except Exception as err:
                    raise SimProcedureError(f"format specifier uses unknown type '{nugtype!r}'") from err
                return FormatSpecifier(original_nugget, length_spec, pad_chr, typeobj.size // 8, typeobj.signed)

        return None

    def extract_components(self, fmt: list) -> list:
        """
        Extract the actual formats from the format string `fmt`.

        :param fmt: A list of format chars.
        :returns: a FormatString object
        """

        # iterate over the format string looking for format specifiers
        components = []
        i = 0
        while i < len(fmt):
            if type(fmt[i]) is bytes and fmt[i] == b"%":
                # Note that we only support concrete format specifiers
                # grab the specifier
                # go to the space
                specifier = b""
                for c in fmt[i + 1 :]:
                    if type(c) is bytes:
                        specifier += c
                    else:
                        break

                specifier = self._match_spec(specifier)
                if specifier is not None:
                    i += len(specifier)
                    components.append(specifier)
                else:
                    # if we get here we didn't match any specs, the first char will be thrown away
                    # and we'll add the percent
                    i += 1
                    components.append(b"%")
            else:
                # claripy ASTs, which are usually symbolic variables
                # They will be kept as they are - even if those chars can be evaluated to "%"
                components.append(fmt[i])
            i += 1

        return components

    def _get_fmt(self, fmt):
        """
        Extract the actual formats from the format string `fmt`.

        :param list fmt: A list of format chars.
        :returns: a FormatString object
        """
        components = self.extract_components(fmt)
        return FormatString(self, components)

    def _sim_atoi_inner(self, str_addr, region, base=10, read_length=None):
        """
        Return the result of invoking the atoi simprocedure on `str_addr`.
        """

        from angr.procedures import SIM_PROCEDURES  # pylint:disable=import-outside-toplevel

        strtol = SIM_PROCEDURES["libc"]["strtol"]

        return strtol.strtol_inner(str_addr, self.state, region, base, True, read_length=read_length)

    def _sim_strlen(self, str_addr):
        """
        Return the result of invoking the strlen simprocedure on `str_addr`.
        """

        from angr.procedures import SIM_PROCEDURES  # pylint:disable=import-outside-toplevel

        strlen = SIM_PROCEDURES["libc"]["strlen"]

        return self.inline_call(strlen, str_addr).ret_expr

    def _parse(self, fmtstr_ptr):
        """
        Parse format strings.

        :param fmt_idx: The pointer to the format string from the arguments list.
        :returns:       A FormatString object which can be used for replacing the format specifiers with arguments or
                        for scanning into arguments.
        """

        if self.state.solver.symbolic(fmtstr_ptr):
            raise SimProcedureError("Symbolic pointer to (format) string :(")

        length = self._sim_strlen(fmtstr_ptr)
        if self.state.solver.symbolic(length):
            all_lengths = self.state.solver.eval_upto(length, 2)
            if len(all_lengths) != 1:
                raise SimProcedureError("Symbolic (format) string, game over :(")
            length = all_lengths[0]

        if self.state.solver.is_true(length == 0):
            return FormatString(self, [b""])

        fmt_xpr = self.state.memory.load(fmtstr_ptr, length)

        fmt = []
        for i in range(fmt_xpr.size(), 0, -8):
            char = fmt_xpr[i - 1 : i - 8]
            try:
                conc_char = self.state.solver.eval_one(char)
            except SimSolverError:
                # For symbolic chars, just keep them symbolic
                fmt.append(char)
            else:
                # Concrete chars are directly appended to the list
                fmt.append(bytes([conc_char]))

        # make a FormatString object
        fmt_str = self._get_fmt(fmt)

        l.debug("Fmt: %r", fmt_str)

        return fmt_str


class ScanfFormatParser(FormatParser):
    """
    For SimProcedures relying on scanf-style format strings.
    """

    basic_spec = {
        b"d": sim_type.SimTypeInt(),  # 'int',
        b"i": sim_type.SimTypeInt(),  # 'int',
        b"o": sim_type.SimTypeInt(signed=False),  # 'unsigned int',
        b"u": sim_type.SimTypeInt(signed=False),  # 'unsigned int',
        b"x": sim_type.SimTypeInt(signed=False),  # 'unsigned int',
        b"X": sim_type.SimTypeInt(signed=False),  # 'unsigned int',
        b"e": sim_type.SimTypeFloat(),  # 'float',
        b"E": sim_type.SimTypeFloat(),  # 'float',
        b"f": sim_type.SimTypeFloat(),  # 'float',
        b"F": sim_type.SimTypeFloat(),  # 'float',
        b"g": sim_type.SimTypeFloat(),  # 'float',
        b"G": sim_type.SimTypeFloat(),  # 'float',
        b"a": sim_type.SimTypeFloat(),  # 'float',
        b"A": sim_type.SimTypeFloat(),  # 'float',
        b"c": sim_type.SimTypeChar(),  # 'char',
        b"s": sim_type.SimTypePointer(sim_type.SimTypeChar()),  # 'char*',
        b"p": sim_type.SimTypePointer(sim_type.SimTypeInt(signed=False)),  # 'uintptr_t',
        b"n": sim_type.SimTypePointer(sim_type.SimTypeInt(signed=False)),
    }

    # All float conversion specifiers
    float_spec = [b"e", b"E", b"f", b"F", b"g", b"G", b"a", b"A"]

    # Length modifiers and how they apply to float conversion.
    float_len_mod = {
        b"l": sim_type.SimTypeDouble,  # 'double',
        b"ll": sim_type.SimTypeDouble,  # 'long double',
    }

    @property
    def _mod_spec(self):
        """
        Modified length specifiers: mapping between length modifiers and conversion specifiers. This generates all the
        possibilities, i.e. lf, etc.
        """
        if FormatParser._MOD_SPEC is None:
            mod_spec = dict(super()._mod_spec.items())
            for mod, size in self.float_len_mod.items():
                for conv in self.float_spec:
                    mod_spec[mod + conv] = size

            FormatParser._MOD_SPEC = mod_spec

        return FormatParser._MOD_SPEC
