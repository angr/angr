import string

from ...errors import SimValueError
from . import MemoryMixin


class HexDumperMixin(MemoryMixin):
    def hex_dump(
        self,
        start,
        size,
        word_size=4,
        words_per_row=4,
        endianness="Iend_BE",
        symbolic_char="?",
        unprintable_char=".",
        solve=False,
        extra_constraints=None,
        inspect=False,
        disable_actions=True,
    ):
        """
        Returns a hex dump as a string. The solver, if enabled, is called once for every byte
        potentially making this function very slow. It is meant to be used mainly as a
        "visualization" for debugging.

        Warning: May read and display more bytes than `size` due to rounding. Particularly,
        if size is less than, or not a multiple of word_size*words_per_line.

        :param start: starting address from which to print
        :param size: number of bytes to display
        :param word_size: number of bytes to group together as one space-delimited unit
        :param words_per_row: number of words to display per row of output
        :param endianness: endianness to use when displaying each word (ASCII representation is unchanged)
        :param symbolic_char: the character to display when a byte is symbolic and has multiple solutions
        :param unprintable_char: the character to display when a byte is not printable
        :param solve: whether or not to attempt to solve (warning: can be very slow)
        :param extra_constraints: extra constraints to pass to the solver is solve is True
        :param inspect: whether or not to trigger SimInspect breakpoints for the memory load
        :param disable_actions: whether or not to disable SimActions for the memory load
        :return: hex dump as a string
        """
        if endianness == "Iend_BE":
            end = 1
        else:
            end = -1
        if extra_constraints is None:
            extra_constraints = []

        # round up size so that chop() works
        line_size = word_size * words_per_row
        size = size if size % line_size == 0 else size + line_size - size % line_size
        raw_mem = super().load(start, size=size, inspect=inspect, disable_actions=disable_actions)

        i = start
        dump_str = ""
        for line in raw_mem.chop(line_size * self.state.arch.byte_width):
            dump = "%x:" % i
            group_str = ""
            for word in line.chop(word_size * self.state.arch.byte_width):
                word_bytes = ""
                word_str = ""
                for byte_ in word.chop(self.state.arch.byte_width)[::end]:
                    byte_value = None
                    if not self.state.solver.symbolic(byte_) or solve:
                        try:
                            byte_value = self.state.solver.eval_one(byte_, extra_constraints=extra_constraints)
                        except SimValueError:
                            pass

                    if byte_value is not None:
                        word_bytes += "%02x" % byte_value
                        if chr(byte_value) in string.printable[:-5]:
                            word_str += chr(byte_value)
                        else:
                            word_str += unprintable_char
                    else:
                        word_bytes += symbolic_char * 2
                        word_str += symbolic_char
                dump += " " + word_bytes
                group_str += word_str[::end]  # always print ASCII representation in little-endian
            dump += " " + group_str
            i += line_size
            dump_str += dump + "\n"
        return dump_str
