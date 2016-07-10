import operator
from .plugin import SimStatePlugin

class SimStateCGC(SimStatePlugin):
    """
    This state plugin keeps track of CGC state.
    """

    #__slots__ = [ 'heap_location', 'max_str_symbolic_bytes' ]

    def __init__(self):
        SimStatePlugin.__init__(self)

        self.allocation_base = 0xb8000000
        self.time = 0

        self.max_allocation = 0x10000000

        # CGC error codes
        self.EBADF = 1
        self.EFAULT = 2
        self.EINVAL = 3
        self.ENOMEM = 4
        self.ENOSYS = 5
        self.EPIPE = 6

        # other CGC constants
        self.FD_SETSIZE = 1024

        self.input_size = 0

        self.input_strings = [ ]
        self.output_strings = [ ]

        self.sinkholes = set()

    def peek_input(self):
        if len(self.input_strings) == 0: return None
        return self.input_strings[0]

    def discard_input(self, num_bytes):
        if len(self.input_strings) == 0: return

        self.input_strings[0] = self.input_strings[0][num_bytes:]
        if self.input_strings[0] == '':
            self.input_strings.pop(0)

    def peek_output(self):
        if len(self.output_strings) == 0: return None
        return self.output_strings[0]

    def discard_output(self, num_bytes):
        if len(self.output_strings) == 0: return

        self.output_strings[0] = self.output_strings[0][num_bytes:]
        if self.output_strings[0] == '':
            self.output_strings.pop(0)

    def addr_invalid(self, a):
        return not self.state.se.solution(a != 0, True)

    def copy(self):
        c = SimStateCGC()
        c.allocation_base = self.allocation_base
        c.time = self.time
        c.input_strings = list(self.input_strings)
        c.output_strings = list(self.output_strings)
        c.input_size = self.input_size
        c.sinkholes = set(self.sinkholes)

        return c

    def _combine(self, others):
        merging_occured = False

        new_allocation_base = max(o.allocation_base for o in others)
        if self.state.se.symbolic(new_allocation_base):
            raise ValueError("wat")

        concrete_allocation_base = (
            self.allocation_base
            if type(self.allocation_base) in (int, long) else
            self.state.se.any_int(self.allocation_base)
        )

        concrete_new_allocation_base = (
            new_allocation_base
            if type(new_allocation_base) in (int, long) else
            self.state.se.any_int(new_allocation_base)
        )

        if concrete_allocation_base != concrete_new_allocation_base:
            self.allocation_base = new_allocation_base
            merging_occured = True

        return merging_occured

    def merge(self, others, merge_conditions):
        return self._combine(others)

    def widen(self, others):
        return self._combine(others)

### HEAP MANAGEMENT

    def get_max_sinkhole(self, length):
        """
        Find a sinkhole which is large enough to support `length` bytes.

        This uses first-fit. The first sinkhole (ordered in descending order by their address)
        which can hold `length` bytes is chosen. If there are more than `length` bytes in the
        sinkhole, a new sinkhole is created representing the remaining bytes while the old
        sinkhole is removed.
        """

        ordered_sinks = sorted(list(self.sinkholes), key=operator.itemgetter(0), reverse=True)
        max_pair = None
        for addr, sz in ordered_sinks:
            if sz >= length:
                max_pair = (addr, sz)
                break

        if max_pair is None:
            return None

        remaining = max_pair[1] - length
        max_addr = max_pair[0] + remaining
        max_length = remaining

        self.sinkholes.remove(max_pair)

        if remaining:
            self.sinkholes.add((max_pair[0], max_length))

        return max_addr

    def add_sinkhole(self, address, length):
        """
        Add a sinkhole.

        Allow the possibility for the program to reuse the memory represented by the
        address length pair.
        """

        self.sinkholes.add((address, length))

SimStatePlugin.register_default('cgc', SimStateCGC)
