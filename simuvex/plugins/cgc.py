from .plugin import SimStatePlugin

class SimStateCGC(SimStatePlugin):
    '''
    This state plugin keeps track of CGC state.
    '''

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
        return not self.state.satisfiable(extra_constraints=[a!=0])

    def copy(self):
        c = SimStateCGC()
        c.allocation_base = self.allocation_base
        c.time = self.time
        c.input_strings = list(self.input_strings)
        c.output_strings = list(self.output_strings)
        c.input_size = self.input_size
        return c

    def merge(self, others, merge_flag, flag_values):
        merging_occured = False

        new_allocation_base = max(o.allocation_base for o in others)
        if self.state.se.symbolic(new_allocation_base):
            raise ValueError("wat")
        concrete_allocation_base = self.allocation_base if type(self.allocation_base) in (int, long) else \
            self.state.se.any_int(self.allocation_base)
        concrete_new_allocation_base = new_allocation_base if type(new_allocation_base) in (int, long) else \
            self.state.se.any_int(new_allocation_base)
        if concrete_allocation_base != concrete_new_allocation_base:
            self.allocation_base = new_allocation_base
            merging_occured = True

        return merging_occured, [ ]

    def widen(self, others, merge_flag, flag_values):
        # TODO: Recheck this function
        return self.merge(others, merge_flag, flag_values)

SimStatePlugin.register_default('cgc', SimStateCGC)
