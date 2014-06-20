import simuvex

### Note: this is a copy of libc's state plugin. It might need some further
# adaptation to uclibc

max_mem_per_variable = 2 ** 16

class SimState_uClibc(simuvex.SimStatePlugin):
    '''
    This state plugin keeps track of various libc stuff:

        heap_location: the current location of the heap
        max_str_symbolic_bytes: the maximum number of symbolic bytes
            that a string can have (for the str* sections).
    '''

    #__slots__ = [ 'heap_location', 'max_str_symbolic_bytes' ]

    def __init__(self, heap_location=0xc0000000, max_str_symbolic_bytes = 16):
        simuvex.SimStatePlugin.__init__(self)
        self.heap_location = heap_location
        self.max_str_symbolic_bytes = max_str_symbolic_bytes
        # TODO: Justify this setting!
        self.max_mem_per_variable = 10000

    def copy(self):
        return SimState_uClibc(self.heap_location, self.max_str_symbolic_bytes)

    def merge(self, others, merge_flag, flag_values):
        self.heap_location = max(o.heap_location for o in others)
        return [ ]

simuvex.SimStatePlugin.register_default('uclibc', SimState_uClibc)
