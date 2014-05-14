import simuvex

max_mem_per_variable = 2 ** 16

class SimStateLibc(simuvex.SimStatePlugin):
    '''
    This state plugin keeps track of various libc stuff:
    '''

    #__slots__ = [ 'heap_location', 'max_str_symbolic_bytes' ]

    def __init__(self):
        simuvex.SimStatePlugin.__init__(self)

        # various thresholds
        self.heap_location = 0xc0000000
        self.buf_symbolic_bytes = 48
        self.max_symbolic_search = 16
        self.max_mem_per_variable = 10000
        self.max_buffer_size = 48

        # strtok
        self.strtok_heap = [ ]
        self.simple_strtok = True
        self.strtok_token_size = 1024

    def copy(self):
        c = SimStateLibc()
        c.heap_location = self.heap_location
        c.buf_symbolic_bytes = self.buf_symbolic_bytes
        c.max_symbolic_search = self.max_symbolic_search
        c.max_mem_per_variable = self.max_mem_per_variable
        c.max_buffer_size = self.max_buffer_size

        c.strtok_heap = self.strtok_heap[:]
        c.simple_strtok = self.simple_strtok
        c.strtok_token_size = self.strtok_token_size
        #c.aa = self.aa

        return c

    def merge(self, others, merge_flag, flag_values):
        self.heap_location = max(o.heap_location for o in others)
        return [ ]

simuvex.SimStatePlugin.register_default('libc', SimStateLibc)
