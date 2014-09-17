from .plugin import SimStatePlugin

class SimStateLibc(SimStatePlugin):
    '''
    This state plugin keeps track of various libc stuff:
    '''

    #__slots__ = [ 'heap_location', 'max_str_symbolic_bytes' ]

    def __init__(self):
        SimStatePlugin.__init__(self)

        # various thresholds
        self.heap_location = 0xc0000000
        self.buf_symbolic_bytes = 60
        self.max_symbolic_strstr = 1
        self.max_symbolic_strchr = 16
        self.max_variable_size = 128
        self.max_str_len = 128
        self.max_buffer_size = 48

        # strtok
        self.strtok_heap = [ ]
        self.simple_strtok = True
        self.strtok_token_size = 1024

        # helpful stuff
        self.strdup_stack = [ ]

    def copy(self):
        c = SimStateLibc()
        c.heap_location = self.heap_location
        c.buf_symbolic_bytes = self.buf_symbolic_bytes
        c.max_symbolic_strstr = self.max_symbolic_strstr
        c.max_symbolic_strchr = self.max_symbolic_strchr
        c.max_variable_size = self.max_variable_size
        c.max_buffer_size = self.max_buffer_size
        c.max_str_len = self.max_str_len
        c.strtok_heap = self.strtok_heap[:]
        c.simple_strtok = self.simple_strtok
        c.strtok_token_size = self.strtok_token_size
        c.strdup_stack = self.strdup_stack[:]
        #c.aa = self.aa

        return c

    def merge(self, others, merge_flag, flag_values):
        self.heap_location = max(o.heap_location for o in others)
        return [ ]

SimStatePlugin.register_default('libc', SimStateLibc)
