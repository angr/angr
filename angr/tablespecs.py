import claripy

class StringSpec(object):
    def __new__(cls, string=None, sym_length=None, concat=None, name=None, nonnull=False):
        print 'StringSpec is deprecated! Please use raw claripy ASTs or else face my wrath.'
        if nonnull:
            print 'Additional deprecation warning: nonnull completely doesn\'t work in our hacked up support shint for StringSpec. Please just fix your code. Please.'

        if string is not None:
            return StringTableSpec.string_to_ast(string)
        if sym_length is not None:
            if name is None:
                name = 'stringspec_sym_%d' % sym_length
            return claripy.BVS(name, sym_length * 8)
        if concat is not None:
            return claripy.Concat(*concat)

class StringTableSpec(object):
    @staticmethod
    def string_to_ast(string):
            return claripy.Concat(*(claripy.BVV(ord(c), 8) for c in string))

    def __init__(self):
        self._contents = []
        self._str_len = 0

    def add_string(self, string):
        if isinstance(string, str):
            self._contents.append(('string', self.string_to_ast(string+'\0')))
            self._str_len += len(string) + 1
        elif isinstance(string, claripy.ast.Bits):
            self._contents.append(('string', string.concat(claripy.BVV(0, 8))))
            self._str_len += len(string) / 8 + 1
        else:
            raise ValueError('String must be either string literal or claripy AST')

    def add_pointer(self, pointer):
        self._contents.append(('pointer', pointer))

    def add_null(self):
        self.add_pointer(0)

    def dump(self, state, end_addr, align=0x10):
        if isinstance(end_addr, (int, long)):
            end_addr = state.se.BVV(end_addr, state.arch.bits)
        ptr_size = len(self._contents) * state.arch.bytes
        size = self._str_len + ptr_size
        start_addr = end_addr - size
        zero_fill = state.se.any_int(start_addr % align)
        start_addr -= zero_fill
        start_str = start_addr + ptr_size

        ptr_i = start_addr
        str_i = start_str
        for itemtype, item in self._contents:
            if itemtype == 'string':
                state.memory.store(ptr_i, str_i, endness=state.arch.memory_endness)
                state.memory.store(str_i, item)
                ptr_i += state.arch.bytes
                str_i += len(item)/8
            else:
                if isinstance(item, (int, long)):
                    item = state.se.BVV(item, state.arch.bits)
                state.memory.store(ptr_i, item, endness=state.arch.memory_endness)
                ptr_i += state.arch.bytes

        if zero_fill != 0:
            state.memory.store(end_addr - zero_fill, state.se.BVV(0, 8*zero_fill))

        return start_addr
