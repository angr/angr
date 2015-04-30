class RegisterMap(object):
    def __init__(self, arch):
        self._reg_map = {}
        # TODO: Properly set the width of a register
        self._general_register_width = arch.bytes

    def assign(self, reg_offset, expr):
        if reg_offset % self._general_register_width == 0:
            self._reg_map[reg_offset] = expr
        else:
            raise Exception("The offset %d is not aligned." % reg_offset)

    def contains(self, reg_offset):
        # TODO: Support unaligned offsets
        assert reg_offset % self._general_register_width == 0
        return reg_offset in self._reg_map

    def get(self, reg_offset):
        if reg_offset % self._general_register_width == 0:
            if reg_offset in self._reg_map:
                return self._reg_map[reg_offset]
            else:
                return None
        else:
            raise Exception("The offset is not aligned.")

    def remove(self, reg_offset):
        if reg_offset % self._general_register_width == 0:
            del self._reg_map[reg_offset]
        else:
            raise Exception("The offset is not aligned.")
