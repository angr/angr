from ....sim_type import SimType, SimTypeReg


class RustSimType(SimType):
    def __init__(self, label=None):
        super().__init__()
        self.label = label


class RustSimTypeInt(SimTypeReg):
    def __init__(self, size, signed, label=None):
        super().__init__(size, label)
        self.signed = signed

    def repr(self, name=None, full=0, memo=None, indent=0):
        if name is None:
            return self.__repr__()
        return f"let {name}: {self.__repr__()}"

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        return self.repr(name, full, memo, indent)

    def __repr__(self):
        name = "i" if self.signed else "u"
        name += str(self.size)
        return name
