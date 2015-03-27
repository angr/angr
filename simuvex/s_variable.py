
class SimVariable(object):
    def __init__(self):
        pass

class SimRegisterVariable(SimVariable):
    def __init__(self, reg_offset, size):
        SimVariable.__init__(self)

        self.reg = reg_offset
        self.size = size

    def __repr__(self):
        s = "<%d %d>" % (self.reg, self.size)

        return s

class SimMemoryVariable(SimVariable):
    def __init__(self, addr, size):
        SimVariable.__init__(self)

        self.addr = addr
        self.size = size

    def __repr__(self):
        if self.addr in (int, long):
            s = "<0x%x %d>" % (self.addr, self.size)
        else:
            s = "<%s %d>" % (self.addr, self.size)

        return s

class SimVariableSet(object):
    def __init__(self, se):
        self.se = se

        self.register_variables = set()
        self.memory_variables = set()

    def add(self, item):
        if item not in self:
            if isinstance(item, SimRegisterVariable):
                self.register_variables.add(item)
            elif isinstance(item, SimMemoryVariable):
                self.memory_variables.add(item)
            else:
                # TODO:
                raise Exception('')

    def add_memory_variables(self, addrs, size):
        for a in addrs:
            var = SimMemoryVariable(a, size)
            self.add(var)

    def copy(self):
        s = SimVariableSet(self.se)
        s.register_variables |= self.register_variables
        s.memory_variables |= self.memory_variables

        return s

    def __contains__(self, item):
        if isinstance(item, SimRegisterVariable):
            for v in self.register_variables:
                # TODO: Make it better!
                if v.reg == item.reg:
                    return True
        elif isinstance(item, SimMemoryVariable):
            # TODO: Make it better!
            for v in self.memory_variables:
                if self.se.is_true(v.addr == item.addr):
                    return True
