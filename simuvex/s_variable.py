import collections
import claripy

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

    def __hash__(self):
        return hash('reg_%d_%d' % (self.reg, self.size))

    def __eq__(self, other):
        if isinstance(other, SimRegisterVariable):
            return hash(self) == hash(other)

        else:
            return False

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

    def __hash__(self):
        return hash('%d_%d' % (hash(self.addr), self.size))

    def __eq__(self, other):
        if isinstance(other, SimMemoryVariable):
            return hash(self) == hash(other)

        else:
            return False

class SimVariableSet(collections.MutableSet):
    def __init__(self):
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

    def discard(self, item):
        if item in self:
            if isinstance(item, SimRegisterVariable):
                self.register_variables.discard(item)
            elif isinstance(item, SimMemoryVariable):
                self.memory_variables.discard(item)
            else:
                # TODO:
                raise Exception('')

    def __len__(self):
        return len(self.register_variables) + len(self.memory_variables)

    def __iter__(self):
        for i in self.register_variables: yield i
        for i in self.memory_variables: yield i

    def add_memory_variables(self, addrs, size):
        for a in addrs:
            var = SimMemoryVariable(a, size)
            self.add(var)

    def copy(self):
        s = SimVariableSet()
        s.register_variables |= self.register_variables
        s.memory_variables |= self.memory_variables

        return s

    def complement(self, other):
        """
        Calculate the complement of `self` and `other`
        :param other: Another SimVariableSet instance
        :return: The complement result
        """

        s = SimVariableSet()
        s.register_variables = self.register_variables - other.register_variables
        s.memory_variables = self.memory_variables - other.memory_variables

        return s

    def __contains__(self, item):
        if isinstance(item, SimRegisterVariable):
            for v in self.register_variables:
                # TODO: Make it better!
                if v.reg == item.reg:
                    return True
            return False
        elif isinstance(item, SimMemoryVariable):
            # TODO: Make it better!
            a = item.addr
            if isinstance(a, (tuple, list)): a = a[-1]

            for v in self.memory_variables:
                b = v.addr
                if isinstance(b, (tuple, list)): b = b[-1]

                if (isinstance(a, claripy.Base) or isinstance(b, claripy.Base)) and (a == b).is_true():
                    return True
                elif a == b:
                    return True
