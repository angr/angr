import collections
import claripy

class SimVariable(object):
    def __init__(self):
        pass

class SimTemporaryVariable(SimVariable):
    def __init__(self, tmp_id):
        SimVariable.__init__(self)

        self.tmp_id = tmp_id

    def __repr__(self):
        s = "<tmp %d>" % (self.tmp_id)

        return s

    def __hash__(self):
        return hash('tmp_%d' % (self.tmp_id))

    def __eq__(self, other):
        if isinstance(other, SimTemporaryVariable):
            return hash(self) == hash(other)

        else:
            return False

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

        if isinstance(size, claripy.ast.BV) and not size.symbolic:
            # Convert it to a concrete number
            size = size.model.value

        self.size = size

    def __repr__(self):
        if type(self.size) in (int, long):
            size = '%d' % self.size
        else:
            size = '%s' % self.size

        if type(self.addr) in (int, long):
            s = "<0x%x %s>" % (self.addr, size)
        else:
            s = "<%s %s>" % (self.addr, size)

        return s

    def __hash__(self):
        if isinstance(self.addr, claripy.ast.BV):
            addr_hash = hash(self.addr.model)
        else:
            addr_hash = hash(self.addr)
        return hash((addr_hash, hash(self.size)))

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
