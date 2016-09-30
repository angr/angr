import itertools

"""
Basically, "ValueID"s are LLVM's slots, but also tracking named values for convenience.
"""


class ValueID(object):
    pass


class LocalValueID(ValueID):
    pass


class NamedLocalValueID(ValueID):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "%%%s" % self.name


class SlottedLocalValueID(ValueID):
    def __init__(self, slot):
        self.slot = slot

    def __repr__(self):
        return "%%%d" % self.slot


class GlobalValueID(ValueID):
    pass


class NamedGlobalValueID(ValueID):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "@%s" % self.name


class SlottedGlobalValueID(ValueID):
    def __init__(self, slot):
        self.slot = slot

    def __repr__(self):
        return "@%d" % self.slot

def build_slots(func):
    # see llvm/lib/IR/AsmWriter.cpp, SlotTracker::processFunction for comparison

    # we're too cool for a plain int around here
    counter = itertools.count()
    slots = {}

    for arg in func.args:
        if arg.name is None:
            slots[arg] = next(counter)

    for bb in func.basic_blocks:
        if bb.name is None:
            slots[bb] = next(counter)

        for insn in bb.instructions:
            # TODO: fix this once we have a better way of representing types
            if str(insn.type) != 'void' and insn.name is None:
                slots[insn] = next(counter)

    return slots


class ValueIDTracker(object):
    def __init__(self, mod):
        self.mod = mod
        self.globals = {}
        self.locals = {}

        self._initialize_globals()

    def _add_global_value(self, val, counter):
        if val.name:
            self.globals[val] = NamedGlobalValueID(val.name)
        else:
            self.globals[val] = SlottedGlobalValueID(next(counter))

    def _initialize_globals(self):
        # TODO: fill in once all necessary parts are implemented
        counter = itertools.count()

        # for var in self.mod.globals:
        #     self._add_global_value(var, counter)

        # for alias in self.mod.aliases:
        #     self._add_global_value(alias, counter)

        for func in self.mod.functions:
            self._add_global_value(func, counter)

    def _add_local_value(self, storage, val, counter):
        if val.name:
            storage[val] = NamedLocalValueID(val.name)
        else:
            storage[val] = SlottedLocalValueID(next(counter))

    def _initialize_locals(self, func):
        storage = self.locals[func] = {}

        counter = itertools.count()
        slots = {}

        for arg in func.params:
            print arg
            self._add_local_value(storage, arg, counter)

        for bb in func.basic_blocks:
            # print bb
            self._add_local_value(storage, bb, counter)

            for insn in bb.instructions:
                print insn
                # TODO: fix this once we have a better way of representing types
                # import ipdb; ipdb.set_trace()
                if str(insn.type) != 'void':
                    self._add_local_value(storage, insn, counter)

    def lookup_local(self, func, val):
        if func not in self.locals:
            self._initialize_locals(func)

        return self.locals[func].get(val)
