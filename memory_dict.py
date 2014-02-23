#!/usr/bin/env python

import collections
import cooldict

import logging
l = logging.getLogger("memory_dict")

# TODO: granularity is still wonky (i.e., requesting something aligned with the granularity, when that byte doesn't exist)

class MemoryDict(collections.MutableMapping):
    """
    Create a memory dict, backed by the binaries. 'what' is either 'mem' or
    'perm'
    """

    _pickle_by_id = True

    def __init__(self, binaries, what, granularity=1):
        self.granularity = granularity
        if what == 'mem':
            mem = [b.get_mem() for b in binaries.values()]
        elif what == 'perm':
            mem = [b.get_perms() for b in binaries.values()]
        else:
            raise Exception("Unknown type.")
        self.mem = cooldict.CachedDict(cooldict.BackedDict(*mem))
        self.dict_id = id(self) # this, and pickle_by_id, are to support smart pickling

    def pull(self):
        """Flattens the memory, if it hasn't already been flattened."""
        if hasattr(self.mem, 'backer'):
            self.mem.backer.flatten()
            self.mem = self.mem.backer.storage

    def round(self, k):
        if self.granularity == 1:
            return k

        return (k / self.granularity) * self.granularity

    def __getitem__(self, k):
        try:
            if type(k) == slice:
                return self.get_bytes(self.round(k.start), self.round(k.stop))
            else:
                return self.mem[self.round(k)]
        except KeyError:
            if type(k) == slice:
                return self.get_bytes(k.start, k.stop)
            else:
                return self.mem[k]

    def __setitem__(self, k, v):
        self.mem[self.round(k)] = v

    def __delitem__(self, k):
        del self.mem[self.round(k)]

    def __iter__(self):
        if self.granularity == 1:
            return self.mem.__iter__()
        else:
            return (_ for _ in set([self.round(k) for k in self.mem.__iter__()]))

    def __len__(self):
        return len(self.mem)

    def __contains__(self, k):
        return self.round(k) in self.mem or k in self.mem

    def get_bytes(self, start, end):
        buff = []
        for i in range(start, end):
            buff.append(self[i])
        return "".join(buff)

    # Pickle support!
    def __getstate__(self):
        if type(self.mem) != dict:
            self.pull()
        return { 'mem': self.mem, 'granularity': self.granularity, 'dict_id': self.dict_id }
