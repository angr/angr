#!/usr/bin/env python

import collections
import cooldict

import logging
l = logging.getLogger("memory_dict")


class MemoryDict(collections.MutableMapping):
    """
    Create a memory dict, backed by the binaries. 'what' is either 'mem' or
    'perm'
    """

    def __init__(self, binaries, what, granularity=1):
        self.granularity = granularity
        if what == 'mem':
            mem = [b.get_mem() for b in binaries.values()]
        elif what == 'perm':
            mem = [b.get_perms() for b in binaries.values()]
        else:
            raise Exception("Unknown type.")
        self.mem = cooldict.CachedDict(cooldict.BackedDict(*mem))

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
                return (
                    self.get_bytes(self.round(k.start), self.round(k.stop))
                )
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
            tuple(set([self.round(k) for k in self.mem.__iter__()]))

    def __len__(self):
        return len(self.mem)

    def __contains__(self, k):
        return self.round(k) in self.mem or k in self.mem

    def get_bytes(self, start, end):
        buff = []
        for i in range(start, end):
            buff.append(self[i])
        return "".join(buff)
