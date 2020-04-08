import collections

from angr import sim_options as options
from . import MemoryMixin

class ConvenientMappingsMixin(MemoryMixin):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self._symbolic_addrs = set()
        self._name_mapping = collections.ChainMap()
        self._hash_mapping = collections.ChainMap()
        self._updated_mappings = set()

    def copy(self, memo):
        o = super().copy(memo)
        o._symbolic_addrs = set(self._symbolic_addrs)
        o._name_mapping = self._name_mapping.new_child()
        o._hash_mapping = self._hash_mapping.new_child()
        return o

    def store(self, addr, data, size=None, **kwargs):
        if options.MEMORY_SYMBOLIC_BYTES_MAP in self.state.options:
            if data.symbolic:
                self._symbolic_addrs.update(range(addr, addr+size))
            else:
                self._symbolic_addrs.difference_update(range(addr, addr+size))

        if not (options.REVERSE_MEMORY_NAME_MAP in self.state.options or
                options.REVERSE_MEMORY_HASH_MAP in self.state.options):
            return super().store(addr, data, size=size, **kwargs)

        if options.REVERSE_MEMORY_HASH_MAP not in self.state.options and not data.variables:
            return super().store(addr, data, size=size, **kwargs)

        try:
            # remove this address for the old variables
            old_obj = self.load(addr, size=size)

            if options.REVERSE_MEMORY_NAME_MAP in self.state.options:
                obj_vars = old_obj.variables
                for v in obj_vars:
                    self._mark_updated_mapping(self._name_mapping, v)
                    self._name_mapping[v].difference_update(range(addr, addr+size))
                    if len(self._name_mapping[v]) == 0:
                        self._name_mapping.pop(v, None)

                if options.REVERSE_MEMORY_HASH_MAP in self.state.options:
                    h = old_obj.cache_key
                    self._mark_updated_mapping(self._hash_mapping, h)
                    self._hash_mapping[h].difference_update(range(addr, addr+size))
                    if len(self._hash_mapping[h]) == 0:
                        self._hash_mapping.pop(h, None)
        except KeyError:
            pass

        if options.REVERSE_MEMORY_NAME_MAP in self.state.options:
            # add the new variables to the mapping
            for v in data.variables:
                self._mark_updated_mapping(self._name_mapping, v)
                if v not in self._name_mapping:
                    self._name_mapping[v] = set()
                self._name_mapping[v].update(range(addr, addr+size))

        if options.REVERSE_MEMORY_HASH_MAP in self.state.options:
            # add the new variables to the hash->addrs mapping
            h = data.cache_key
            self._mark_updated_mapping(self._hash_mapping, h)
            if h not in self._hash_mapping:
                self._hash_mapping[h] = set()
            self._hash_mapping[h].update(range(addr, addr+size))

        return super().store(addr, data, size=size, **kwargs)

    def _mark_updated_mapping(self, d, m):
        # TODO: wtf is this logic, this can't be right
        if m in self._updated_mappings:
            return

        if options.REVERSE_MEMORY_HASH_MAP not in self.state.options and d is self._hash_mapping:
            return
        if options.REVERSE_MEMORY_NAME_MAP not in self.state.options and d is self._name_mapping:
            return

        try:
            d[m] = set(d[m])
        except KeyError:
            d[m] = set()
        self._updated_mappings.add(m)

    def addrs_for_name(self, n):
        """
        Returns addresses that contain expressions that contain a variable named `n`.
        """
        if n not in self._name_mapping:
            return

        self._mark_updated_mapping(self._name_mapping, n)

        to_discard = set()
        for e in self._name_mapping[n]:
            try:
                if n in self.load(e, size=1).variables: yield e
                else: to_discard.add(e)
            except KeyError:
                to_discard.add(e)
        self._name_mapping[n] -= to_discard

    def addrs_for_hash(self, h):
        """
        Returns addresses that contain expressions that contain a variable with the hash of `h`.
        """
        if h not in self._hash_mapping:
            return

        self._mark_updated_mapping(self._hash_mapping, h)

        to_discard = set()
        for e in self._hash_mapping[h]:
            try:
                present = self.load(e, size=1)
                if h == present.cache_key or (present.op == 'Extract' and present.args[0] - present.args[1] == 7 and h == present.args[2].cache_key): yield e
                else: to_discard.add(e)
            except KeyError:
                to_discard.add(e)
        self._hash_mapping[h] -= to_discard
