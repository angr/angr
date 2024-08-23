# pylint:disable=arguments-differ,assignment-from-no-return,isinstance-second-argument-not-valid-type
from __future__ import annotations
import logging

import claripy

from angr import sim_options as options
from ...utils.cowdict import ChainMapCOW
from ...errors import SimMemoryError, SimMemoryMissingError
from . import MemoryMixin

l = logging.getLogger(name=__name__)


class ConvenientMappingsMixin(MemoryMixin):
    """
    Implements mappings between names and hashes of symbolic variables and these variables themselves.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self._symbolic_addrs: set = set()
        self._name_mapping = ChainMapCOW()
        self._hash_mapping = ChainMapCOW()
        self._updated_mappings = set()

    def copy(self, memo):
        o = super().copy(memo)
        o._symbolic_addrs = set(self._symbolic_addrs)
        o._name_mapping = self._name_mapping.copy()
        o._hash_mapping = self._hash_mapping.copy()
        o._updated_mappings = set()
        return o

    def store(self, addr, data, size=None, **kwargs):
        if options.MEMORY_SYMBOLIC_BYTES_MAP in self.state.options:
            if data.symbolic:
                self._symbolic_addrs.update(range(addr, addr + size))
            else:
                self._symbolic_addrs.difference_update(range(addr, addr + size))

        if not (
            options.REVERSE_MEMORY_NAME_MAP in self.state.options
            or options.REVERSE_MEMORY_HASH_MAP in self.state.options
        ):
            return super().store(addr, data, size=size, **kwargs)

        if options.REVERSE_MEMORY_HASH_MAP not in self.state.options and not data.variables:
            return super().store(addr, data, size=size, **kwargs)

        try:
            if options.REVERSE_MEMORY_NAME_MAP in self.state.options:
                # remove this address for the old variables
                old_obj = self.load(addr, size=size, fill_missing=False, disable_actions=True, inspect=False)

                obj_vars = old_obj.variables
                for v in obj_vars:
                    self._mark_updated_mapping(self._name_mapping, v)
                    self._name_mapping[v].difference_update(range(addr, addr + size))
                    if len(self._name_mapping[v]) == 0:
                        self._name_mapping.pop(v, None)
                        self._updated_mappings.remove((v, id(self._name_mapping)))

                if options.REVERSE_MEMORY_HASH_MAP in self.state.options:
                    h = old_obj.cache_key
                    self._mark_updated_mapping(self._hash_mapping, h)
                    self._hash_mapping[h].difference_update(range(addr, addr + size))
                    if len(self._hash_mapping[h]) == 0:
                        self._hash_mapping.pop(h, None)
                        self._updated_mappings.remove((h, id(self._hash_mapping)))
        except SimMemoryMissingError:
            pass

        if options.REVERSE_MEMORY_NAME_MAP in self.state.options:
            # add the new variables to the mapping
            for v in data.variables:
                self._mark_updated_mapping(self._name_mapping, v)
                if v not in self._name_mapping:
                    self._name_mapping[v] = set()
                self._name_mapping[v].update(range(addr, addr + size))

        if options.REVERSE_MEMORY_HASH_MAP in self.state.options:
            # add the new variables to the hash->addrs mapping
            h = data.cache_key
            self._mark_updated_mapping(self._hash_mapping, h)
            if h not in self._hash_mapping:
                self._hash_mapping[h] = set()
            self._hash_mapping[h].update(range(addr, addr + size))

        return super().store(addr, data, size=size, **kwargs)

    def _default_value(self, addr, size, **kwargs):
        d = super()._default_value(addr, size, **kwargs)
        if addr is not None:
            self._update_mappings(addr, None, d)
        return d

    def _mark_updated_mapping(self, d, m):
        if (m, id(d)) in self._updated_mappings:
            return

        if options.REVERSE_MEMORY_HASH_MAP not in self.state.options and d is self._hash_mapping:
            return
        if options.REVERSE_MEMORY_NAME_MAP not in self.state.options and d is self._name_mapping:
            return

        if d is self._hash_mapping:
            d = self._hash_mapping = d.clean()
        elif d is self._name_mapping:
            d = self._name_mapping = d.clean()

        try:
            d[m] = set(d[m])
        except KeyError:
            d[m] = set()
        self._updated_mappings.add((m, id(d)))

    def _update_mappings(self, actual_addr: int, old_obj: claripy.ast.BV | None, new_obj: claripy.ast.BV):
        if options.MEMORY_SYMBOLIC_BYTES_MAP in self.state.options:
            if self.state.solver.symbolic(new_obj):
                self._symbolic_addrs.add(actual_addr)
            else:
                self._symbolic_addrs.discard(actual_addr)

        if not (
            options.REVERSE_MEMORY_NAME_MAP in self.state.options
            or options.REVERSE_MEMORY_HASH_MAP in self.state.options
        ):
            return

        if (options.REVERSE_MEMORY_HASH_MAP not in self.state.options) and len(
            self.state.solver.variables(new_obj)
        ) == 0:
            return

        l.debug("Updating mappings at address %#x", actual_addr)

        # remove this address for the old variables
        if isinstance(old_obj, claripy.ast.BV):
            l.debug("... removing old mappings")
            if options.REVERSE_MEMORY_NAME_MAP in self.state.options:
                var_set = self.state.solver.variables(old_obj)
                for v in var_set:
                    self._mark_updated_mapping(self._name_mapping, v)
                    self._name_mapping[v].discard(actual_addr)
                    if len(self._name_mapping[v]) == 0:
                        self._name_mapping.pop(v, None)

            if options.REVERSE_MEMORY_HASH_MAP in self.state.options:
                h = hash(old_obj)
                self._mark_updated_mapping(self._hash_mapping, h)
                self._hash_mapping[h].discard(actual_addr)
                if len(self._hash_mapping[h]) == 0:
                    self._hash_mapping.pop(h, None)

        l.debug("... adding new mappings")
        if options.REVERSE_MEMORY_NAME_MAP in self.state.options:
            # add the new variables to the mapping
            var_set = self.state.solver.variables(new_obj)
            for v in var_set:
                self._mark_updated_mapping(self._name_mapping, v)
                if v not in self._name_mapping:
                    self._name_mapping[v] = set()
                self._name_mapping[v].add(actual_addr)

        if options.REVERSE_MEMORY_HASH_MAP in self.state.options:
            # add the new variables to the hash->addrs mapping
            h = hash(new_obj)
            self._mark_updated_mapping(self._hash_mapping, h)
            if h not in self._hash_mapping:
                self._hash_mapping[h] = set()
            self._hash_mapping[h].add(actual_addr)

    def get_symbolic_addrs(self):
        return self._symbolic_addrs

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
                if n in self.load(e, size=1).variables:
                    yield e
                else:
                    to_discard.add(e)
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
                if h == present.cache_key or (
                    present.op == "Extract"
                    and present.args[0] - present.args[1] == 7
                    and h == present.args[2].cache_key
                ):
                    yield e
                else:
                    to_discard.add(e)
            except KeyError:
                to_discard.add(e)
        self._hash_mapping[h] -= to_discard

    def replace_all(self, old: claripy.ast.BV, new: claripy.ast.BV):
        """
        Replaces all instances of expression `old` with expression `new`.

        :param old: A claripy expression. Must contain at least one named variable (to make it possible to use the
                    name index for speedup).
        :param new: The new variable to replace it with.
        """

        if options.REVERSE_MEMORY_NAME_MAP not in self.state.options:
            raise SimMemoryError(
                "replace_all is not doable without a reverse name mapping. Please add "
                "sim_options.REVERSE_MEMORY_NAME_MAP to the state options"
            )

        if not isinstance(old, claripy.ast.BV) or not isinstance(new, claripy.ast.BV):
            raise SimMemoryError("old and new arguments to replace_all() must be claripy.BV objects")

        if len(old.variables) == 0:
            raise SimMemoryError("old argument to replace_all() must have at least one named variable")

        # Computer an intersection between sets of memory addresses for each unique variable name. The eventual address
        # set contains all addresses whose memory objects we should update.
        addrs: set | None = None
        for v in old.variables:
            v: str
            if addrs is None:
                addrs = set(self.addrs_for_name(v))
            elif len(addrs) == 0:
                # It's a set and it's already empty
                # there is no way for it to go back...
                break
            else:
                addrs &= set(self.addrs_for_name(v))

        self._replace_all(addrs, old, new)
