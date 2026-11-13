"""
Address indexes of function maps and FunctionManager caches.

Integer-keyed function maps use the Rust FunctionIndex. PyFunctionIndex implements the same interface for other key
types (SootMethodDescriptor).
"""

from __future__ import annotations

import bisect
from collections import defaultdict
from collections.abc import Hashable, Iterable, Iterator, Mapping
from collections.abc import Set as AbstractSet
from typing import TYPE_CHECKING, Any

from sortedcontainers import SortedList

from angr.rustylib.function_core import FunctionIndex  # pylint:disable=import-error,no-name-in-module

if TYPE_CHECKING:
    from .function_manager import FunctionManager


class PyFunctionIndex:
    """
    FunctionIndex for keys that are not integers. The key-function, binary-name and PLT caches are integer-address
    caches and are kept only for interface compatibility.
    """

    def __init__(self):
        self._addrs = SortedList()
        self._nonreturning: set = set()
        self._unknown_returning: set = set()
        self._block_counts: dict = {}
        self._names: dict = {}
        self._name_to_addrs: defaultdict[str, dict] = defaultdict(dict)
        self._old_name_to_addrs: defaultdict[str, dict] = defaultdict(dict)
        self._from_signature: dict = {}
        self._key_funcs: defaultdict[str, dict] = defaultdict(dict)
        self._binnames: list[tuple[int, int, str | None]] = []
        self._plt_ranges: list[tuple[int, int]] = []
        self._plt_addrs: set[int] = set()

    def copy(self) -> PyFunctionIndex:
        o = PyFunctionIndex()
        o._addrs = SortedList(self._addrs)
        o._nonreturning = set(self._nonreturning)
        o._unknown_returning = set(self._unknown_returning)
        o._block_counts = dict(self._block_counts)
        o._names = dict(self._names)
        o._name_to_addrs = defaultdict(dict, {k: dict(v) for k, v in self._name_to_addrs.items()})
        o._old_name_to_addrs = defaultdict(dict, {k: dict(v) for k, v in self._old_name_to_addrs.items()})
        o._from_signature = dict(self._from_signature)
        o._key_funcs = defaultdict(dict, {k: dict(v) for k, v in self._key_funcs.items()})
        o._binnames = list(self._binnames)
        o._plt_ranges = list(self._plt_ranges)
        o._plt_addrs = set(self._plt_addrs)
        return o

    # ordered addresses

    def add(self, addr) -> bool:
        if addr in self._addrs:
            return False
        self._addrs.add(addr)
        return True

    def discard(self, addr) -> bool:
        if addr in self._addrs:
            self._addrs.remove(addr)
            return True
        return False

    def clear_addrs(self) -> None:
        self._addrs.clear()

    def __contains__(self, addr) -> bool:
        return addr in self._addrs

    def __len__(self) -> int:
        return len(self._addrs)

    def addrs(self) -> list:
        return list(self._addrs)

    def next_addr(self, addr=None):
        i = 0 if addr is None else self._addrs.bisect_right(addr)
        return self._addrs[i] if i < len(self._addrs) else None

    def floor(self, addr):
        i = self._addrs.bisect_right(addr)
        return self._addrs[i - 1] if i > 0 else None

    def ceiling(self, addr):
        i = self._addrs.bisect_left(addr)
        return self._addrs[i] if i < len(self._addrs) else None

    def irange(self, minimum=None, maximum=None, inclusive=(True, True), reverse=False) -> list:
        return list(self._addrs.irange(minimum, maximum, inclusive=inclusive, reverse=reverse))

    # returning status

    def set_returning(self, addr, v: bool | None) -> None:
        if v is False:
            self._nonreturning.add(addr)
            self._unknown_returning.discard(addr)
        elif v is True:
            self._nonreturning.discard(addr)
            self._unknown_returning.discard(addr)
        else:
            self._unknown_returning.add(addr)
            self._nonreturning.discard(addr)

    def is_nonreturning(self, addr) -> bool:
        return addr in self._nonreturning

    def is_returning_unknown(self, addr) -> bool:
        return addr in self._unknown_returning

    def nonreturning_addrs(self) -> list:
        return list(self._nonreturning)

    def unknown_returning_addrs(self) -> list:
        return list(self._unknown_returning)

    # block counts

    def set_block_count(self, addr, count: int) -> None:
        self._block_counts[addr] = count

    def block_count(self, addr) -> int | None:
        return self._block_counts.get(addr)

    def block_counts(self) -> dict:
        return dict(self._block_counts)

    def addrs_with_block_count(self, count: int) -> set:
        return {a for a, c in self._block_counts.items() if c == count}

    # names

    def name_changed(self, addr, old_name: str | None, new_name: str) -> None:
        if old_name is not None:
            addrs = self._name_to_addrs.get(old_name)
            if addrs is not None:
                addrs.pop(addr, None)
                if not addrs:
                    del self._name_to_addrs[old_name]
            self._old_name_to_addrs[old_name][addr] = None
        self._name_to_addrs[new_name][addr] = None
        self._names[addr] = new_name

    def add_name_addr(self, name: str, addr) -> None:
        self._name_to_addrs[name][addr] = None

    def add_old_name_addr(self, name: str, addr) -> None:
        self._old_name_to_addrs[name][addr] = None

    def name(self, addr) -> str | None:
        return self._names.get(addr)

    def addrs_by_name(self, name: str, check_previous_names: bool = False) -> list:
        addrs = dict(self._name_to_addrs.get(name, {}))
        if check_previous_names:
            addrs.update(self._old_name_to_addrs.get(name, {}))
        out = list(addrs)
        if all(isinstance(a, int) for a in out):
            out.sort()
        return out

    def addrs_by_name_set(self, name: str, check_previous_names: bool = False) -> set:
        addrs = list(self._name_to_addrs.get(name, {}))
        if check_previous_names:
            addrs = list(self._old_name_to_addrs.get(name, {})) + addrs
        s = set()
        for a in addrs:
            s.add(a)
        return s

    # signature sources

    def set_from_signature(self, addr, from_signature: str | None) -> None:
        self._from_signature[addr] = from_signature

    def from_signature(self, addr) -> str | None:
        return self._from_signature.get(addr)

    def addrs_from_signature(self, from_signature: str) -> set:
        return {a for a, s in self._from_signature.items() if s == from_signature}

    # key functions

    def add_key_func(self, func_type: str, addr) -> None:
        self._key_funcs[func_type][addr] = None

    def key_func_addrs(self, func_type: str) -> set:
        return set(self._key_funcs.get(func_type, {}))

    def key_funcs(self) -> dict[str, set]:
        return {t: set(addrs) for t, addrs in self._key_funcs.items()}

    def index_info(self, addr, info: Mapping[str, Any]) -> None:
        for key, value in info.items():
            if key.startswith("is_") and value is True:
                self.add_key_func(key[3:], addr)

    # function addition and removal

    def function_added(self, addr, returning, block_count: int, from_signature: str | None, name: str) -> None:
        self.set_returning(addr, returning)
        self._block_counts[addr] = block_count
        self._from_signature[addr] = from_signature
        self.name_changed(addr, None, name)

    def function_removed(self, addr, previous_names: list[str]) -> None:
        self._nonreturning.discard(addr)
        self._unknown_returning.discard(addr)
        self._block_counts.pop(addr, None)
        name = self._names.pop(addr, None)
        if name is not None:
            addrs = self._name_to_addrs.get(name)
            if addrs is not None:
                addrs.pop(addr, None)
                if not addrs:
                    del self._name_to_addrs[name]
        self._from_signature.pop(addr, None)
        for old_name in previous_names:
            self._old_name_to_addrs.get(old_name, {}).pop(addr, None)
        for addrs in self._key_funcs.values():
            addrs.pop(addr, None)

    def clear_caches(self) -> None:
        addrs = self._addrs
        self.__init__()
        self._addrs = addrs

    # binary names and PLT stubs

    def binary_name_cached(self, addr: int) -> tuple[bool, str | None]:
        i = bisect.bisect_right(self._binnames, addr, key=lambda e: e[0])
        if i > 0 and addr < self._binnames[i - 1][1]:
            return True, self._binnames[i - 1][2]
        return False, None

    def cache_binary_name(self, min_addr: int, max_addr: int, name: str | None) -> None:
        i = bisect.bisect_left(self._binnames, min_addr, key=lambda e: e[0])
        if i < len(self._binnames) and self._binnames[i][0] == min_addr:
            self._binnames[i] = (min_addr, max_addr, name)
        else:
            self._binnames.insert(i, (min_addr, max_addr, name))

    def plt_cached(self, addr: int) -> bool | None:
        i = bisect.bisect_right(self._plt_ranges, addr, key=lambda e: e[0])
        if i > 0 and addr < self._plt_ranges[i - 1][1]:
            return addr in self._plt_addrs
        return None

    def is_plt_addr(self, addr: int) -> bool:
        return addr in self._plt_addrs

    def cache_plt_range(self, min_addr: int, max_addr: int, plt_addrs: list[int] | None = None) -> None:
        i = bisect.bisect_left(self._plt_ranges, min_addr, key=lambda e: e[0])
        if not (i < len(self._plt_ranges) and self._plt_ranges[i][0] == min_addr):
            self._plt_ranges.insert(i, (min_addr, max_addr))
        if plt_addrs is not None:
            self._plt_addrs.update(plt_addrs)


AnyFunctionIndex = FunctionIndex | PyFunctionIndex


def make_function_index(key_types: type | tuple[type, ...]) -> AnyFunctionIndex:
    """
    The index for a function map whose keys are of the given type(s).
    """
    if key_types is int or key_types == (int,):
        return FunctionIndex()
    return PyFunctionIndex()


def make_function_index_for_keys(keys: Iterable[Hashable]) -> AnyFunctionIndex:
    if all(type(k) is int for k in keys):  # pylint:disable=unidiomatic-typecheck
        return FunctionIndex()
    return PyFunctionIndex()


class FunctionAddrsView(AbstractSet):
    """
    ``FunctionManager.function_addrs_set``: a read-only set view of the function addresses.
    """

    __slots__ = ("_fm",)

    def __init__(self, fm: FunctionManager):
        self._fm = fm

    def __contains__(self, addr) -> bool:
        return self._fm.contains_addr(addr)

    def __len__(self) -> int:
        return len(self._fm)

    def __iter__(self) -> Iterator:
        return iter(self._fm)

    @classmethod
    def _from_iterable(cls, it) -> set:
        return set(it)

    def copy(self) -> set:
        return set(self._fm)

    def __repr__(self) -> str:
        return f"FunctionAddrsView({set(self._fm)!r})"


__all__ = (
    "AnyFunctionIndex",
    "FunctionAddrsView",
    "FunctionIndex",
    "PyFunctionIndex",
    "make_function_index",
    "make_function_index_for_keys",
)
