# pylint:disable=raise-missing-from
from __future__ import annotations

import shutil
from typing import TypeVar, Generic, cast, TYPE_CHECKING, overload
from collections.abc import Iterator, Generator
from collections import OrderedDict
import contextlib
import logging
import collections.abc
import re
import weakref
import bisect
import os
import tempfile
import uuid

import lmdb
import networkx

from archinfo.arch_soot import SootMethodDescriptor
import cle
from cachetools import LRUCache

from angr.errors import SimEngineError
from angr.codenode import FuncNode
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from .function import Function
from .soot_function import SootFunction

K = TypeVar("K", int, SootMethodDescriptor)
T = TypeVar("T")

if TYPE_CHECKING:
    from angr import KnowledgeBase

    class SortedDict(Generic[K, T], dict[K, T]):
        def irange(self, *args, **kwargs) -> Iterator[K]: ...

else:
    from sortedcontainers import SortedDict, SortedList, SortedKeysView, SortedItemsView, SortedValuesView

QUERY_PATTERN = re.compile(r"^(::(.+?))?::(.+)$")
ADDR_PATTERN = re.compile(r"^(0x[\dA-Fa-f]+)|(\d+)$")

l = logging.getLogger(name=__name__)
_missing = object()

# Default maximum number of functions to keep in memory (None means unlimited)
DEFAULT_MAX_CACHED_FUNCTIONS: int | None = 1000


class FunctionDictBase(Generic[K]):
    """
    Base class for FunctionDict and SpillingFunctionDict.
    """

    def __init__(self, backref: FunctionManager[K] | None, key_types: type = int):
        self._backref = (
            cast(FunctionManager[K], backref if isinstance(backref, weakref.ProxyType) else weakref.proxy(backref))
            if backref is not None
            else None
        )
        self._key_types = key_types

    def _getitem_create_new_function(self, addr: K) -> Function:
        # Create a new function
        if isinstance(addr, SootMethodDescriptor):
            t = SootFunction(self._backref, addr)
        else:
            t = Function(self._backref, addr)
        self[addr] = t
        if self._backref is not None:
            self._backref._function_added(t)
        return t

    def floor_addr(self, addr: K):
        try:
            return next(self.irange(maximum=addr, reverse=True))
        except StopIteration as err:
            raise KeyError(addr) from err

    def ceiling_addr(self, addr):
        try:
            return next(self.irange(minimum=addr, reverse=False))
        except StopIteration as err:
            raise KeyError(addr) from err

    def __setstate__(self, state):
        for v, k in state.items():
            self[k] = v

    def __getstate__(self):
        return dict(self.items())

    def __setitem__(self, addr: K, value: Function):
        raise NotImplementedError

    def __getitem__(self, addr: K) -> Function:
        raise NotImplementedError

    def __delitem__(self, key: K) -> None:
        raise NotImplementedError

    def items(self):
        raise NotImplementedError

    @overload
    def get(self, key: K, default: None = None, /, meta_only: bool = False) -> Function: ...
    @overload
    def get(self, key: K, default: Function, /, meta_only: bool = False) -> Function: ...
    @overload
    def get(self, key: K, default: T, /, meta_only: bool = False) -> Function | T: ...

    def get(self, addr: K, default=_missing, /, meta_only: bool = False):
        raise NotImplementedError

    def irange(self, minimum=None, maximum=None, inclusive=(True, True), reverse=False):
        raise NotImplementedError


class FunctionDict(SortedDict[K, Function], FunctionDictBase[K]):
    """
    FunctionDict is a dict where the keys are function starting addresses and map to the associated :class:`Function`.
    """

    def __init__(self, backref: FunctionManager[K] | None, *args, key_types: type = int, **kwargs):
        SortedDict.__init__(self, *args, **kwargs)
        FunctionDictBase.__init__(self, backref, key_types=key_types)

    def copy(self) -> FunctionDict[K]:
        return FunctionDict(self._backref, self, key_types=self._key_types)

    def __setitem__(self, addr: K, value: Function):
        """
        Override SortedDict.__setitem__ because it uses __contains__, which may be overwritten by SpillingFunctionDict.
        """
        super().__setitem__(addr, value)

    def __getitem__(self, addr: K) -> Function:
        try:
            return super().__getitem__(addr)
        except KeyError as ex:
            if isinstance(addr, bool) or not isinstance(addr, self._key_types):
                raise TypeError(f"FunctionDict only supports {self._key_types} as key type") from ex
            return self._getitem_create_new_function(addr)

    def __delitem__(self, key: K) -> None:
        super().__delitem__(key)

    def get(self, addr: K, default=_missing, /, meta_only: bool = False):
        try:
            return super().__getitem__(addr)
        except KeyError:
            pass

        if default is _missing:
            raise KeyError(addr)
        return default

    def floor_addr(self, addr: K):
        try:
            return next(self.irange(maximum=addr, reverse=True))
        except StopIteration as err:
            raise KeyError(addr) from err

    def ceiling_addr(self, addr):
        try:
            return next(self.irange(minimum=addr, reverse=False))
        except StopIteration as err:
            raise KeyError(addr) from err

    def __setstate__(self, state):
        for v, k in state.items():
            self[k] = v

    def __getstate__(self):
        return dict(self.items())


class SpillingFunctionDict(dict[K, Function], FunctionDictBase[K]):
    """
    SpillingFunctionDict extends FunctionDict with LRU caching and LMDB spilling. This class keeps only the most
    recently accessed N functions in memory, spilling others to an LMDB database on disk.

    SpillingFunctionDict also keeps a cache of meta-only Function objects that do not have graph or block information.
    These meta-only Function objects are read-only and may become stale if the full Function is later loaded and
    updated. Therefore, please be extremely cautious when using these meta-only Function objects.

    :ivar cache_limit:          The maximum number of functions to keep in memory.
    :ivar _lmdb_batch_size:     The number of functions that are evicted in a single batch.
    """

    def __init__(
        self,
        backref: FunctionManager[K] | None,
        *args,
        key_types: type = int,
        cache_limit: int | None = None,
        **kwargs,
    ):
        dict.__init__(self, *args, **kwargs)
        FunctionDictBase.__init__(self, backref, key_types=key_types)

        self._cache_limit: int | None = cache_limit
        self._lru_order: OrderedDict[K, None] = OrderedDict()
        self._spilled_keys: set[K] = set()
        self._list = SortedList()  # a sorted list of all keys (cached + spilled)
        self.irange = self._list.irange

        self._meta_func_cache: LRUCache[K, Function] = LRUCache(maxsize=cache_limit)
        self._lmdb_env: lmdb.Environment | None = None
        self._lmdb_path: str | None = None
        self._lmdb_funcsdb = None
        self._lmdb_mapsize: int = 1024 * 1024 * 10
        self._lmdb_batch_size: int = 100
        self._eviction_enabled: bool = True
        self._loading_from_lmdb: bool = False
        self._currently_loading: set[K] = set()

    def __del__(self):
        self._cleanup_lmdb()

    def __getitem__(self, addr: K) -> Function:
        # First try to get from in-memory cache
        if self.is_cached(addr):
            try:
                func = super().__getitem__(addr)
                # Touch to update LRU order
                self._touch(addr)
                return func
            except KeyError:
                pass

        # not found in memory
        if isinstance(addr, bool) or not isinstance(addr, self._key_types):
            raise TypeError(f"SpillingFunctionDict only supports {self._key_types} as key type")

        # Try to load from LMDB if it's spilled
        if addr in self._spilled_keys and not self._loading_from_lmdb:
            func = self._load_from_lmdb(addr)
            if func is not None:
                return func

        return self._getitem_create_new_function(addr)

    def __setitem__(self, key: K, value: Function) -> None:
        if key not in self:
            self._list.add(key)
        super().__setitem__(key, value)
        self._on_function_stored(key)

    def __delitem__(self, key: K) -> None:
        # Remove from in-memory map if present
        if self.is_cached(key):
            super().__delitem__(key)
        # Remove from spilled set if present; don't remove it from lmdb to save time
        if key in self._spilled_keys:
            self._spilled_keys.discard(key)
        # Remove from LRU order
        if key in self._lru_order:
            del self._lru_order[key]
        # Remove from sorted list
        self._list.remove(key)

    def copy(self) -> SpillingFunctionDict[K]:
        # Load all spilled functions for copying
        self._load_all_spilled()

        new_dict = SpillingFunctionDict(
            self._backref,
            key_types=self._key_types,
            cache_limit=self._cache_limit,
        )
        # Temporarily disable eviction during copy
        new_dict._eviction_enabled = False
        # iterate over in-memory functions and copy them
        for address in self.cached_keys:
            function = SortedDict.__getitem__(self, address)
            SortedDict.__setitem__(new_dict, address, function.copy())
            new_dict._lru_order[address] = None

        # Copy any remaining spilled addresses and their LMDB data
        if self._spilled_keys and self._lmdb_env is not None:
            new_dict._init_lmdb()
            with (
                self._lmdb_env.begin(db=self._lmdb_funcsdb) as src_txn,
                new_dict._lmdb_env.begin(write=True, db=new_dict._lmdb_funcsdb) as dst_txn,
            ):
                for addr in self._spilled_keys:
                    key = str(addr).encode("utf-8")
                    value = src_txn.get(key)
                    if value is not None:
                        dst_txn.put(key, value)
                        new_dict._spilled_keys.add(addr)

        new_dict._eviction_enabled = True
        return new_dict

    def clear(self) -> None:
        """
        Clear all functions from memory and spilled storage.
        """
        super().clear()
        self._lru_order.clear()
        self._spilled_keys.clear()
        self._cleanup_lmdb()

    def __contains__(self, item) -> bool:
        # Check both in-memory and spilled
        return super().__contains__(item) or item in self._spilled_keys

    def __len__(self) -> int:
        # Total count includes both in-memory and spilled functions
        return self.cached_count + len(self._spilled_keys)

    def __iter__(self):
        # Iterate over all function addresses (cached + spilled)
        return self._list.__iter__()

    def get(self, addr, default=_missing, /, meta_only: bool = False):
        # First check in-memory
        if self.is_cached(addr):
            try:
                func = super().__getitem__(addr)
                self._touch(addr)
                return func
            except KeyError:
                pass

        # Check if spilled to LMDB
        if addr in self._spilled_keys:
            if meta_only and addr in self._meta_func_cache:
                return self._meta_func_cache[addr]
            if not self._loading_from_lmdb:
                func = self._load_from_lmdb(addr, meta_only=meta_only)
                if func is not None:
                    return func

        if default is _missing:
            raise KeyError(addr)
        return default

    def keys(self):
        return SortedKeysView(self)

    def items(self):
        return SortedItemsView(self)

    def values(self):
        return SortedValuesView(self)

    #
    # Properties
    #

    @property
    def cached_keys(self) -> Generator[None, None, K]:
        yield from self._list

    @property
    def cache_limit(self) -> int | None:
        """
        Get the maximum number of functions to keep in memory.
        """
        return self._cache_limit

    @cache_limit.setter
    def cache_limit(self, value: int | None) -> None:
        """
        Set the maximum number of functions to keep in memory.
        """
        self._cache_limit = value
        if value is not None and self.cached_count > value + self._lmdb_batch_size:
            self._evict_lru()

    @property
    def cached_count(self) -> int:
        """Return the number of functions currently in memory."""
        return super().__len__()

    @property
    def spilled_count(self) -> int:
        """Return the number of functions currently spilled to LMDB."""
        return len(self._spilled_keys)

    @property
    def total_count(self) -> int:
        """Return the total number of functions (in memory + spilled)."""
        return super().__len__() + len(self._spilled_keys)

    def is_cached(self, addr: K) -> bool:
        return super().__contains__(addr)

    #
    # LRU Cache Management
    #

    def _touch(self, addr: K) -> None:
        """
        Update the LRU order for a function (move to end = most recently used).
        """
        if addr in self._lru_order:
            self._lru_order.move_to_end(addr)
        else:
            self._lru_order[addr] = None
        if addr in self._meta_func_cache:
            del self._meta_func_cache[addr]

    def _on_function_stored(self, addr: K) -> None:
        self._touch(addr)

        # Remove from spilled set if it was there
        self._spilled_keys.discard(addr)

        # Check if we need to evict (but not during loading)
        if (
            self._eviction_enabled
            and not self._loading_from_lmdb
            and self._cache_limit is not None
            and SortedDict.__len__(self) > self._cache_limit
        ):
            self._evict_lru()

    def _evict_lru(self) -> bool:
        """
        Evict functions until we're back under the cache limit.

        :return: True if at least one function was successfully evicted, False otherwise.
        """
        evicted_any = False
        while self.cached_count > self._cache_limit + self._lmdb_batch_size:
            if self._evict_n(self._lmdb_batch_size) == 0:
                break
            evicted_any = True
        return evicted_any

    def _evict_n(self, n: int) -> int:
        """
        Evict n least recently used functions to LMDB.

        :return: The number of functions that were successfully evicted.
        """
        if not self._lru_order:
            return 0

        evicted = 0
        funcs_to_evict = []
        for lru_addr in list(self._lru_order):
            if evicted >= n:
                break

            # Don't evict if it's not in memory
            if not self.is_cached(lru_addr):
                self._lru_order.pop(lru_addr)
                continue

            # Get the function
            func = super().__getitem__(lru_addr)
            if func.dirty:
                funcs_to_evict.append(func)

            # Remove from in-memory map
            super().__delitem__(lru_addr)

            # Remove from LRU order
            del self._lru_order[lru_addr]

            # Add to spilled set
            self._spilled_keys.add(lru_addr)
            evicted += 1

            l.debug("Evicted function %s", hex(lru_addr) if isinstance(lru_addr, int) else lru_addr)

        if funcs_to_evict:
            self._save_to_lmdb(funcs_to_evict)

        return evicted

    #
    # LMDB Management
    #

    def _init_lmdb(self) -> None:
        """
        Lazily initialize the LMDB database for spilling functions.
        """
        if self._lmdb_env is not None:
            return

        # Only generate the path once
        if self._lmdb_path is None:
            self._lmdb_path = os.path.join(tempfile.gettempdir(), f"angr_lru_cache_{uuid.uuid4().hex}")

        self._lmdb_env = lmdb.open(self._lmdb_path, map_size=self._lmdb_mapsize, max_dbs=1)
        self._lmdb_funcsdb = self._lmdb_env.open_db(b"functions.radb")
        l.debug("Initialized LRU cache LMDB at %s", self._lmdb_path)

    def _cleanup_lmdb(self):
        """
        Clean up LMDB resources.
        """
        if self._lmdb_env is not None:
            self._lmdb_env.close()
            self._lmdb_env = None
            self._lmdb_funcsdb = None

        if self._lmdb_path is not None:
            with contextlib.suppress(OSError):
                shutil.rmtree(self._lmdb_path)
            self._lmdb_path = None

    def _increase_lmdb_map_size(self) -> None:
        """
        Increase the LMDB map size.
        """
        delta = min(self._lmdb_mapsize, 1024 * 1024 * 256)
        l.debug("Increasing LMDB map size by %d bytes", delta)
        self._lmdb_mapsize += delta
        self._lmdb_env.set_mapsize(self._lmdb_mapsize)

    def _save_to_lmdb(self, funcs: list[Function]) -> None:
        """
        Save multiple functions to LMDB.
        """
        self._init_lmdb()

        last_idx = 0

        while True:
            try:
                with self._lmdb_env.begin(write=True, db=self._lmdb_funcsdb) as txn:
                    for idx, func in enumerate(funcs):
                        if idx < last_idx:
                            continue
                        cmsg = func.serialize_to_cmessage()
                        key = str(func.addr).encode("utf-8")
                        txn.put(key, cmsg.SerializeToString())
                        last_idx = idx
            except lmdb.MapFullError:
                # Increase map size and retry
                self._increase_lmdb_map_size()
                continue

            break

    def _delete_from_lmdb(self, addr: K) -> None:
        """
        Delete a function from LMDB.
        """
        if self._lmdb_env is None:
            return

        key = str(addr).encode("utf-8")

        with self._lmdb_env.begin(write=True, db=self._lmdb_funcsdb) as txn:
            txn.delete(key)

    def _load_from_lmdb(self, addr: K, meta_only: bool = False) -> Function | None:
        """
        Load a function from LMDB and bring it back into memory.
        """
        if self._lmdb_env is None:
            return None

        # Prevent recursive loading
        if addr in self._currently_loading:
            return None

        self._currently_loading.add(addr)
        old_loading_state = self._loading_from_lmdb
        self._loading_from_lmdb = True

        try:
            key = str(addr).encode("utf-8")

            with self._lmdb_env.begin(db=self._lmdb_funcsdb) as txn:
                value = txn.get(key)
                if value is None:
                    return None

                # Deserialize protobuf
                from angr.protos import function_pb2

                cmsg = function_pb2.Function()
                cmsg.ParseFromString(value)

                # Reconstruct function
                func = Function.parse_from_cmessage(
                    cmsg,
                    function_manager=self._backref,
                    project=self._backref._kb._project,
                    meta_only=meta_only,
                )

            if meta_only:
                self._meta_func_cache[addr] = func
            else:
                # Remove from spilled set
                self._spilled_keys.discard(addr)
                # Add to in-memory map
                super().__setitem__(addr, func)
                self._on_function_stored(addr)

            l.debug("Loaded function %s from LMDB", hex(addr) if isinstance(addr, int) else addr)
            return func
        finally:
            self._currently_loading.discard(addr)
            self._loading_from_lmdb = old_loading_state

            # After loading is complete (and we're back to not loading), evict if needed
            if (
                not self._loading_from_lmdb
                and self._eviction_enabled
                and self._cache_limit is not None
                and self.cached_count > self._cache_limit + self._lmdb_batch_size
            ):
                self._evict_lru()

    def _load_all_spilled(self) -> None:
        """
        Load all spilled functions back into memory (disables eviction temporarily).
        """
        if not self._spilled_keys:
            return

        # Temporarily disable eviction
        old_eviction_state = self._eviction_enabled
        self._eviction_enabled = False

        try:
            # Make a copy of spilled_addrs since _load_from_lmdb modifies it
            addrs_to_load = list(self._spilled_keys)
            for addr in addrs_to_load:
                self._load_from_lmdb(addr)
        finally:
            self._eviction_enabled = old_eviction_state


class FunctionManager(Generic[K], KnowledgeBasePlugin, collections.abc.Mapping[K, Function]):
    """
    When cache_limit is set, the FunctionManager uses a SpillingFunctionDict
    that implements an LRU cache keeping only the most recently accessed N functions
    in memory, spilling others to an LMDB database on disk. This allows working with
    binaries that have more functions than can fit in memory.

    :param cache_limit: Maximum number of functions to keep in memory. None means unlimited (no eviction). Default is
                        None.
    """

    def __init__(self, kb: KnowledgeBase, cache_limit: int | None = DEFAULT_MAX_CACHED_FUNCTIONS):
        super().__init__(kb=kb)
        self.function_address_types = self._kb._project.arch.function_address_types
        self.address_types = self._kb._project.arch.address_types

        # Use SpillingFunctionDict when caching is enabled, otherwise plain FunctionDict
        if cache_limit is not None:
            self._function_map: FunctionDict[K] | SpillingFunctionDict[K] = SpillingFunctionDict(
                self, key_types=self.function_address_types, cache_limit=cache_limit
            )
        else:
            self._function_map = FunctionDict(self, key_types=self.function_address_types)

        self.function_addrs_set: set = set()
        self.callgraph = networkx.MultiDiGraph()

        # Registers used for passing arguments around
        self._arg_registers = kb._project.arch.argument_registers

        # local PLT dictionary cache
        self._rplt_cache_ranges: None | list[tuple[int, int]] = None
        self._rplt_cache: None | set[int] = None
        # local binary name cache: min_addr -> (max_addr, binary_name)
        self._binname_cache: None | SortedDict[int, tuple[int, str | None]] = None

    def __setstate__(self, state):
        self._kb = state["_kb"]
        self.function_address_types = state["function_address_types"]
        self.address_types = state["address_types"]
        self._function_map = state["_function_map"]
        self.callgraph = state["callgraph"]

        self._function_map._backref = weakref.proxy(self)
        for func in self._function_map.values():
            func._function_manager = self

        # Reinitialize cache state
        self._rplt_cache_ranges = None
        self._rplt_cache = None
        self._binname_cache = None

        # If the unpickled function_map is a SpillingFunctionDict, reinitialize its LRU state
        if isinstance(self._function_map, SpillingFunctionDict):
            self._function_map._lru_order = OrderedDict()
            for addr in SortedDict.keys(self._function_map):
                self._function_map._lru_order[addr] = None

    def __getstate__(self):
        # Before pickling, bring all spilled functions back to memory
        if isinstance(self._function_map, SpillingFunctionDict):
            self._function_map._load_all_spilled()
        return {
            "_kb": self._kb,
            "function_address_types": self.function_address_types,
            "address_types": self.address_types,
            "_function_map": self._function_map,
            "callgraph": self.callgraph,
        }

    def copy(self):
        cache_limit = None
        if isinstance(self._function_map, SpillingFunctionDict):
            cache_limit = self._function_map.cache_limit

        fm = FunctionManager(self._kb, cache_limit=cache_limit)
        for k, v in self._function_map.items():
            fm._function_map[k] = v
        fm._function_map._backref = weakref.proxy(fm)
        fm.callgraph = networkx.MultiDiGraph(self.callgraph)
        fm._arg_registers = self._arg_registers.copy()
        fm.function_addrs_set = self.function_addrs_set.copy()

        return fm

    def clear(self):
        if isinstance(self._function_map, SpillingFunctionDict):
            cache_limit = self._function_map.cache_limit
            self._function_map.clear()
            self._function_map = SpillingFunctionDict(
                self, key_types=self.function_address_types, cache_limit=cache_limit
            )
        else:
            self._function_map = FunctionDict(self, key_types=self.function_address_types)

        self.callgraph = networkx.MultiDiGraph()
        self.function_addrs_set = set()
        # cache
        self._rplt_cache = None
        self._rplt_cache_ranges = None
        self._binname_cache = None

    def _genenate_callmap_sif(self, filepath):
        """
        Generate a sif file from the call map.

        :param filepath:    Path of the sif file
        :return:            None
        """
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(f"{src:#x}\tDirectEdge\t{dst:#x}\n" for src, dst in self.callgraph.edges())

    def _addr_in_plt_cached_ranges(self, addr: int) -> bool:
        if self._rplt_cache_ranges is None:
            return False
        pos = bisect.bisect_left(self._rplt_cache_ranges, addr, key=lambda x: x[0])
        return pos > 0 and self._rplt_cache_ranges[pos - 1][0] <= addr < self._rplt_cache_ranges[pos - 1][1]

    def is_plt_cached(self, addr: int) -> bool:
        # check if the addr is in the cache range
        if not self._addr_in_plt_cached_ranges(addr):
            # find the object containing this addr
            obj = self._kb._project.loader.find_object_containing(addr, membership_check=False)
            if obj is None:
                return False
            if self._rplt_cache_ranges is None:
                self._rplt_cache_ranges = []
            obj_range = obj.min_addr, obj.max_addr
            idx = bisect.bisect_left(self._rplt_cache_ranges, obj_range)
            if not (idx < len(self._rplt_cache_ranges) and self._rplt_cache_ranges[idx] == obj_range):
                self._rplt_cache_ranges.insert(idx, obj_range)
            if isinstance(obj, (cle.MetaELF, cle.MachO)):
                if self._rplt_cache is None:
                    self._rplt_cache = set()
                self._rplt_cache |= set(obj.reverse_plt)

        return addr in self._rplt_cache if self._rplt_cache is not None else False

    def _binname_cache_get_addr_base(self, addr: int) -> int | None:
        if self._binname_cache is None:
            return None
        try:
            base_addr = next(self._binname_cache.irange(maximum=addr, reverse=True))
        except StopIteration:
            return None
        return base_addr if base_addr <= addr < self._binname_cache[base_addr][0] else None

    def get_binary_name_cached(self, addr: int) -> str | None:
        base_addr = self._binname_cache_get_addr_base(addr)
        if base_addr is None:
            # not cached; cache it first
            obj = self._kb._project.loader.find_object_containing(addr, membership_check=False)
            if obj is None:
                return None
            if self._binname_cache is None:
                self._binname_cache = SortedDict()
            binary_basename = os.path.basename(obj.binary) if obj.binary else None
            self._binname_cache[obj.min_addr] = obj.max_addr, binary_basename
            base_addr = obj.min_addr
        return self._binname_cache[base_addr][1] if self._binname_cache is not None else None

    def _add_node(self, function_addr, node, syscall=None, size=None):
        if isinstance(node, self.address_types):
            node = self._kb._project.factory.snippet(node, size=size)
        dst_func = self._function_map[function_addr]
        if syscall in (True, False):
            dst_func.is_syscall = syscall
        dst_func._register_node(True, node)

    def _add_call_to(
        self,
        function_addr,
        from_node,
        to_addr,
        retn_node=None,
        syscall=None,
        stmt_idx=None,
        ins_addr=None,
        return_to_outside: bool = False,
    ):
        """
        Add a call to a function.

        :param int function_addr:   Address of the current function where this call happens.
        :param from_node:           The source node.
        :param to_addr:             Address of the target function, or None if unknown.
        :param retn_node:           The node where the target function will return to if it returns.
        :param bool syscall:        If this is a call to a syscall or not.
        :param int stmt_idx:        ID of the statement where this call happens.
        :param int ins_addr:        Address of the instruction where this call happens.
        :param return_to_outside:  True if the return of the call is considered going to outside of the current
                                        function.
        :return:                    None
        """

        if isinstance(from_node, self.address_types):
            from_node = self._kb._project.factory.snippet(from_node)
        if isinstance(retn_node, self.address_types):
            retn_node = self._kb._project.factory.snippet(retn_node)
        func = self._function_map[function_addr]
        func._add_call_site(from_node.addr, to_addr, retn_node.addr if retn_node else None)

        if to_addr is not None:
            dest_func_node = FuncNode(to_addr)
            if syscall in (True, False):
                dest_func_node.is_syscall = syscall
            func._call_to(
                from_node,
                dest_func_node,
                retn_node,
                stmt_idx=stmt_idx,
                ins_addr=ins_addr,
                return_to_outside=return_to_outside,
            )

        if return_to_outside:
            func.add_retout_site(from_node)

        # is there any existing edge on the callgraph?
        edge_data = {"type": "call"}
        if to_addr is not None and (
            function_addr not in self.callgraph
            or to_addr not in self.callgraph[function_addr]
            or edge_data not in self.callgraph[function_addr][to_addr].values()
        ):
            self.callgraph.add_edge(function_addr, to_addr, **edge_data)

    def _add_fakeret_to(
        self, function_addr, from_node, to_node, confirmed=None, syscall=None, to_outside=False, to_function_addr=None
    ):
        if isinstance(from_node, self.address_types):
            from_node = self._kb._project.factory.snippet(from_node)
        if isinstance(to_node, self.address_types):
            to_node = self._kb._project.factory.snippet(to_node)
        src_func = self._function_map[function_addr]

        if syscall in (True, False):
            src_func.is_syscall = syscall

        src_func._fakeret_to(from_node, to_node, confirmed=confirmed, to_outside=to_outside)

        if to_outside and to_function_addr is not None:
            # mark it on the callgraph
            edge_data = {"type": "fakeret"}
            if (
                function_addr not in self.callgraph
                or to_function_addr not in self.callgraph[function_addr]
                or edge_data not in self.callgraph[function_addr][to_function_addr].values()
            ):
                self.callgraph.add_edge(function_addr, to_function_addr, **edge_data)

    def _remove_fakeret(self, function_addr, from_node, to_node):
        if type(from_node) is int:  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        if type(to_node) is int:  # pylint: disable=unidiomatic-typecheck
            to_node = self._kb._project.factory.snippet(to_node)
        self._function_map[function_addr]._remove_fakeret(from_node, to_node)

    def _add_return_from(self, function_addr, from_node, to_node=None):  # pylint:disable=unused-argument
        if isinstance(from_node, self.address_types):  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        self._function_map[function_addr]._add_return_site(from_node)

    def _add_transition_to(self, function_addr, from_node, to_node, ins_addr=None, stmt_idx=None, is_exception=False):
        if isinstance(from_node, self.address_types):  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        if isinstance(to_node, self.address_types):  # pylint: disable=unidiomatic-typecheck
            to_node = self._kb._project.factory.snippet(to_node)
        self._function_map[function_addr]._transit_to(
            from_node, to_node, ins_addr=ins_addr, stmt_idx=stmt_idx, is_exception=is_exception
        )

    def _add_outside_transition_to(
        self, function_addr, from_node, to_node, to_function_addr=None, ins_addr=None, stmt_idx=None, is_exception=False
    ):
        if type(from_node) is int:  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        if type(to_node) is int:  # pylint: disable=unidiomatic-typecheck
            try:
                to_node = self._kb._project.factory.snippet(to_node)
            except SimEngineError:
                # we cannot get the snippet, but we should at least tell the function that it's going to jump out here
                self._function_map[function_addr].add_jumpout_site(from_node)
                return
        self._function_map[function_addr]._transit_to(
            from_node,
            to_node,
            outside=True,
            ins_addr=ins_addr,
            stmt_idx=stmt_idx,
            is_exception=is_exception,
        )

        if to_function_addr is not None:
            # mark it on the callgraph
            edge_data = {"type": "transition" if not is_exception else "exception"}
            if (
                function_addr not in self.callgraph
                or to_function_addr not in self.callgraph[function_addr]
                or edge_data not in self.callgraph[function_addr][to_function_addr].values()
            ):
                self.callgraph.add_edge(function_addr, to_function_addr, **edge_data)

    def _add_return_from_call(self, function_addr, src_function_addr, to_node, to_outside=False):
        # Note that you will never return to a syscall

        if type(to_node) is int:  # pylint: disable=unidiomatic-typecheck
            to_node = self._kb._project.factory.snippet(to_node)
        func = self._function_map[function_addr]
        src_funcnode = FuncNode(src_function_addr)
        func._return_from_call(src_funcnode, to_node, to_outside=to_outside)

    #
    # Dict methods
    #

    def __contains__(self, item):
        if type(item) is int:
            # Delegate to _function_map (SpillingFunctionDict handles spilled addrs)
            return item in self._function_map

        try:
            _ = self[item]
            return True
        except (KeyError, TypeError):
            return False

    def __getitem__(self, k) -> Function:
        if isinstance(k, self.function_address_types):
            f = self.function(addr=k)
        elif type(k) is str:
            f = self.function(name=k) or self.function(name=k, check_previous_names=True)
        else:
            raise ValueError(f"FunctionManager.__getitem__ does not support keys of type {type(k)}")

        if f is None:
            raise KeyError(k)

        return f

    def __setitem__(self, k, v):
        if isinstance(k, self.function_address_types):
            self._function_map[k] = v
            self._function_added(v)
        else:
            raise ValueError("FunctionManager.__setitem__ keys must be an int")

    def __delitem__(self, k):
        if isinstance(k, self.function_address_types):
            # Delegate to _function_map (SpillingFunctionDict handles spilled addrs)
            if k in self._function_map:
                del self._function_map[k]
            if k in self.callgraph:
                self.callgraph.remove_node(k)
            self.function_addrs_set.discard(k)
        else:
            raise ValueError(
                f"FunctionManager.__delitem__ only accepts the following address types: "
                f"{self.function_address_types}"
            )

    def __len__(self):
        # Delegate to _function_map (SpillingFunctionDict includes spilled count)
        return len(self._function_map)

    def __iter__(self):
        # Delegate to _function_map (SpillingFunctionDict handles spilled addrs)
        yield from self._function_map

    def items(self, /, meta_only: bool = False):
        for addr in self._function_map:
            yield addr, self._function_map.get(addr, meta_only=meta_only)

    def values(self, /, meta_only: bool = False):
        for addr in self._function_map:
            yield self._function_map.get(addr, meta_only=meta_only)

    def get_by_addr(self, addr, meta_only: bool = False) -> Function:
        return self._function_map.get(addr, meta_only=meta_only)

    def get_by_name(self, name: str, check_previous_names: bool = False) -> Generator[Function]:
        # For SpillingFunctionDict, we need to iterate over all addresses
        # and load spilled functions as needed
        for addr in self._function_map:
            func = self._function_map.get(addr)
            if func.name == name or (check_previous_names and name in func.previous_names):
                yield func

    def _function_added(self, func: Function):
        """
        A callback method for adding a new function instance to the manager.

        :param func:   The Function instance being added.
        :return:       None
        """

        # Add the function address to the set of function addresses
        self.function_addrs_set.add(func.addr)

        # make sure all functions exist in the call graph
        self.callgraph.add_node(func.addr)

    def contains_addr(self, addr):
        """
        Decide if an address is handled by the function manager.

        Note: this function is non-conformant with python programming idioms, but its needed for performance reasons.

        :param int addr: Address of the function.
        """
        return addr in self._function_map

    def ceiling_addr(self, addr: K) -> K | None:
        """
        Return the function who has the least address that is greater than or equal to `addr`.

        :param int addr: The address to query.
        :return:         A Function instance, or None if there is no other function after `addr`.
        """

        try:
            return self._function_map.ceiling_addr(addr)
        except KeyError:
            return None

    def ceiling_func(self, addr) -> Function | None:
        """
        Return the function who has the least address that is greater than or equal to `addr`.

        :param int addr: The address to query.
        :return:         A Function instance, or None if there is no other function after `addr`.
        """

        try:
            next_addr = self._function_map.ceiling_addr(addr)
            return self._function_map.get(next_addr)

        except KeyError:
            return None

    def floor_addr(self, addr: K) -> K | None:
        """
        Return the function who has the greatest address that is less than or equal to `addr`.

        :param int addr: The address to query.
        :return:         An address, or None if there is no other function before `addr`.
        """

        try:
            return self._function_map.floor_addr(addr)
        except KeyError:
            return None

    def floor_func(self, addr):
        """
        Return the function who has the greatest address that is less than or equal to `addr`.

        :param int addr: The address to query.
        :return:         A Function instance, or None if there is no other function before `addr`.
        :rtype:          Function or None
        """

        try:
            prev_addr = self._function_map.floor_addr(addr)
            return self._function_map.get(prev_addr)

        except KeyError:
            return None

    def query(self, query: str, check_previous_names: bool = False) -> Function | None:
        """
        Query for a function using selectors to disambiguate. Supported variations:

            ::<name>           Function <name> in the main object
            ::<addr>::<name>   Function <name> at <addr>
            ::<obj>::<name>    Function <name> in <obj>

        """
        # FIXME: Proper mangle handling
        matches = QUERY_PATTERN.match(query)
        if matches:
            selector = matches.group(2)
            name = matches.group(3)

            if selector is not None and ADDR_PATTERN.fullmatch(selector):
                addr = cast(K, int(matches.group(2), 0))
                try:
                    func = self._function_map.get(addr)
                    if func.name == name or (check_previous_names and name in func.previous_names):
                        return func
                except KeyError:
                    pass

            obj_name = selector or self._kb._project.loader.main_object.binary_basename
            for func in self.get_by_name(name, check_previous_names=check_previous_names):
                if func.binary_name == obj_name:
                    return func

        return None

    def function(
        self, addr=None, name=None, check_previous_names=False, create=False, syscall=False, plt=None
    ) -> Function | None:
        """
        Get a function object from the function manager.

        Pass either `addr` or `name` with the appropriate values.

        :param int addr: Address of the function.
        :param str name: Name of the function.
        :param bool create: Whether to create the function or not if the function does not exist.
        :param bool syscall: True to create the function as a syscall, False otherwise.
        :param bool or None plt: True to find the PLT stub, False to find a non-PLT stub, None to disable this
                                 restriction.
        :return: The Function instance, or None if the function is not found and create is False.
        :rtype: Function or None
        """
        if name is not None and name.startswith("sub_"):
            # first check if a function with the specified name exists
            for func in self.get_by_name(name, check_previous_names=check_previous_names):
                if plt is None or func.is_plt == plt:
                    return func

            # then enter the syntactic sugar mode
            try:
                addr = cast(K, int(name.split("_")[-1], 16))
                name = None
            except ValueError:
                pass

        if addr is not None:
            try:
                f = self._function_map.get(addr)
                if plt is None or f.is_plt == plt:
                    return f
            except KeyError:
                if create:
                    # the function is not found
                    f = self._function_map[addr]
                    if name is not None:
                        f.name = name
                    if syscall:
                        f.is_syscall = True
                    return f
        elif name is not None:
            func = self.query(name, check_previous_names=check_previous_names)
            if func is not None:
                return func

            for func in self.get_by_name(name, check_previous_names=check_previous_names):
                if plt is None or func.is_plt == plt:
                    return func

        return None

    def dbg_draw(self, prefix="dbg_function_"):
        for func_addr, func in self._function_map.items():
            filename = f"{prefix}{func_addr:#08x}.png"
            func.dbg_draw(filename)

    def rebuild_callgraph(self):
        self.callgraph = networkx.MultiDiGraph()
        cfg = self._kb.cfgs.get_most_accurate()
        for func_addr in self._function_map:
            self.callgraph.add_node(func_addr)
        for func in self._function_map.values():
            if func.block_addrs_set:
                for node in func.transition_graph.nodes():
                    if isinstance(node, Function):
                        self.callgraph.add_edge(func.addr, node.addr)
                    else:
                        cfgnode = cfg.get_any_node(node.addr)
                        if (
                            cfgnode is not None
                            and cfgnode.function_address is not None
                            and cfgnode.function_address != func.addr
                        ):
                            self.callgraph.add_edge(func.addr, cfgnode.function_address)

    #
    # LRU Cache Management (delegates to SpillingFunctionDict when available)
    #

    @property
    def cache_limit(self) -> int | None:
        """
        Get the maximum number of functions to keep in memory. None means unlimited (no eviction).
        """
        if isinstance(self._function_map, SpillingFunctionDict):
            return self._function_map.cache_limit
        return None

    @cache_limit.setter
    def cache_limit(self, value: int | None) -> None:
        """
        Set the maximum number of functions to keep in memory.
        If the new limit is lower than the current number of cached functions, excess functions will be evicted to
        storage.
        """
        if isinstance(self._function_map, SpillingFunctionDict):
            self._function_map.cache_limit = value
        elif value is not None:
            # Need to convert FunctionDict to SpillingFunctionDict
            old_map = self._function_map
            new_map = SpillingFunctionDict(self, key_types=self.function_address_types, cache_limit=value)
            # Disable eviction during bulk copy
            new_map._eviction_enabled = False
            # Copy existing functions
            for addr, func in old_map.items():
                SortedDict.__setitem__(new_map, addr, func)
                new_map._lru_order[addr] = None
            # Re-enable eviction
            new_map._eviction_enabled = True
            self._function_map = new_map
            # Now trigger eviction if needed
            self._function_map._evict_lru()

    @property
    def cached_function_count(self) -> int:
        """
        Return the number of functions currently in memory.
        """
        if isinstance(self._function_map, SpillingFunctionDict):
            return self._function_map.cached_count
        return len(self._function_map)

    @property
    def spilled_function_count(self) -> int:
        """
        Return the number of functions currently spilled to LMDB.
        """
        if isinstance(self._function_map, SpillingFunctionDict):
            return self._function_map.spilled_count
        return 0

    @property
    def total_function_count(self) -> int:
        """
        Return the total number of functions (in memory + spilled).
        """
        if isinstance(self._function_map, SpillingFunctionDict):
            return self._function_map.total_count
        return len(self._function_map)

    @property
    def _spilled_addrs(self) -> set:
        """
        Proxy for backward compatibility - access spilled addresses from SpillingFunctionDict.
        """
        if isinstance(self._function_map, SpillingFunctionDict):
            return self._function_map._spilled_keys
        return set()


KnowledgeBasePlugin.register_default("functions", FunctionManager)
