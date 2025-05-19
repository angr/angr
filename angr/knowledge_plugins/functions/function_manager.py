# pylint:disable=raise-missing-from
from __future__ import annotations

import contextlib
from collections.abc import Generator
import logging
import collections.abc
import re
import weakref
import bisect
import os
from sortedcontainers import SortedDict

import networkx

from archinfo.arch_soot import SootMethodDescriptor
import cle

from angr.errors import SimEngineError
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from .function import Function
from .soot_function import SootFunction


QUERY_PATTERN = re.compile(r"^(::(.+?))?::(.+)$")
ADDR_PATTERN = re.compile(r"^(0x[\dA-Fa-f]+)|(\d+)$")

l = logging.getLogger(name=__name__)


class FunctionDict(SortedDict):
    """
    FunctionDict is a dict where the keys are function starting addresses and
    map to the associated :class:`Function`.
    """

    def __init__(self, backref, *args, **kwargs):
        self._backref = weakref.proxy(backref) if backref is not None else None
        self._key_types = kwargs.pop("key_types", int)
        super().__init__(*args, **kwargs)

    def __getitem__(self, addr):
        try:
            return super().__getitem__(addr)
        except KeyError as ex:
            if isinstance(addr, bool) or not isinstance(addr, self._key_types):
                raise TypeError(f"FunctionDict only supports {self._key_types} as key type") from ex

            if isinstance(addr, SootMethodDescriptor):
                t = SootFunction(self._backref, addr)
            else:
                t = Function(self._backref, addr)
            with contextlib.suppress(Exception):
                self[addr] = t
            if self._backref is not None:
                self._backref._function_added(t)
            return t

    def get(self, addr):
        return super().__getitem__(addr)

    def floor_addr(self, addr):
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


class FunctionManager(KnowledgeBasePlugin, collections.abc.Mapping):
    """
    This is a function boundaries management tool. It takes in intermediate
    results during CFG generation, and manages a function map of the binary.
    """

    def __init__(self, kb):
        super().__init__(kb=kb)
        self.function_address_types = self._kb._project.arch.function_address_types
        self.address_types = self._kb._project.arch.address_types
        self._function_map: FunctionDict[int, Function] = FunctionDict(self, key_types=self.function_address_types)
        self.function_addrs_set: set = set()
        self.callgraph = networkx.MultiDiGraph()
        self.block_map = {}

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
        self.block_map = state["block_map"]

        self._function_map._backref = weakref.proxy(self)
        for func in self._function_map.values():
            func._function_manager = self

    def __getstate__(self):
        return {
            "_kb": self._kb,
            "function_address_types": self.function_address_types,
            "address_types": self.address_types,
            "_function_map": self._function_map,
            "callgraph": self.callgraph,
            "block_map": self.block_map,
        }

    def copy(self):
        fm = FunctionManager(self._kb)
        fm._function_map = self._function_map.copy()
        for address, function in fm._function_map.items():
            fm._function_map[address] = function.copy()
        fm.callgraph = networkx.MultiDiGraph(self.callgraph)
        fm._arg_registers = self._arg_registers.copy()
        fm.function_addrs_set = self.function_addrs_set.copy()

        return fm

    def clear(self):
        self._function_map = FunctionDict(self, key_types=self.function_address_types)
        self.callgraph = networkx.MultiDiGraph()
        self.block_map.clear()
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
            for src, dst in self.callgraph.edges():
                f.write(f"{src:#x}\tDirectEdge\t{dst:#x}\n")

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
            if isinstance(obj, cle.MetaELF):
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
        self.block_map[node.addr] = node

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
            dest_func = self._function_map[to_addr]
            if syscall in (True, False):
                dest_func.is_syscall = syscall
            func._call_to(
                from_node,
                dest_func,
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
        src_func = self._function_map[src_function_addr]
        func._return_from_call(src_func, to_node, to_outside=to_outside)

    #
    # Dict methods
    #

    def __contains__(self, item):
        if type(item) is int:
            # this is an address
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
        return len(self._function_map)

    def __iter__(self):
        yield from sorted(self._function_map.keys())

    def get_by_addr(self, addr) -> Function:
        return self._function_map.get(addr)

    def get_by_name(self, name: str, check_previous_names: bool = False) -> Generator[Function]:
        for f in self._function_map.values():
            if f.name == name or (check_previous_names and name in f.previous_names):
                yield f

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

    def ceiling_func(self, addr):
        """
        Return the function who has the least address that is greater than or equal to `addr`.

        :param int addr: The address to query.
        :return:         A Function instance, or None if there is no other function after `addr`.
        :rtype:          Function or None
        """

        try:
            next_addr = self._function_map.ceiling_addr(addr)
            return self._function_map.get(next_addr)

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
                addr = int(matches.group(2), 0)
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
                addr = int(name.split("_")[-1], 16)
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


KnowledgeBasePlugin.register_default("functions", FunctionManager)
