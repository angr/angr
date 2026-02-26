# pylint:disable=no-member
from __future__ import annotations

import logging
from typing import Generic, TypeVar, TYPE_CHECKING

from collections.abc import Iterator, Callable
import string

import networkx

import cle
from archinfo.arch_soot import SootMethodDescriptor

from angr.engines.vex.lifter import VEX_IRSB_MAX_SIZE
from angr.protos import cfg_pb2, primitives_pb2
from angr.serializable import Serializable
from angr.utils.enums_conv import cfg_jumpkind_to_pb, cfg_jumpkind_from_pb
from angr.errors import AngrCFGError
from .cfg_node import CFGNode
from .memory_data import MemoryData, MemoryDataSort
from .indirect_jump import IndirectJump
from .spilling_cfg import SpillingCFG, get_block_key

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.xrefs import XRefManager, XRef
    from angr.knowledge_plugins.functions import Function
    from angr.rustylib import SegmentList
    from .types import CFG_ADDR_TYPES

    K = TypeVar("K", int, SootMethodDescriptor)

    class SortedList(Generic[K], list[K]):  # pylint:disable=missing-class-docstring
        def irange(self, *args, **kwargs) -> Iterator[K]: ...  # pylint:disable=unused-argument,no-self-use
        def add(self, value: K) -> None: ...  # pylint:disable=unused-argument,no-self-use
        def bisect_left(self, value: K) -> int: ...  # pylint:disable=unused-argument,no-self-use

else:
    from sortedcontainers import SortedList


l = logging.getLogger(name=__name__)

_PRINTABLES = string.printable.replace("\x0b", "").replace("\x0c", "").encode()


class CFGModel(Serializable):
    """
    This class describes a Control Flow Graph for a specific range of code.
    """

    __slots__ = (
        "__weakref__",
        "_addr_type",
        "_blockid_to_blockkey",
        "_cache_limit",
        "_cfg_manager",
        "_db_batch_size",
        "_edge_cache_limit",
        "_edge_db_batch_size",
        "_iropt_level",
        "_node_addrs",
        "edges_to_repair",
        "graph",
        "ident",
        "insn_addr_to_memory_data",
        "is_arm",
        "jump_tables",
        "memory_data",
        "normalized",
    )

    def __init__(
        self,
        ident,
        cfg_manager=None,
        is_arm=False,
        cache_limit: int | None = None,
        db_batch_size: int = 800,
        edge_cache_limit: int | None = None,
        edge_db_batch_size: int = 800,
        addr_type: CFG_ADDR_TYPES = "int",
    ):
        self.ident = ident
        self._cfg_manager = cfg_manager
        self.is_arm = is_arm
        self._cache_limit = cache_limit
        self._db_batch_size = db_batch_size
        self._edge_cache_limit = edge_cache_limit
        self._edge_db_batch_size = edge_db_batch_size
        self.graph = None  # type:ignore
        self.addr_type = addr_type

        # Necessary settings
        self._iropt_level = None

        # The graph - uses SpillingCFGGraph which stores nodes internally
        # When cache_limit is None, spilling is disabled (regular dict for nodes)
        rtdb = None
        if cfg_manager is not None and hasattr(cfg_manager, "_kb") and cfg_manager._kb is not None:
            rtdb = cfg_manager._kb.rtdb

        self.graph: SpillingCFG = SpillingCFG(
            rtdb=rtdb,
            cfg_model=self,
            cache_limit=cache_limit,
            db_batch_size=db_batch_size,
            edge_cache_limit=edge_cache_limit,
            edge_db_batch_size=edge_db_batch_size,
            addr_type=self.addr_type,
        )

        # Jump tables
        self.jump_tables: dict[int, IndirectJump] = {}

        # Memory references
        # A mapping between address and the actual data in memory
        self.memory_data: dict[int, MemoryData] = {}
        # A mapping between address of the instruction that's referencing the memory data and the memory data itself
        self.insn_addr_to_memory_data: dict[int, MemoryData] = {}

        # addresses of CFGNodes to speed up get_any_node(..., anyaddr=True). Don't serialize
        self._node_addrs: SortedList[int] | None = None
        # block ID to block key mapping for compatibility reasons
        self._blockid_to_blockkey: dict = {}

        self.normalized = False

        self.edges_to_repair = []

    #
    # Properties
    #

    @property
    def addr_type(self) -> CFG_ADDR_TYPES:
        return self._addr_type

    @addr_type.setter
    def addr_type(self, value: CFG_ADDR_TYPES) -> None:
        if value not in ("int", "block_id", "soot"):
            raise TypeError(f"Unsupported address type {value}. Supported types are 'int', 'block_id', and 'soot'.")
        self._addr_type = value
        if self.graph is not None:
            self.graph.addr_type = value

    @property
    def project(self):
        if self._cfg_manager is None:
            return None
        return self._cfg_manager._kb._project

    @property
    def _nodes(self):
        """CFGNodes dict indexed by block ID. Delegates to graph._nodes."""
        return self.graph._nodes

    @property
    def node_addrs(self) -> SortedList[int]:
        if self._node_addrs is None:
            self._build_node_addr_index()
            assert self._node_addrs is not None
        return self._node_addrs

    def nodes_by_addr(self, addr: int) -> Iterator[CFGNode]:
        yield from self.graph.nodes_by_addr(addr)

    def has_node_addr(self, addr: int) -> bool:
        return self.graph.has_node_addr(addr)

    #
    # Serialization
    #

    def __getstate__(self):
        return {x: self.__getattribute__(x) for x in self.__slots__ if x not in {"__weakref__", "_cfg_manager"}}

    def __setstate__(self, state):
        for attribute, value in state.items():
            self.__setattr__(attribute, value)

        # Restore cfg_model reference in the graph
        self.graph._cfg_model = self

        # Restore cfg_model reference in all nodes
        for addr in self._nodes:
            node = self._nodes[addr]
            node._cfg_model = self

        self._cfg_manager = None

    @classmethod
    def _get_cmsg(cls):
        return cfg_pb2.CFG()  # type:ignore

    def serialize_to_cmessage(self):
        if "Emulated" in self.ident:
            raise NotImplementedError("Serializing a CFGEmulated instance is currently not supported.")

        cmsg = self._get_cmsg()
        cmsg.ident = self.ident

        # nodes
        nodes = []
        for n in self.graph.nodes():
            nodes.append(n.serialize_to_cmessage())
        cmsg.nodes.extend(nodes)

        # edges
        edges = []
        for src, dst, data in self.graph.edges(data=True):
            edge = primitives_pb2.Edge()  # type:ignore
            edge.src_ea = src.addr
            edge.dst_ea = dst.addr
            for k, v in data.items():
                if k == "jumpkind":
                    jk = cfg_jumpkind_to_pb(v)
                    edge.jumpkind = primitives_pb2.Edge.UnknownJumpkind if jk is None else jk  # type:ignore
                elif k == "ins_addr":
                    edge.ins_addr = v if v is not None else 0xFFFF_FFFF_FFFF_FFFF
                elif k == "stmt_idx":
                    edge.stmt_idx = v if v is not None else -1
                else:
                    l.warning('Unexpected edge data type "%s" found during CFG serialization.', k)
            edges.append(edge)
        cmsg.edges.extend(edges)

        # memory data
        memory_data = []
        for data in self.memory_data.values():
            memory_data.append(data.serialize_to_cmessage())
        cmsg.memory_data.extend(memory_data)

        # jump tables
        for ij in self.jump_tables.values():
            cmsg.jump_tables.append(ij.serialize_to_cmessage())

        cmsg.normalized = self.normalized

        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, cfg_manager=None, loader=None):  # pylint:disable=arguments-differ
        # create a new model unassociated from any project
        model = cls(cmsg.ident) if cfg_manager is None else cfg_manager.new_model(cmsg.ident)

        # nodes
        for node_pb2 in cmsg.nodes:
            node = CFGNode.parse_from_cmessage(node_pb2, cfg=model)
            node.dirty = True  # mark dirty so the node is saved to LMDB if evicted from the spilling cache
            model.graph.add_node(node)

        model._node_addrs = None

        # edges
        for edge_pb2 in cmsg.edges:
            # more than one node at a given address is unsupported, grab the first one
            src = next(model.graph.nodes_by_addr(edge_pb2.src_ea))
            dst = next(model.graph.nodes_by_addr(edge_pb2.dst_ea))
            data = {
                "jumpkind": cfg_jumpkind_from_pb(edge_pb2.jumpkind),
                "ins_addr": edge_pb2.ins_addr if edge_pb2.ins_addr != 0xFFFF_FFFF_FFFF_FFFF else None,
                "stmt_idx": edge_pb2.stmt_idx if edge_pb2.stmt_idx != -1 else None,
            }
            model.graph.add_edge(src, dst, **data)

        # memory data
        for data_pb2 in cmsg.memory_data:
            md = MemoryData.parse_from_cmessage(data_pb2)
            if loader is not None and md.content is None:
                # fill in the content
                md.fill_content(loader)
            model.memory_data[md.addr] = md

        # jump tables
        for ij_pb2 in cmsg.jump_tables:
            ij = IndirectJump.parse_from_cmessage(ij_pb2)
            model.jump_tables[ij.addr] = ij

        model.normalized = cmsg.normalized

        return model

    #
    # Other methods
    #

    def copy(self):
        model = CFGModel(
            self.ident,
            cfg_manager=self._cfg_manager,
            is_arm=self.is_arm,
            cache_limit=self._cache_limit,
            db_batch_size=self._db_batch_size,
            edge_cache_limit=self._edge_cache_limit,
            edge_db_batch_size=self._edge_db_batch_size,
        )
        model.graph = self.graph.copy()
        model.graph._cfg_model = model
        model.jump_tables = self.jump_tables.copy()
        model.memory_data = self.memory_data.copy()
        model.insn_addr_to_memory_data = self.insn_addr_to_memory_data.copy()
        model.edges_to_repair = self.edges_to_repair.copy()

        return model

    def _build_node_addr_index(self):
        self._node_addrs = SortedList(iter(k for k, lst in self.graph._keys_by_addr.items() if lst))

    #
    # Node insertion and removal
    #

    def add_node(self, block_id: int, node: CFGNode) -> None:
        self._blockid_to_blockkey[block_id] = get_block_key(node)
        self.graph.add_node(node)
        if self._node_addrs is not None and isinstance(node.addr, int) and node.addr not in self._node_addrs:
            self._node_addrs.add(node.addr)

    def remove_node(self, block_id: int, node: CFGNode) -> None:
        """
        Remove the given CFGNode instance. Note that this method *does not* remove the node from the graph.

        :param block_id:    The Unique ID of the CFGNode.
        :param node:        The CFGNode instance to remove.
        :return:            None
        """
        self._blockid_to_blockkey.pop(block_id, None)
        self.graph.remove_node(node)
        # Only remove from _node_addrs if no other nodes exist at this address
        if (
            self._node_addrs is not None
            and isinstance(node.addr, int)
            and node.addr in self._node_addrs
            and not self.graph.has_node_addr(node.addr)
        ):
            self._node_addrs.remove(node.addr)

    #
    # CFG View
    #

    def has_node_id(self, node_id) -> bool:
        return node_id in self._blockid_to_blockkey

    def get_node(self, block_id) -> CFGNode | None:
        """
        Get a single node from Block ID.

        :param BlockID block_id: Block ID of the node.
        :return:                 The CFGNode, or None if the node does not exist.
        """
        if block_id in self._blockid_to_blockkey:
            block_key = self._blockid_to_blockkey[block_id]
            return self.graph.get_node_by_key(block_key)
        return None

    def get_any_node(
        self, addr: int, is_syscall: bool | None = None, anyaddr: bool = False, force_fastpath: bool = False
    ) -> CFGNode | None:
        """
        Get an arbitrary CFGNode (without considering their contexts) from our graph.

        :param addr:            Address of the beginning of the basic block. Set anyaddr to True to support arbitrary
                                address.
        :param is_syscall:      Whether you want to get the syscall node or any other node. This is due to the fact that
                                syscall SimProcedures have the same address as the target it returns to.
                                None means get either, True means get a syscall node, False means get something that
                                isn't a syscall node.
        :param anyaddr:         If anyaddr is True, then addr doesn't have to be the beginning address of a basic
                                block. By default the entire graph.nodes() will be iterated, and the first node
                                containing the specific address is returned, which can be slow.
        :param force_fastpath:  If force_fastpath is True, it will only perform a dict lookup in the
                                graph._keys_by_addr dict.
        :return:                A CFGNode if there is any that satisfies given conditions, or None otherwise
        """

        # fastpath: directly look in the nodes list
        if not anyaddr or self.graph.has_node_addr(addr):
            try:
                if is_syscall is None:
                    return next(self.graph.nodes_by_addr(addr))
                return next(iter(node for node in self.graph.nodes_by_addr(addr) if node.is_syscall == is_syscall))
            except (KeyError, IndexError, StopIteration):
                pass

        if force_fastpath:
            return None

        if isinstance(addr, int):
            if self._node_addrs is None:
                self._build_node_addr_index()
                assert self._node_addrs is not None

            # slower path
            # find all potential addresses that the block may cover
            pos = self._node_addrs.bisect_left(max(addr - VEX_IRSB_MAX_SIZE, 0))

            is_cfgemulated = self.ident == "CFGEmulated"

            while pos < len(self._node_addrs):
                node_addr = self._node_addrs[pos]
                actual_addr = node_addr if not self.is_arm else node_addr & 0xFFFF_FFFE
                if actual_addr > addr:
                    break

                n = next(self.graph.nodes_by_addr(node_addr))
                cond = n.looping_times == 0 if is_cfgemulated else True
                if anyaddr and n.size is not None:
                    cond = cond and (addr == actual_addr or actual_addr <= addr < actual_addr + n.size)
                else:
                    cond = cond and (addr == actual_addr)
                if cond:
                    if is_syscall is None:
                        return n
                    if n.is_syscall == is_syscall:
                        return n

                pos += 1

        return None

    def get_all_nodes(self, addr: int, is_syscall: bool | None = None, anyaddr: bool = False) -> list[CFGNode]:
        """
        Get all CFGNodes whose address is the specified one.

        :param addr:       Address of the node
        :param is_syscall: True returns the syscall node, False returns the normal CFGNode, None returns both
        :return:           all CFGNodes
        """
        results = []

        for cfg_node in self.graph.nodes():
            if (
                cfg_node.addr == addr
                or (anyaddr and cfg_node.size is not None and cfg_node.addr <= addr < (cfg_node.addr + cfg_node.size))
            ) and (is_syscall is None or is_syscall == cfg_node.is_syscall):
                results.append(cfg_node)

        return results

    def get_all_nodes_intersecting_region(self, addr: int, size: int = 1) -> set[CFGNode]:
        """
        Get all CFGNodes that intersect the given region.

        :param addr: Minimum address of target region.
        :param size: Size of region, in bytes.
        """
        end_addr = addr + size
        return {n for n in self.nodes() if not (addr >= (n.addr + n.size) or n.addr >= end_addr)}

    def nodes(self):
        """
        An iterator of all nodes in the graph.

        :return: The iterator.
        :rtype: iterator
        """

        return self.graph.nodes()

    def get_predecessors(
        self, cfgnode: CFGNode, excluding_fakeret: bool = True, jumpkind: str | None = None
    ) -> list[CFGNode]:
        """
        Get predecessors of a node in the control flow graph.

        :param cfgnode:             The node.
        :param excluding_fakeret:   True if you want to exclude all predecessors that is connected to the node with a
                                    fakeret edge.
        :param jumpkind:            Only return predecessors with the specified jumpkind. This argument will be ignored
                                    if set to None.
        :return:                    A list of predecessors
        """

        if excluding_fakeret and jumpkind == "Ijk_FakeRet":
            return []

        if not excluding_fakeret and jumpkind is None:
            # fast path
            if cfgnode in self.graph:
                return list(self.graph.predecessors(cfgnode))
            return []

        predecessors = []
        for pred, _, data in self.graph.in_edges([cfgnode], data=True):
            jk = data["jumpkind"]
            if jumpkind is not None:
                if jk == jumpkind:
                    predecessors.append(pred)
            elif excluding_fakeret:
                if jk != "Ijk_FakeRet":
                    predecessors.append(pred)
            else:
                predecessors.append(pred)
        return predecessors

    def get_successors(
        self, node: CFGNode, excluding_fakeret: bool = True, jumpkind: str | None = None
    ) -> list[CFGNode]:
        """
        Get successors of a node in the control flow graph.

        :param CFGNode node:                The node.
        :param bool excluding_fakeret:      True if you want to exclude all successors that is connected to the node
                                            with a fakeret edge.
        :param str or None jumpkind:        Only return successors with the specified jumpkind. This argument will be
                                            ignored if set to None.
        :return:                            A list of successors
        :rtype:                             list
        """

        if jumpkind is not None and excluding_fakeret and jumpkind == "Ijk_FakeRet":
            return []

        if not excluding_fakeret and jumpkind is None:
            # fast path
            if node in self.graph:
                return list(self.graph.successors(node))
            return []

        successors = []
        for _, suc, data in self.graph.out_edges([node], data=True):
            jk = data["jumpkind"]
            if jumpkind is not None:
                if jumpkind == jk:
                    successors.append(suc)
            elif excluding_fakeret:
                if jk != "Ijk_FakeRet":
                    successors.append(suc)
            else:
                successors.append(suc)
        return successors

    def get_successors_and_jumpkinds(self, node, excluding_fakeret=True) -> list[tuple[CFGNode, str]]:
        """
        Get a list of tuples where the first element is the successor of the CFG node and the second element is the
        jumpkind of the successor.

        :param CFGNode node:            The node.
        :param bool excluding_fakeret:  True if you want to exclude all successors that are fall-through successors.
        :return:                        A list of successors and their corresponding jumpkinds.
        :rtype:                         list
        """

        successors = []
        for _, suc, data in self.graph.out_edges([node], data=True):
            if not excluding_fakeret or data["jumpkind"] != "Ijk_FakeRet":
                successors.append((suc, data["jumpkind"]))
        return successors

    get_successors_and_jumpkind = get_successors_and_jumpkinds

    def get_predecessors_and_jumpkinds(
        self, node: CFGNode, excluding_fakeret: bool = True
    ) -> list[tuple[CFGNode, str]]:
        """
        Get a list of tuples where the first element is the predecessor of the CFG node and the second element is the
        jumpkind of the predecessor.

        :param node:                The node.
        :param excluding_fakeret:   True if you want to exclude all predecessors that are fall-through predecessors.
        :return:                    A list of predecessors and their corresponding jumpkinds.
        """

        predecessors = []
        for pred, _, data in self.graph.in_edges([node], data=True):
            if not excluding_fakeret or data["jumpkind"] != "Ijk_FakeRet":
                predecessors.append((pred, data["jumpkind"]))
        return predecessors

    get_predecessors_and_jumpkind = get_predecessors_and_jumpkinds

    def get_all_predecessors(self, cfgnode, depth_limit=None):
        """
        Get all predecessors of a specific node on the control flow graph.

        :param CFGNode cfgnode: The CFGNode object
        :param int depth_limit: Optional depth limit for the depth-first search
        :return: A list of predecessors in the CFG
        :rtype: list
        """
        # use the reverse graph and query for successors (networkx.dfs_predecessors is misleading)
        # dfs_successors returns a dict of (node, [predecessors]). We ignore the keyset and use the values
        predecessors = set().union(
            *networkx.dfs_successors(self.graph.to_networkx().reverse(), cfgnode, depth_limit).values()
        )
        return list(predecessors)

    def get_all_successors(self, cfgnode, depth_limit=None):
        """
        Get all successors of a specific node on the control flow graph.

        :param CFGNode cfgnode: The CFGNode object
        :param int depth_limit: Optional depth limit for the depth-first search
        :return: A list of successors in the CFG
        :rtype: list
        """
        # dfs_successors returns a dict of (node, [predecessors]). We ignore the keyset and use the values
        successors = set().union(*networkx.dfs_successors(self.graph.to_networkx(), cfgnode, depth_limit).values())
        return list(successors)

    def get_branching_nodes(self):
        """
        Returns all nodes that has an out degree >= 2
        """
        nodes = set()
        for n in self.graph.nodes():
            if self.graph.out_degree(n) >= 2:
                nodes.add(n)
        return nodes

    def get_exit_stmt_idx(self, src_block, dst_block):
        """
        Get the corresponding exit statement ID for control flow to reach destination block from source block. The exit
        statement ID was put on the edge when creating the CFG.
        Note that there must be a direct edge between the two blocks, otherwise an exception will be raised.

        :return: The exit statement ID
        """

        if not self.graph.has_edge(src_block, dst_block):
            raise AngrCFGError(f"Edge ({src_block}, {dst_block}) does not exist in CFG")

        return self.graph[src_block][dst_block]["stmt_idx"]

    #
    # Memory data
    #

    def add_memory_data(self, data_addr: int, data_type: MemoryDataSort | None, data_size: int | None = None) -> bool:
        """
        Add a MemoryData entry to self.memory_data.

        :param data_addr:   Address of the data
        :param data_type:   Type of the memory data
        :param data_size:   Size of the memory data, or None if unknown for now.
        :return:            True if a new memory data entry is added, False otherwise.
        """

        if data_addr not in self.memory_data:
            if data_type is not None and data_size is not None:
                data = MemoryData(data_addr, data_size, data_type, max_size=data_size)
            else:
                data = MemoryData(data_addr, 0, MemoryDataSort.Unknown)
            self.memory_data[data_addr] = data
            return True
        return False

    def tidy_data_references(
        self,
        memory_data_addrs: list[int] | None = None,
        exec_mem_regions: list[tuple[int, int]] | None = None,
        xrefs: XRefManager | None = None,
        seg_list: SegmentList | None = None,
        data_type_guessing_handlers: list[Callable] | None = None,
    ) -> bool:
        """
        Go through all data references (or the ones as specified by memory_data_addrs) and determine their sizes and
        types if possible.

        :param memory_data_addrs:   A list of addresses of memory data, or None if tidying all known memory data
                                    entries.
        :param exec_mem_regions:    A list of start and end addresses of executable memory regions.
        :param seg_list:            The segment list that CFGFast uses during CFG recovery.
        :param data_type_guessing_handlers: A list of Python functions that will guess data types. They will be called
                                    in sequence to determine data types for memory data whose type is unknown.
        :return:                    True if new data entries are found, False otherwise.
        """

        assert self.project is not None and self.project.loader is not None

        # Make sure all memory data entries cover all data sections
        keys = sorted(memory_data_addrs) if memory_data_addrs is not None else sorted(self.memory_data.keys())

        for i, data_addr in enumerate(keys):
            data = self.memory_data[data_addr]
            if exec_mem_regions and self._addr_in_exec_memory_regions(data.address, exec_mem_regions):
                # TODO: Handle data in code regions (or executable regions)
                pass
            else:
                next_data_addr = keys[i + 1] if i + 1 != len(keys) else None

                # goes until the end of the section/segment
                # TODO: the logic needs more testing

                sec = self.project.loader.find_section_containing(data_addr)
                if sec is None:
                    sec = self.project.loader.find_section_containing(data_addr - 1)
                next_sec_addr = None
                if sec is not None:
                    last_addr = sec.vaddr + sec.memsize
                else:
                    # it does not belong to any section. what's the next adjacent section? any memory data does not go
                    # beyond section boundaries
                    next_sec = self.project.loader.find_section_next_to(data_addr)
                    if next_sec is not None:
                        next_sec_addr = next_sec.vaddr

                    seg = self.project.loader.find_segment_containing(data_addr)
                    if seg is None:
                        seg = self.project.loader.find_segment_containing(data_addr - 1)
                    if seg is not None:
                        last_addr = seg.vaddr + seg.memsize
                    else:
                        # We got an address that is not inside the current binary...
                        l.warning(
                            "tidy_data_references() sees an address %#08x that does not belong to any "
                            "section or segment.",
                            data_addr,
                        )
                        last_addr = None

                if next_data_addr is None:
                    boundary = last_addr
                elif last_addr is None:
                    boundary = next_data_addr
                else:
                    boundary = min(last_addr, next_data_addr)

                if next_sec_addr is not None:
                    boundary = min(boundary, next_sec_addr)

                if boundary is not None:
                    data.max_size = boundary - data_addr
                else:
                    # boundary does not exist, which means the data address is not mapped at all
                    data.max_size = 0

        keys = sorted(self.memory_data.keys())

        new_data_found = False

        i = 0
        # pylint:disable=too-many-nested-blocks
        while i < len(keys):
            data_addr = keys[i]
            i += 1

            memory_data = self.memory_data[data_addr]

            if memory_data.sort == MemoryDataSort.SegmentBoundary:
                continue

            content_holder = []

            # let's see what sort of data it is
            if memory_data.sort in (MemoryDataSort.Unknown, MemoryDataSort.Unspecified) or (
                memory_data.sort == MemoryDataSort.Integer and memory_data.size in (0, self.project.arch.bytes)
            ):
                data_type, data_size = self._guess_data_type(
                    data_addr,
                    memory_data.max_size,
                    content_holder=content_holder,
                    xrefs=xrefs,
                    seg_list=seg_list,
                    data_type_guessing_handlers=data_type_guessing_handlers,
                )
            else:
                data_type, data_size = memory_data.sort, memory_data.size

            if data_type is not None:
                memory_data.size = data_size
                memory_data.sort = data_type

                if len(content_holder) == 1:
                    memory_data.content = content_holder[0]

                if memory_data.max_size is not None and (0 < memory_data.size < memory_data.max_size):
                    # Create another memory_data object to fill the gap
                    new_addr = data_addr + memory_data.size
                    new_md = MemoryData(new_addr, None, None, max_size=memory_data.max_size - memory_data.size)
                    self.memory_data[new_addr] = new_md
                    if xrefs is not None:
                        # Make a copy of all old references
                        old_crs = xrefs.get_xrefs_by_dst(data_addr)
                        crs = []
                        for old_cr in old_crs:
                            cr = old_cr.copy()
                            cr.memory_data = new_md
                            crs.append(cr)
                        xrefs.add_xrefs(crs)
                    keys.insert(i, new_addr)

                if data_type == MemoryDataSort.PointerArray:
                    # make sure all pointers are identified
                    pointer_size = self.project.arch.bytes
                    old_crs = xrefs.get_xrefs_by_dst(data_addr) if xrefs is not None else []

                    for j in range(0, data_size, pointer_size):
                        ptr = self.project.loader.fast_memory_load_pointer(data_addr + j)

                        # is this pointer coming from the current binary?
                        obj = self.project.loader.find_object_containing(ptr, membership_check=False)
                        if obj is not self.project.loader.main_object:
                            # the pointer does not come from current binary. skip.
                            continue

                        if seg_list is not None and seg_list.is_occupied(ptr):
                            sort = seg_list.occupied_by_sort(ptr)
                            if sort == "code":
                                continue
                            if sort == "pointer-array":
                                continue
                            # TODO: other types
                        if ptr not in self.memory_data:
                            new_md = MemoryData(ptr, 0, MemoryDataSort.Unknown, pointer_addr=data_addr + j)
                            self.memory_data[ptr] = new_md
                            if xrefs is not None:
                                # Make a copy of the old reference
                                crs = []
                                for old_cr in old_crs:
                                    cr = old_cr.copy()
                                    cr.memory_data = new_md
                                    crs.append(cr)
                                xrefs.add_xrefs(crs)
                            new_data_found = True

            else:
                if memory_data.max_size is not None:
                    memory_data.size = memory_data.max_size

            if seg_list is not None:
                seg_list.occupy(data_addr, memory_data.size, memory_data.sort)

        return new_data_found

    def _guess_data_type(
        self,
        data_addr,
        max_size,
        content_holder=None,
        xrefs: XRefManager | None = None,
        seg_list: SegmentList | None = None,
        data_type_guessing_handlers: list[Callable] | None = None,
        extra_memory_regions: list[tuple[int, int]] | None = None,
    ):
        """
        Make a guess to the data type.

        Users can provide their own data type guessing code when initializing CFGFast instance, and each guessing
        handler will be called if this method fails to determine what the data is.

        :param int data_addr: Address of the data.
        :param int max_size: The maximum size this data entry can be.
        :return: a tuple of (data type, size). (None, None) if we fail to determine the type or the size.
        :rtype: tuple
        """

        assert self.project is not None and self.project.loader is not None

        if max_size is None:
            max_size = 0

        # quick check: if it's at the beginning of a binary, it might be the ELF header
        elfheader_sort, elfheader_size = self._guess_data_type_elfheader(data_addr, max_size)
        if elfheader_sort:
            return elfheader_sort, elfheader_size

        pointer_size = self.project.arch.bytes

        # who's using it?
        irsb_addr, stmt_idx = None, None
        if xrefs is not None and seg_list is not None:
            try:
                ref: XRef = next(iter(xrefs.get_xrefs_by_dst(data_addr)))
                irsb_addr = ref.block_addr
            except StopIteration:
                pass
        if irsb_addr is not None and isinstance(self.project.loader.main_object, cle.MetaELF):
            plt_entry = self.project.loader.main_object.reverse_plt.get(irsb_addr, None)
            if plt_entry is not None:
                # IRSB is owned by plt!
                return MemoryDataSort.GOTPLTEntry, pointer_size

        # is it in a section with zero bytes, like .bss?
        obj = self.project.loader.find_object_containing(data_addr)
        if obj is None:
            return None, None
        section = obj.find_section_containing(data_addr)
        if section is not None and section.only_contains_uninitialized_data:
            # Nothing much you can do
            return None, None

        r = self._guess_data_type_pointer_array(
            data_addr, pointer_size, max_size, extra_memory_regions=extra_memory_regions
        )
        if r is not None:
            return r

        non_zero_max_size = 1024 if max_size == 0 else max_size
        try:
            data = self.project.loader.memory.load(data_addr, min(1024, non_zero_max_size))
        except KeyError:
            data = b""

        # Is it an unicode string?
        # TODO: Support unicode string longer than the max length
        if len(data) >= 4 and data[1] == 0 and data[2] != 0 and data[3] == 0 and data[0] in _PRINTABLES:

            def can_decode(n):
                try:
                    data[: n * 2].decode("utf_16_le")
                except UnicodeDecodeError:
                    return False
                return True

            if can_decode(4) or can_decode(5) or can_decode(6):
                running_failures = 0
                last_success = 4
                for i in range(4, len(data) // 2):
                    if can_decode(i):
                        last_success = i
                        running_failures = 0
                        if data[i * 2 - 2] == 0 and data[i * 2 - 1] == 0:
                            break
                    else:
                        running_failures += 1
                        if running_failures > 3:
                            break

                if last_success > 5:
                    if content_holder is not None:
                        string_data = data[: last_success * 2]
                        if string_data.endswith(b"\x00\x00"):
                            string_data = string_data[:-2]
                        content_holder.append(string_data)
                    return MemoryDataSort.UnicodeString, last_success * 2

        if data:
            try:
                zero_pos = data.index(0)
            except ValueError:
                zero_pos = None
            if (zero_pos is not None and zero_pos > 0 and all(c in _PRINTABLES for c in data[:zero_pos])) or all(
                c in _PRINTABLES for c in data
            ):
                # it's a string
                # however, it may not be terminated
                string_data = data if zero_pos is None else data[:zero_pos]
                if content_holder is not None:
                    content_holder.append(string_data)
                string_len = len(string_data)
                if zero_pos:
                    string_len += 1
                return MemoryDataSort.String, min(string_len, 1024)

        # is it a code reference?
        irsb_addr, stmt_idx = None, None
        if xrefs is not None and seg_list is not None:
            try:
                ref: XRef = next(iter(xrefs.get_xrefs_by_dst(data_addr)))
                irsb_addr = ref.block_addr
                stmt_idx = ref.stmt_idx
            except StopIteration:
                pass

            if seg_list.is_occupied(data_addr) and seg_list.occupied_by_sort(data_addr) == "code":
                # it's a code reference
                # TODO: Further check if it's the beginning of an instruction
                return MemoryDataSort.CodeReference, 0

        if data_type_guessing_handlers:
            for handler in data_type_guessing_handlers:
                irsb = None if irsb_addr is None else self.get_any_node(irsb_addr).block.vex
                sort, size = handler(self, irsb, irsb_addr, stmt_idx, data_addr, max_size)
                if sort is not None:
                    return sort, size

        return None, None

    def _guess_data_type_pointer_array(
        self,
        data_addr: int,
        pointer_size: int,
        max_size: int,
        extra_memory_regions: list[tuple[int, int]] | None = None,
    ):
        assert self.project is not None and self.project.loader is not None

        pointers_count = 0

        max_pointer_array_size = min(512 * pointer_size, max_size)
        for i in range(0, max_pointer_array_size, pointer_size):
            ptr = self.project.loader.fast_memory_load_pointer(data_addr + i)

            if ptr is not None:
                # if self._seg_list.is_occupied(ptr) and self._seg_list.occupied_by_sort(ptr) == 'code':
                #    # it's a code reference
                #    # TODO: Further check if it's the beginning of an instruction
                #    pass
                if (
                    self.project.loader.find_section_containing(ptr) is not None
                    or self.project.loader.find_segment_containing(ptr) is not None
                    or (extra_memory_regions and next(((a < ptr < b) for (a, b) in extra_memory_regions), None))
                ):
                    # it's a pointer of some sort
                    # TODO: Determine what sort of pointer it is
                    pointers_count += 1
                else:
                    break

        if pointers_count:
            return MemoryDataSort.PointerArray, pointer_size * pointers_count

        return None

    def _guess_data_type_elfheader(self, data_addr, max_size):
        """
        Is the specified data chunk an ELF header?

        :param int data_addr:   Address of the data chunk
        :param int max_size:    Size of the data chunk.
        :return:                A tuple of ('elf-header', size) if it is, or (None, None) if it is not.
        :rtype:                 tuple
        """

        assert self.project is not None and self.project.loader is not None

        obj = self.project.loader.find_object_containing(data_addr)
        if obj is None:
            # it's not mapped
            return None, None

        if data_addr == obj.min_addr and 4 < max_size < 1000:
            # Does it start with the ELF magic bytes?
            try:
                data = self.project.loader.memory.load(data_addr, 4)
            except KeyError:
                return None, None
            if data == b"\x7fELF":
                # yes!
                return MemoryDataSort.ELFHeader, max_size

        return None, None

    #
    # Util methods
    #

    @staticmethod
    def _addr_in_exec_memory_regions(addr: int, exec_mem_regions: list[tuple[int, int]]) -> bool:
        return any(start <= addr < end for start, end in exec_mem_regions)

    def remove_node_and_graph_node(self, node: CFGNode) -> None:
        """
        Like `remove_node`, but also removes node from the graph.

        :param node: The node to remove.
        """
        self.graph.remove_node(node)
        self.remove_node(node.addr, node)  # FIXME: block_id param

    def get_intersecting_functions(
        self,
        addr: int,
        size: int = 1,
        kb: KnowledgeBase | None = None,
    ) -> set[Function]:
        """
        Find all functions with nodes intersecting [addr, addr + size).

        :param addr: Minimum address of target region.
        :param size: Size of region, in bytes.
        :param kb:   Knowledge base to search for functions in.
        """
        if kb is None:
            if self.project is None:
                raise AngrCFGError("Please provide knowledge base")
            kb = self.project.kb

        functions = set()
        for func_addr in {n.function_address for n in self.get_all_nodes_intersecting_region(addr, size)}:
            try:
                func = kb.functions.get_by_addr(func_addr)
            except KeyError:
                l.error("Function %#x not found in KB", func_addr)
                continue
            functions.add(func)
        return functions

    def find_function_for_reflow_into_addr(self, addr: int, kb: KnowledgeBase | None = None) -> Function | None:
        """
        Look for a function that flows into a new node at addr.

        :param addr: Address of new block.
        :param kb:   Knowledge base to search for functions in.
        """
        if kb is None:
            if self.project is None:
                raise AngrCFGError("Please provide knowledge base")
            kb = self.project.kb

        # FIXME: Track nodecodes as nodes in CFG and use graph to resolve instead of analyzing IRSBs here
        assert kb is not None

        func = kb.functions.floor_func(addr)
        if func is None:
            return None

        for block in func.blocks:
            irsb = block.vex
            if (
                irsb.jumpkind == "Ijk_Call"
                and irsb.addr + irsb.size == addr
                and func.get_node(block.addr) not in func.callout_sites
            ) or addr in irsb.constant_jump_targets_and_jumpkinds:
                return func

        return None

    def clear_region_for_reflow(self, addr: int, size: int = 1, kb: KnowledgeBase | None = None) -> None:
        """
        Remove nodes in the graph intersecting region [addr, addr + size).

        Any functions that intersect the range, and their associated nodes in the CFG, will also be removed from the
        knowledge base for analysis.

        :param addr: Minimum address of target region.
        :param size: Size of the region, in bytes.
        :param kb:   Knowledge base to search for functions in.
        """
        if kb is None and self.project is not None:
            kb = self.project.kb

        to_remove = {a for a in self.insn_addr_to_memory_data if addr <= a < (addr + size)}
        for a in to_remove:
            del self.insn_addr_to_memory_data[a]

        if kb:
            for func in self.get_intersecting_functions(addr, size, kb):
                # Save incoming edges to the function for repairs on future edits
                self.edges_to_repair.extend(list(self.graph.in_edges(self.get_all_nodes(func.addr), data=True)))

                for block in func.blocks:
                    for ins_addr in block.instruction_addrs:
                        self.insn_addr_to_memory_data.pop(ins_addr, None)

                    for node in self.get_all_nodes(block.addr):
                        self.remove_node_and_graph_node(node)

                del kb.functions[func.addr]

        # FIXME: Gather any additional edges to nodes that are not part of a function

        for node in self.get_all_nodes_intersecting_region(addr, size):
            self.remove_node_and_graph_node(node)
