# pylint:disable=no-member,protected-access
from __future__ import annotations

import logging
from collections.abc import Callable, Iterator, Mapping
from typing import TYPE_CHECKING

import cle
import networkx
from sortedcontainers import SortedList

from angr.engines.vex.lifter import VEX_IRSB_MAX_SIZE
from angr.errors import AngrCFGError
from angr.protos import cfg_pb2, primitives_pb2
from angr.rustylib.cfg_graph import CfgGraph
from angr.rustylib.memory_data import guess_data_type, tidy_data_references
from angr.serializable import Serializable
from angr.utils.enums_conv import cfg_jumpkind_to_pb

from .cfg_node import CFGNode
from .indirect_jump import IndirectJump
from .memory_data import MemoryData, MemoryDataDict, MemoryDataSort
from .spilling_cfg import SpillingCFG, get_block_key

if TYPE_CHECKING:
    from archinfo.arch_soot import SootAddressDescriptor

    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.functions import Function
    from angr.knowledge_plugins.xrefs import XRef, XRefManager
    from angr.rustylib import SegmentList
    from angr.rustylib.cfg_scan import LoaderSnapshot

    from .types import CFG_ADDR_TYPES

l = logging.getLogger(name=__name__)


class CFGModel(Serializable):
    """
    This class describes a Control Flow Graph for a specific range of code.
    """

    __slots__ = (
        "__weakref__",
        "_addr_type",
        "_block_addrs_with_return",
        "_blockid_to_blockkey",
        "_cache_limit",
        "_cfg_manager",
        "_db_batch_size",
        "_iropt_level",
        "_memory_data",
        "_node_addrs",
        "_node_function_addrs_complete",
        "_segment_budget",
        "edges_to_repair",
        "graph",
        "ident",
        "insn_addr_to_memory_data",
        "is_arm",
        "jump_tables",
        "normalized",
    )

    def __init__(
        self,
        ident,
        cfg_manager=None,
        is_arm=False,
        cache_limit: int | None = None,
        db_batch_size: int = 800,
        addr_type: CFG_ADDR_TYPES = "int",
        segment_budget: int | None = None,
    ):
        self.ident = ident
        self._cfg_manager = cfg_manager
        self.is_arm = is_arm
        self._cache_limit = cache_limit
        self._db_batch_size = db_batch_size
        self._segment_budget = segment_budget
        self.graph: SpillingCFG = None  # type:ignore
        self._addr_type: CFG_ADDR_TYPES = addr_type

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
            addr_type=self.addr_type,
            segment_budget=segment_budget,
        )

        # Jump tables
        self.jump_tables: dict[int, IndirectJump] = {}

        # Memory references
        # A mapping between address and the actual data in memory
        self._memory_data: MemoryDataDict = MemoryDataDict()
        # A mapping between address of the instruction that's referencing the memory data and the memory data itself
        self.insn_addr_to_memory_data: dict[int, MemoryData] = {}

        # addresses of CFGNodes to speed up get_any_node(..., anyaddr=True). Don't serialize
        self._node_addrs: SortedList[int] | None = None
        # block ID to block key mapping for compatibility reasons
        self._blockid_to_blockkey: dict = {}

        # addresses of blocks with a return or conditional return instruction
        self._block_addrs_with_return: set[int | SootAddressDescriptor] = set()

        self.normalized = False

        self.edges_to_repair = []

        # read by FunctionManagerSerializer.load(); node records always come with their function addresses, so this
        # stays False
        self._node_function_addrs_complete: bool = False

    #
    # Properties
    #

    @property
    def memory_data(self) -> MemoryDataDict:
        return self._memory_data

    @memory_data.setter
    def memory_data(self, value: MemoryDataDict | Mapping[int, MemoryData]) -> None:
        self._memory_data = value if isinstance(value, MemoryDataDict) else MemoryDataDict(value)

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
        """A mapping view (block key -> CFGNode) over the graph's nodes."""
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

    def mark_node_addr_has_return(self, node_addr: int | SootAddressDescriptor, has_return: bool = True) -> None:
        if has_return:
            self._block_addrs_with_return.add(node_addr)
        else:
            self._block_addrs_with_return.discard(node_addr)

    def node_addr_has_return(self, node_addr: int | SootAddressDescriptor) -> bool:
        return node_addr in self._block_addrs_with_return

    #
    # Serialization
    #

    def __getstate__(self):
        return {x: self.__getattribute__(x) for x in self.__slots__ if x not in {"__weakref__", "_cfg_manager"}}

    def __setstate__(self, state):
        # defaults for attributes that may be missing from states pickled by older versions of angr
        self._node_function_addrs_complete = False

        for attribute, value in state.items():
            self.__setattr__(attribute, value)

        # Restore cfg_model reference in the graph; nodes are views created by the graph
        self.graph._cfg_model = self

        self._cfg_manager = None

    @classmethod
    def _get_cmsg(cls):
        return cfg_pb2.CFG()  # type:ignore

    def serialize_to_cmessage(self):
        if "Emulated" in self.ident:
            raise NotImplementedError("Serializing a CFGEmulated instance is currently not supported.")

        cmsg = self._get_cmsg()
        cmsg.ident = self.ident

        # Integer-keyed graphs are written as the packed store's segment blobs, which carry the node records and
        # the edges (evicted segments are copied straight out of the backend, nothing is materialized); other key
        # types fall back to per-node and per-edge messages.
        if self.graph.addr_type == "int":
            header, blobs = self.graph._graph.to_blobs()
            cmsg.graph_header = header
            cmsg.graph_segments.extend(blobs)
            if self.graph._extra_edge_attrs:
                l.warning("Non-standard CFG edge attributes are not serialized.")
        else:
            cmsg.nodes.extend(n.serialize_to_cmessage() for n in self.graph.nodes())
            edges = []
            for src, dst, data in self.graph.edges(data=True):
                src_ea, dst_ea = src.addr, dst.addr
                jumpkind, ins_addr, stmt_idx = data.get("jumpkind"), data.get("ins_addr"), data.get("stmt_idx")
                edge = primitives_pb2.Edge()  # type:ignore
                edge.src_ea = src_ea
                edge.dst_ea = dst_ea
                # missing attributes are written as None (their sentinels), not as the protobuf default 0
                jk = cfg_jumpkind_to_pb(jumpkind)
                edge.jumpkind = primitives_pb2.Edge.UnknownJumpkind if jk is None else jk  # type:ignore
                edge.ins_addr = ins_addr if ins_addr is not None else 0xFFFF_FFFF_FFFF_FFFF
                edge.stmt_idx = stmt_idx if stmt_idx is not None else -1
                edges.append(edge)
            cmsg.edges.extend(edges)

        # memory data
        cmsg.memory_data.extend(self._memory_data.serialize_records())

        # jump tables
        for ij in self.jump_tables.values():
            cmsg.jump_tables.append(ij.serialize_to_cmessage())

        cmsg.normalized = self.normalized

        # block addrs with return
        block_addrs_with_return = list(self._block_addrs_with_return)
        cmsg.block_addrs_with_return.extend(block_addrs_with_return)

        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, cfg_manager=None, loader=None):  # pylint:disable=arguments-differ
        from angr.angrdb.v2 import AngrDbV2  # pylint:disable=import-outside-toplevel

        # create a new model unassociated from any project
        model = cls(cmsg.ident) if cfg_manager is None else cfg_manager.new_model(cmsg.ident)

        graph = model.graph
        has_blobs = bool(cmsg.graph_header)
        if has_blobs:
            if model.addr_type != "int":
                raise ValueError("serialized CFG graph segments require an integer-keyed graph")
            header = bytes(cmsg.graph_header)
            graph._load_graph_blobs(header, [bytes(b) for b in cmsg.graph_segments])
            # blobs of format 3 carry the node records; older blobs only the graph, the nodes come as messages
            if CfgGraph.header_version(header) < 3 or cmsg.nodes:
                graph._import_node_fields(cmsg.nodes)
        elif model.addr_type == "int":
            # the node records are built straight from the messages, no CFGNode objects are created
            graph._import_node_fields(cmsg.nodes)
            AngrDbV2.parse_cfg_edges_spilled(cmsg, graph)
        else:
            for node_pb2 in cmsg.nodes:
                graph.add_node(CFGNode.parse_from_cmessage(node_pb2, cfg=model))
            AngrDbV2.parse_cfg_edges(cmsg, model)

        model._node_addrs = None

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

        # block addrs with return
        model._block_addrs_with_return = set(cmsg.block_addrs_with_return)

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
            addr_type=self.addr_type,
            segment_budget=self._segment_budget,
        )
        model.graph = self.graph.copy()
        model.graph._cfg_model = model
        model.jump_tables = self.jump_tables.copy()
        model.memory_data = self.memory_data.copy()
        # keep the instruction map pointing at the copy's records
        old_store = self._memory_data.store
        model.insn_addr_to_memory_data = {
            k: model.memory_data[v._key] if v._store is old_store else v
            for k, v in self.insn_addr_to_memory_data.items()
        }
        model.edges_to_repair = self.edges_to_repair.copy()
        model._node_function_addrs_complete = self._node_function_addrs_complete

        return model

    def _build_node_addr_index(self):
        self._node_addrs = SortedList(self.graph.node_addrs())

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

    def floor_addr(self, addr: int) -> int | None:
        """
        Get the largest address that is less than or equal to the given address and has a CFGNode.

        :param addr: The address to floor.
        :return: The largest address that is less than or equal to the given address and has a CFGNode, or None if
                 no such address exists.
        """
        if self._node_addrs is None:
            self._build_node_addr_index()
            assert self._node_addrs is not None

        pos = self._node_addrs.bisect_right(addr)
        if pos == 0:
            return None
        return self._node_addrs[pos - 1]

    def ceil_addr(self, addr: int) -> int | None:
        """
        Get the smallest address that is greater than or equal to the given address and has a CFGNode.

        :param addr: The address to ceil.
        :return: The smallest address that is greater than or equal to the given address and has a CFGNode, or None if
                 no such address exists.
        """
        if self._node_addrs is None:
            self._build_node_addr_index()
            assert self._node_addrs is not None

        pos = self._node_addrs.bisect_left(addr)
        if pos == len(self._node_addrs):
            return None
        return self._node_addrs[pos]

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
        for pred, jk in self.graph.predecessors_and_jumpkinds(cfgnode):
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
        for suc, jk in self.graph.successors_and_jumpkinds(node):
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
        for suc, jk in self.graph.successors_and_jumpkinds(node):
            if not excluding_fakeret or jk != "Ijk_FakeRet":
                successors.append((suc, jk))
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
        for pred, jk in self.graph.predecessors_and_jumpkinds(node):
            if not excluding_fakeret or jk != "Ijk_FakeRet":
                predecessors.append((pred, jk))
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

        return self._memory_data.store.add_memory_data(data_addr, data_type, data_size)

    def tidy_data_references(
        self,
        memory_data_addrs: list[int] | None = None,
        exec_mem_regions: list[tuple[int, int]] | None = None,
        xrefs: XRefManager | None = None,
        seg_list: SegmentList | None = None,
        data_type_guessing_handlers: list[Callable] | None = None,
        fill_gaps: bool = True,
        new_mem_data_addrs: set[int] | None = None,
        snapshot: LoaderSnapshot | None = None,
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
        :param fill_gaps:           If True, when a memory data entry is found to have a gap between its end and the
                                    next data entry, a new memory data entry will be created to fill the gap. fill_gaps
                                    should only be set to True at the end of CFG recovery when traversing the entire
                                    memory_data dict for the last time.
        :param new_mem_data_addrs:  If given, addresses of the memory data entries created for pointer targets are
                                    added to it.
        :param snapshot:            A LoaderSnapshot of the project's loader; Project.loader_snapshot() if not given.
        :return:                    True if new data entries are found, False otherwise.
        """

        assert self.project is not None and self.project.loader is not None

        if memory_data_addrs is not None and not memory_data_addrs:
            return False
        if snapshot is None:
            snapshot = self._take_loader_snapshot()

        new_data_found, new_addrs = tidy_data_references(
            self._memory_data.store,
            snapshot,
            memory_data_addrs=memory_data_addrs,
            exec_mem_regions=exec_mem_regions,
            seg_list=seg_list,
            has_xrefs=xrefs is not None,
            plt_xref=self._plt_xref_check(xrefs, seg_list),
            copy_xrefs=None if xrefs is None else self._xref_copier(xrefs),
            guess_fallback=self._guess_fallback(xrefs, seg_list, data_type_guessing_handlers),
            fill_gaps=fill_gaps,
        )
        if new_mem_data_addrs is not None:
            new_mem_data_addrs.update(new_addrs)
        return new_data_found

    def _take_loader_snapshot(self) -> LoaderSnapshot:
        assert self.project is not None
        return self.project.loader_snapshot()

    def _plt_xref_check(self, xrefs: XRefManager | None, seg_list: SegmentList | None) -> Callable | None:
        """`plt_xref(data_addr)`: is `data_addr` read by a PLT stub (a GOT PLT slot)? None when it never is."""
        assert self.project is not None
        main_object = self.project.loader.main_object
        if xrefs is None or seg_list is None or not isinstance(main_object, cle.MetaELF):
            return None
        reverse_plt = main_object.reverse_plt
        if not reverse_plt:
            return None

        def plt_xref(data_addr: int) -> bool:
            return any(
                ref.block_addr is not None and ref.block_addr in reverse_plt
                for ref in xrefs.get_xrefs_by_dst(data_addr)
            )

        return plt_xref

    def _xref_copier(self, xrefs: XRefManager) -> Callable[[int, int], None]:
        """`copy_xrefs(old_addr, new_addr)`: copy the xrefs of the data at old_addr for the new data at new_addr."""

        def copy_xrefs(old_addr: int, new_addr: int) -> None:
            old_crs = xrefs.get_xrefs_by_dst(old_addr)
            if not old_crs:
                return
            new_md = self.memory_data[new_addr]
            crs = []
            for old_cr in old_crs:
                cr = old_cr.copy()
                cr.memory_data = new_md
                crs.append(cr)
            xrefs.add_xrefs(crs)

        return copy_xrefs

    def _guess_fallback(
        self,
        xrefs: XRefManager | None,
        seg_list: SegmentList | None,
        data_type_guessing_handlers: list[Callable] | None,
    ) -> Callable | None:
        """`guess(data_addr, max_size)`: run the user's data type guessing handlers; None without handlers."""
        if not data_type_guessing_handlers:
            return None

        def guess(data_addr: int, max_size: int) -> tuple[str, int | None] | None:
            irsb_addr, stmt_idx = None, None
            if xrefs is not None and seg_list is not None:
                ref = self._first_xref(xrefs.get_xrefs_by_dst(data_addr))
                if ref is not None:
                    irsb_addr = ref.block_addr
                    stmt_idx = ref.stmt_idx
            for handler in data_type_guessing_handlers:
                irsb = None if irsb_addr is None else self.get_any_node(irsb_addr).block.vex
                sort, size = handler(self, irsb, irsb_addr, stmt_idx, data_addr, max_size)
                if sort is not None:
                    return sort, size
            return None

        return guess

    def _guess_data_type(
        self,
        data_addr,
        max_size,
        content_holder=None,
        xrefs: XRefManager | None = None,
        seg_list: SegmentList | None = None,
        data_type_guessing_handlers: list[Callable] | None = None,
        snapshot: LoaderSnapshot | None = None,
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

        if snapshot is None:
            snapshot = self._take_loader_snapshot()
        sort, size, content = guess_data_type(
            self._memory_data.store,
            snapshot,
            data_addr,
            max_size,
            seg_list=seg_list,
            has_xrefs=xrefs is not None,
            plt_xref=self._plt_xref_check(xrefs, seg_list),
            guess_fallback=self._guess_fallback(xrefs, seg_list, data_type_guessing_handlers),
        )
        if content_holder is not None and content is not None:
            content_holder.append(content)
        return sort, size

    @staticmethod
    def _first_xref(refs: set[XRef]) -> XRef | None:
        # lowest-addressed xref; set iteration order is not a stable choice
        return min(
            refs,
            key=lambda r: (
                r.ins_addr if r.ins_addr is not None else -1,
                r.block_addr if r.block_addr is not None else -1,
                r.stmt_idx if r.stmt_idx is not None else -1,
                r.type if r.type is not None else -1,
            ),
            default=None,
        )

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
        self.remove_node(node.block_id, node)
        self._block_addrs_with_return.discard(node.addr)
        self._node_addrs = None

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
            assert kb is not None

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
