# pylint:disable=no-member
import pickle
import logging
from typing import Optional, List, Dict
from collections import defaultdict

import networkx

from ...misc.ux import once
from ...protos import cfg_pb2, primitives_pb2
from ...serializable import Serializable
from ...utils.enums_conv import cfg_jumpkind_to_pb, cfg_jumpkind_from_pb
from ...errors import AngrCFGError
from .cfg_node import CFGNode
from .memory_data import MemoryData
from .indirect_jump import IndirectJump


l = logging.getLogger(name=__name__)


class CFGModel(Serializable):
    """
    This class describes a Control Flow Graph for a specific range of code.
    """

    __slots__ = ('ident', 'graph', 'jump_tables', 'memory_data', 'insn_addr_to_memory_data', '_nodes_by_addr',
                 '_nodes', '_cfg_manager', '_iropt_level', )

    def __init__(self, ident, cfg_manager=None):

        self.ident = ident
        self._cfg_manager = cfg_manager

        # Necessary settings
        self._iropt_level = None

        # The graph
        self.graph = networkx.DiGraph()

        # Jump tables
        self.jump_tables: Dict[int,IndirectJump] = { }

        # Memory references
        # A mapping between address and the actual data in memory
        self.memory_data = { }
        # A mapping between address of the instruction that's referencing the memory data and the memory data itself
        self.insn_addr_to_memory_data = { }

        # Lists of CFGNodes indexed by the address of each block. Don't serialize
        self._nodes_by_addr = defaultdict(list)
        # CFGNodes dict indexed by block ID. Don't serialize
        self._nodes = { }

    #
    # Properties
    #

    @property
    def project(self):
        if self._cfg_manager is None:
            return None
        return self._cfg_manager._kb._project

    #
    # Serialization
    #

    def __getstate__(self):
        state = dict(map(
            lambda x: (x, self.__getattribute__(x)),
            self.__slots__
        ))

        return state

    def __setstate__(self, state):
        for attribute, value in state.items():
            self.__setattr__(attribute, value)

        for addr in self._nodes:
            node = self._nodes[addr]
            node._cfg_model = self

    @classmethod
    def _get_cmsg(cls):
        return cfg_pb2.CFG()

    def serialize_to_cmessage(self):
        if "Emulated" in self.ident:
            raise NotImplementedError("Serializing a CFGEmulated instance is currently not supported.")

        cmsg = self._get_cmsg()
        cmsg.ident = self.ident

        # nodes
        nodes = [ ]
        for n in self.graph.nodes():
            nodes.append(n.serialize_to_cmessage())
        cmsg.nodes.extend(nodes)

        # edges
        edges = [ ]
        for src, dst, data in self.graph.edges(data=True):
            edge = primitives_pb2.Edge()
            edge.src_ea = src.addr
            edge.dst_ea = dst.addr
            for k, v in data.items():
                if k == 'jumpkind':
                    edge.jumpkind = cfg_jumpkind_to_pb(v)
                elif k == 'ins_addr':
                    edge.ins_addr = v if v is not None else -1
                elif k == 'stmt_idx':
                    edge.stmt_idx = v if v is not None else -1
                else:
                    edge.data[k] = pickle.dumps(v)
            edges.append(edge)
        cmsg.edges.extend(edges)

        # memory data
        memory_data = [ ]
        for data in self.memory_data.values():
            memory_data.append(data.serialize_to_cmessage())
        cmsg.memory_data.extend(memory_data)

        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, cfg_manager=None, loader=None):  # pylint:disable=arguments-differ
        if cfg_manager is None:
            # create a new model unassociated from any project
            model = cls(cmsg.ident)
        else:
            model = cfg_manager.new_model(cmsg.ident)

        # nodes
        for node_pb2 in cmsg.nodes:
            node = CFGNode.parse_from_cmessage(node_pb2, cfg=model)
            model._nodes[node.block_id] = node
            model._nodes_by_addr[node.addr].append(node)
            model.graph.add_node(node)
            if len(model._nodes_by_addr[node.block_id]) > 1:
                if once("cfg_model_parse_from_cmessage many nodes at addr"):
                    l.warning("Importing a CFG with more than one node for a given address is currently unsupported. "
                              "The resulting graph may be broken.")

        # edges
        for edge_pb2 in cmsg.edges:
            # more than one node at a given address is unsupported, grab the first one
            src = model._nodes_by_addr[edge_pb2.src_ea][0]
            dst = model._nodes_by_addr[edge_pb2.dst_ea][0]
            data = { }
            for k, v in edge_pb2.data.items():
                data[k] = pickle.loads(v)
            data['jumpkind'] = cfg_jumpkind_from_pb(edge_pb2.jumpkind)
            data['ins_addr'] = edge_pb2.ins_addr if edge_pb2.ins_addr != -1 else None
            data['stmt_idx'] = edge_pb2.stmt_idx if edge_pb2.stmt_idx != -1 else None
            model.graph.add_edge(src, dst, **data)

        # memory data
        for data_pb2 in cmsg.memory_data:
            md = MemoryData.parse_from_cmessage(data_pb2)
            if loader is not None and md.content is None:
                # fill in the content
                md.fill_content(loader)
            model.memory_data[md.addr] = md

        return model

    #
    # Other methods
    #

    def copy(self):
        model = CFGModel(self.ident, cfg_manager=self._cfg_manager)
        model.graph = networkx.DiGraph(self.graph)
        model.jump_tables = self.jump_tables.copy()
        model.memory_data = self.memory_data.copy()
        model.insn_addr_to_memory_data = self.insn_addr_to_memory_data.copy()
        model._nodes_by_addr = self._nodes_by_addr.copy()
        model._nodes = self._nodes.copy()

        return model

    #
    # CFG View
    #

    def get_node(self, block_id):
        """
        Get a single node from node key.

        :param BlockID block_id: Block ID of the node.
        :return:                 The CFGNode
        :rtype:                  CFGNode
        """
        if block_id in self._nodes:
            return self._nodes[block_id]
        return None

    def get_any_node(self, addr: int, is_syscall: bool=None, anyaddr: bool=False,
                     force_fastpath: bool=False) -> Optional[CFGNode]:
        """
        Get an arbitrary CFGNode (without considering their contexts) from our graph.

        :param addr:            Address of the beginning of the basic block. Set anyaddr to True to support arbitrary
                                address.
        :param is_syscall:      Whether you want to get the syscall node or any other node. This is due to the fact that
                                syscall SimProcedures have the same address as the targer it returns to.
                                None means get either, True means get a syscall node, False means get something that
                                isn't a syscall node.
        :param anyaddr:         If anyaddr is True, then addr doesn't have to be the beginning address of a basic
                                block. By default the entire graph.nodes() will be iterated, and the first node
                                containing the specific address is returned, which is slow. If you need to do many such
                                queries, you may first call `generate_index()` to create some indices that may speed up
                                the query.
        :param force_fastpath:  If force_fastpath is True, it will only perform a dict lookup in the _nodes_by_addr
                                dict.
        :return:                A CFGNode if there is any that satisfies given conditions, or None otherwise
        """

        # fastpath: directly look in the nodes list
        if not anyaddr:
            try:
                return self._nodes_by_addr[addr][0]
            except (KeyError, IndexError):
                pass

        if force_fastpath:
            return None

        # slower path
        #if self._node_lookup_index is not None:
        #    pass

        # the slowest path
        # try to show a warning first
        # TODO: re-enable it once the segment tree is implemented
        #if self._node_lookup_index_warned == False:
        #    l.warning('Calling get_any_node() with anyaddr=True is slow on large programs. '
        #              'For better performance, you may first call generate_index() to generate some indices that may '
        #              'speed the node lookup.')
        #    self._node_lookup_index_warned = True

        for n in self.graph.nodes():
            if self.ident == "CFGEmulated":
                cond = n.looping_times == 0
            else:
                cond = True
            if anyaddr and n.size is not None:
                cond = cond and (addr == n.addr or n.addr <= addr < n.addr + n.size)
            else:
                cond = cond and (addr == n.addr)
            if cond:
                if is_syscall is None:
                    return n
                if n.is_syscall == is_syscall:
                    return n

        return None

    def get_all_nodes(self, addr: int, is_syscall: bool=None, anyaddr: bool=False) -> List[CFGNode]:
        """
        Get all CFGNodes whose address is the specified one.

        :param addr:       Address of the node
        :param is_syscall: True returns the syscall node, False returns the normal CFGNode, None returns both
        :return:           all CFGNodes
        """
        results = [ ]

        for cfg_node in self.graph.nodes():
            if cfg_node.addr == addr or (anyaddr and
                                         cfg_node.size is not None and
                                         cfg_node.addr <= addr < (cfg_node.addr + cfg_node.size)
                                         ):
                if is_syscall and cfg_node.is_syscall:
                    results.append(cfg_node)
                elif is_syscall is False and not cfg_node.is_syscall:
                    results.append(cfg_node)
                else:
                    results.append(cfg_node)

        return results

    def nodes(self):
        """
        An iterator of all nodes in the graph.

        :return: The iterator.
        :rtype: iterator
        """

        return self.graph.nodes()

    def get_predecessors(self, cfgnode: CFGNode, excluding_fakeret: bool=True,
                         jumpkind: Optional[str]=None) -> List[CFGNode]:
        """
        Get predecessors of a node in the control flow graph.

        :param cfgnode:             The node.
        :param excluding_fakeret:   True if you want to exclude all predecessors that is connected to the node with a
                                    fakeret edge.
        :param jumpkind:            Only return predecessors with the specified jumpkind. This argument will be ignored
                                    if set to None.
        :return:                    A list of predecessors
        """

        if excluding_fakeret and jumpkind == 'Ijk_FakeRet':
            return [ ]

        if not excluding_fakeret and jumpkind is None:
            # fast path
            if cfgnode in self.graph:
                return list(self.graph.predecessors(cfgnode))
            return [ ]

        predecessors = []
        for pred, _, data in self.graph.in_edges([cfgnode], data=True):
            jk = data['jumpkind']
            if jumpkind is not None:
                if jk == jumpkind:
                    predecessors.append(pred)
            elif excluding_fakeret:
                if jk != 'Ijk_FakeRet':
                    predecessors.append(pred)
            else:
                predecessors.append(pred)
        return predecessors

    def get_successors(self, node, excluding_fakeret=True, jumpkind=None):
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

        if jumpkind is not None:
            if excluding_fakeret and jumpkind == 'Ijk_FakeRet':
                return [ ]

        if not excluding_fakeret and jumpkind is None:
            # fast path
            if node in self.graph:
                return list(self.graph.successors(node))
            return [ ]

        successors = []
        for _, suc, data in self.graph.out_edges([node], data=True):
            jk = data['jumpkind']
            if jumpkind is not None:
                if jumpkind == jk:
                    successors.append(suc)
            elif excluding_fakeret:
                if jk != 'Ijk_FakeRet':
                    successors.append(suc)
            else:
                successors.append(suc)
        return successors

    def get_successors_and_jumpkind(self, node, excluding_fakeret=True):
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
            if not excluding_fakeret or data['jumpkind'] != 'Ijk_FakeRet':
                successors.append((suc, data['jumpkind']))
        return successors

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
        predecessors = set().union(*networkx.dfs_successors(self.graph.reverse(), cfgnode, depth_limit).values())
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
        successors = set().union(*networkx.dfs_successors(self.graph, cfgnode, depth_limit).values())
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
            raise AngrCFGError('Edge (%s, %s) does not exist in CFG' % (src_block, dst_block))

        return self.graph[src_block][dst_block]['stmt_idx']
