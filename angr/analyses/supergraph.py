import itertools
from collections import defaultdict

import networkx as nx

from .analysis import Analysis
from ..knowledge_plugins import Function

class SupergraphGenerator(Analysis):
    def __init__(self, function):
        self._function = function

        self.supergraph = None
        self.supernode_mapping = {}
        self._analyze()

    @property
    def _transition_graph(self):
        return self._function.transition_graph

    def _contract_edge(self, src_node, dst_node):
        supernode_src = self._supernode_for_node(src_node)
        supernode_dst = self._supernode_for_node(dst_node)

        if supernode_src == supernode_dst:
            return

        # arbitrarily always pick supernode_src as our new supernode

        # join all the nodes from supernode_dst into supernode_src
        supernode_src.merge(supernode_dst)
        for n in supernode_dst.cfg_nodes:
            self.supernode_mapping[n] = supernode_src

        # update all edges to/from supernode_dst to now be to/from supernode_src
        for _, dst, data in self.supergraph.out_edges(supernode_dst, data=True):
            if supernode_src != dst:
                self.supergraph.add_edge(supernode_src, dst, **data)
        for src, _, data in self.supergraph.in_edges(supernode_dst, data=True):
            if supernode_src != src:
                self.supergraph.add_edge(src, supernode_src, **data)

        self.supergraph.remove_node(supernode_dst)

    def _supernode_for_node(self, node):
        return self.supernode_mapping.get(node)

    def _edges_to_contract_to_create_supergraph(self):
        edges_to_shrink = set()

        # Find all edges to remove in the super graph
        for src in self._transition_graph.nodes():
            edges = self._transition_graph[src]

            # there are two types of edges we want to remove:
            # - call or fakerets, since we do not want blocks to break at calls
            # - boring jumps that directly transfer the control to the block immediately after the current block. this is
            #   usually caused by how VEX breaks down basic blocks, which happens very often in MIPS
            if len(edges) == 1 and src.addr + src.size == next(iter(edges.keys())).addr:
                dst = next(iter(edges.keys()))
                dst_in_edges = self._transition_graph.in_edges(dst)
                if len(dst_in_edges) == 1:
                    edges_to_shrink.add((src, dst))
                    continue

            if any(iter('type' in data and data['type'] not in ('fake_return', 'call') for data in edges.values())):
                continue

            for dst, data in edges.items():
                if isinstance(dst, Function):
                    continue
                if 'type' in data and data['type'] == 'fake_return':
                    edge_is_ret = lambda src, dst, data: 'type' in data and data['type'] in ('fake_return', 'return_from_call')
                    if all(map(lambda args: edge_is_ret(*args), self._transition_graph.in_edges(dst, data=True))):
                        edges_to_shrink.add((src, dst))
                    break
        return edges_to_shrink

    def _analyze(self):
        """
        Convert transition graph of a function to a super transition graph. A super transition graph is a graph that looks
        like IDA Pro's CFG, where calls to returning functions do not terminate basic blocks.

        :param nx.DiGraph transition_graph: The transition graph.
        :return: A converted super transition graph
        :rtype nx.DiGraph
        """

        # Create the super graph
        self.supergraph = nx.DiGraph()

        function_nodes = set()  # it will be traversed after all other nodes are added into the supergraph

        # lift all the nodes to supernodes containing one node
        for node in self._transition_graph:
            if isinstance(node, Function): # don't put functions into the supergraph
                function_nodes.add(node)   # but store them for later
                continue
            self.supernode_mapping[node] = SuperCFGNode.from_cfgnode(node)

        # add all the new supernodes and edges to the graph
        for node in self._transition_graph:
            if self._transition_graph.in_degree(node) == 0:
                continue
            super_node = self._supernode_for_node(node)
            if super_node is not None:
                self.supergraph.add_node(super_node)

        for src, dst, data in self._transition_graph.edges(data=True):
            if data['type'] == 'transition' and data.get('outside', False) is True:
                continue
            src_super_node = self._supernode_for_node(src)
            dst_super_node = self._supernode_for_node(dst)
            if src_super_node is not None and dst_super_node is not None:
                self.supergraph.add_edge(src_super_node, dst_super_node, **data)

        # identify edges to contract
        edges_to_contract = self._edges_to_contract_to_create_supergraph()

        # contract them
        for src, dst in edges_to_contract:
            self._contract_edge(src, dst)

        for node in function_nodes:
            in_edges = self._transition_graph.in_edges(node, data=True)
            for src, _, data in in_edges:
                super_node = self.supernode_mapping[src]
                self._add_edge_to_supergraph(super_node, node.addr, data)

        for super_node in self.supergraph:
            for _, dst, data in self.supergraph.out_edges(super_node, data=True):
                self._add_edge_to_supergraph(super_node, dst.addr, data)

    def _add_edge_to_supergraph(self, supernode_src, dst_addr, data):
        if data.get('type') == 'transition':
            if not ('ins_addr' in data and 'stmt_idx' in data):
                # this is a hack to work around the issue in Function.normalize() where ins_addr and
                # stmt_idx weren't properly set onto edges
                return
            supernode_src.register_out_branch(data['ins_addr'], data['stmt_idx'], data['type'], dst_addr)


class OutBranch:
    def __init__(self, ins_addr, stmt_idx, branch_type):
        self.ins_addr = ins_addr
        self.stmt_idx = stmt_idx
        self.type = branch_type

        self.targets = set()

    def __repr__(self):
        return "<OutBranch at %#x, type %s>" % (self.ins_addr, self.type)

    def add_target(self, addr):
        self.targets.add(addr)

    def merge(self, other):
        """
        Merge with the other OutBranch descriptor.

        :param OutBranch other: The other item to merge with.
        :return: None
        """

        assert self.ins_addr == other.ins_addr
        assert self.type == other.type

        o = self.copy()
        o.targets |= other.targets

        return o

    def copy(self):
        o = OutBranch(self.ins_addr, self.stmt_idx, self.type)
        o.targets = self.targets.copy()
        return o

    def __eq__(self, other):
        if not isinstance(other, OutBranch):
            return False

        return self.ins_addr == other.ins_addr and \
               self.stmt_idx == other.stmt_idx and \
               self.type == other.type and \
               self.targets == other.targets

    def __hash__(self):
        return hash((self.ins_addr, self.stmt_idx, self.type))


class SuperCFGNode:
    def __init__(self, addr):
        self.addr = addr

        self.cfg_nodes = [ ]

        self.out_branches = defaultdict(dict)

    @property
    def size(self):
        return sum(node.size for node in self.cfg_nodes)

    @classmethod
    def from_cfgnode(cls, cfg_node):
        s = cls(cfg_node.addr)

        s.cfg_nodes.append(cfg_node)

        return s

    def insert_cfgnode(self, cfg_node):
        # TODO: Make it binary search/insertion
        for i, n in enumerate(self.cfg_nodes):
            if cfg_node.addr < n.addr:
                # insert before n
                self.cfg_nodes.insert(i, cfg_node)
                break
            elif cfg_node.addr == n.addr:
                break
        else:
            self.cfg_nodes.append(cfg_node)

        # update addr
        self.addr = self.cfg_nodes[0].addr

    def register_out_branch(self, ins_addr, stmt_idx, branch_type, target_addr):
        if ins_addr not in self.out_branches or stmt_idx not in self.out_branches[ins_addr]:
            self.out_branches[ins_addr][stmt_idx] = OutBranch(ins_addr, stmt_idx, branch_type)

        self.out_branches[ins_addr][stmt_idx].add_target(target_addr)

    def merge(self, other):
        """
        Merge another supernode into the current one.

        :param SuperCFGNode other: The supernode to merge with.
        :return: None
        """

        for n in other.cfg_nodes:
            self.insert_cfgnode(n)

        for ins_addr, outs in other.out_branches.items():
            if ins_addr in self.out_branches:
                for stmt_idx, item in outs.items():
                    if stmt_idx in self.out_branches[ins_addr]:
                        self.out_branches[ins_addr][stmt_idx].merge(item)
                    else:
                        self.out_branches[ins_addr][stmt_idx] = item

            else:
                item = next(iter(outs.values()))
                self.out_branches[ins_addr][item.stmt_idx] = item

    def __repr__(self):
        return "<SuperCFGNode %#08x, %d blocks, %d out branches>" % (self.addr, len(self.cfg_nodes),
                                                                     len(self.out_branches)
                                                                     )

    def __hash__(self):
        return hash(('supercfgnode', self.addr))

    def __eq__(self, other):
        if not isinstance(other, SuperCFGNode):
            return False

        return self.addr == other.addr

from ..analyses import AnalysesHub
AnalysesHub.register_default('SupergraphGeneration', SupergraphGenerator)
