from typing import TypeVar, Generic, List, Collection, Optional, Iterator, Set, Dict, Tuple
from collections import defaultdict

from ....misc.ux import deprecated
from ....utils.algo import binary_insert

NodeType = TypeVar("NodeType")


class GraphVisitor(Generic[NodeType]):
    """
    A graph visitor takes a node in the graph and returns its successors. Typically, it visits a control flow graph,
    and returns successors of a CFGNode each time. This is the base class of all graph visitors.
    """

    __slots__ = (
        "_sorted_nodes",
        "_worklist",
        "_nodes_set",
        "_node_to_index",
        "_reached_fixedpoint",
        "_back_edges_by_src",
        "_back_edges_by_dst",
        "_pending_nodes",
    )

    def __init__(self):
        self._sorted_nodes: List[NodeType] = []  # a list of sorted nodes. do not change until we get a new graph
        self._worklist: List[NodeType] = []  # a list of nodes that the analysis should work on and finally exhaust
        self._nodes_set: Set[NodeType] = set()
        self._node_to_index: Dict[NodeType, int] = {}
        self._reached_fixedpoint: Set[NodeType] = set()
        self._back_edges_by_src: Optional[Dict[NodeType, Set[NodeType]]] = None
        self._back_edges_by_dst: Optional[Dict[NodeType, Set[NodeType]]] = None

        self._pending_nodes: Dict[NodeType, Set[NodeType]] = defaultdict(set)

    #
    # Interfaces
    #

    def successors(self, node: NodeType) -> List[NodeType]:
        """
        Get successors of a node. The node should be in the graph.

        :param node: The node to work with.
        :return:     A list of successors.
        :rtype:      list
        """

        raise NotImplementedError()

    def predecessors(self, node: NodeType) -> List[NodeType]:
        """
        Get predecessors of a node. The node should be in the graph.

        :param node: The node to work with.
        :return:     A list of predecessors.
        """

        raise NotImplementedError()

    def sort_nodes(self, nodes: Optional[Collection[NodeType]] = None) -> List[NodeType]:
        """
        Get a list of all nodes sorted in an optimal traversal order.

        :param iterable nodes: A collection of nodes to sort. If none, all nodes in the graph will be used to sort.
        :return:               A list of sorted nodes.
        """

        raise NotImplementedError()

    def back_edges(self) -> List[Tuple[NodeType, NodeType]]:
        """
        Get a list of back edges. This function is optional. If not overriden, the traverser cannot achieve an optimal
        graph traversal order.

        :return:                A list of back edges (source -> destination).
        """
        raise NotImplementedError()

    #
    # Public methods
    #

    def nodes(self) -> Iterator[NodeType]:
        """
        Return an iterator of nodes following an optimal traversal order.

        :return:
        """

        return iter(self.sort_nodes())

    @deprecated(replacement="nodes")
    def nodes_iter(self):
        """
        (Deprecated) Return an iterator of nodes following an optimal traversal order. Will be removed in the future.
        """
        return self.nodes()

    # Traversal

    def reset(self):
        """
        Reset the internal node traversal state. Must be called prior to visiting future nodes.

        :return: None
        """

        self._sorted_nodes.clear()
        self._worklist.clear()
        self._nodes_set.clear()
        self._node_to_index.clear()
        self._reached_fixedpoint.clear()

        self._sorted_nodes = list(self.sort_nodes())
        for i, n in enumerate(self._sorted_nodes):
            self._node_to_index[n] = i
            binary_insert(self._worklist, n, lambda elem: self._node_to_index[elem])
            self._nodes_set.add(n)

        self._populate_back_edges()

    def next_node(self) -> Optional[NodeType]:
        """
        Get the next node to visit.

        :return: A node in the graph.
        """

        if not self._worklist:
            return None

        node = None
        for idx in range(len(self._worklist)):  # pylint:disable=consider-using-enumerate
            node_ = self._worklist[idx]
            if node_ in self._pending_nodes:
                if not self._pending_nodes[node_]:
                    # this pending node is cleared - take it
                    node = node_
                    del self._pending_nodes[node_]
                    del self._worklist[idx]
                    break
                # try the next node
                continue

            node = node_
            del self._worklist[idx]
            break

        if node is None:
            # all nodes are pending... we will just pick the first one
            node = self._worklist.pop(0)

        self._nodes_set.discard(node)

        #  check if this node should be added to pending
        if self._back_edges_by_dst and node in self._back_edges_by_dst:
            for back_edge_src in self._back_edges_by_dst[node]:
                self._pending_nodes[node].add(back_edge_src)

        # check if this node is being pended on by any other node
        if self._back_edges_by_src and node in self._back_edges_by_src:
            for back_edge_dst in self._back_edges_by_src[node]:
                self._pending_nodes[back_edge_dst].discard(node)

        return node

    def all_successors(self, node: NodeType, skip_reached_fixedpoint=False) -> Set[NodeType]:
        """
        Returns all successors to the specific node.

        :param node: A node in the graph.
        :return:     A set of nodes that are all successors to the given node.
        :rtype:      set
        """

        successors = set()

        stack = [node]
        while stack:
            n = stack.pop()
            successors.add(n)
            stack.extend(
                succ
                for succ in self.successors(n)
                if succ not in successors and (not skip_reached_fixedpoint or succ not in self._reached_fixedpoint)
            )

        return successors

    def revisit_successors(self, node: NodeType, include_self=True) -> None:
        """
        Revisit a node in the future. As a result, the successors to this node will be revisited as well.

        :param node: The node to revisit in the future.
        :return:     None
        """

        successors = self.successors(node)  # , skip_reached_fixedpoint=True)

        if include_self:
            if node not in self._nodes_set:
                binary_insert(self._worklist, node, lambda elem: self._node_to_index[elem])
                self._nodes_set.add(node)

        for succ in successors:
            if succ not in self._nodes_set:
                binary_insert(self._worklist, succ, lambda elem: self._node_to_index[elem])
                self._nodes_set.add(succ)

    def revisit_node(self, node: NodeType) -> None:
        """
        Revisit a node in the future. Do not include its successors immediately.

        :param node:    The node to revisit in the future.
        :return:        None
        """

        if node not in self._nodes_set:
            binary_insert(self._worklist, node, lambda elem: self._node_to_index[elem])
            self._nodes_set.add(node)

    def reached_fixedpoint(self, node: NodeType) -> None:
        """
        Mark a node as reached fixed-point. This node as well as all its successors will not be visited in the future.

        :param node: The node to mark as reached fixed-point.
        :return:     None
        """

        self._reached_fixedpoint.add(node)

    #
    # Private methods
    #

    def _populate_back_edges(self):
        try:
            back_edges = self.back_edges()
        except NotImplementedError:
            return

        self._back_edges_by_src = defaultdict(set)
        self._back_edges_by_dst = defaultdict(set)
        for src, dst in back_edges:
            self._back_edges_by_src[src].add(dst)
            self._back_edges_by_dst[dst].add(src)
