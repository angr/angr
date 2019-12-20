from claripy.utils.orderedset import OrderedSet

from ....misc.ux import deprecated


class GraphVisitor:
    """
    A graph visitor takes a node in the graph and returns its successors. Typically it visits a control flow graph, and
    returns successors of a CFGNode each time. This is the base class of all graph visitors.
    """
    def __init__(self):
        self._sorted_nodes = OrderedSet()
        self._node_to_index = { }
        self._reached_fixedpoint = set()

    #
    # Interfaces
    #

    def successors(self, node):
        """
        Get successors of a node. The node should be in the graph.

        :param node: The node to work with.
        :return:     A list of successors.
        :rtype:      list
        """

        raise NotImplementedError()

    def predecessors(self, node):
        """
        Get predecessors of a node. The node should be in the graph.

        :param node: The node to work with.
        :return:     A list of predecessors.
        :rtype:      list
        """

        raise NotImplementedError()

    def sort_nodes(self, nodes=None):
        """
        Get a list of all nodes sorted in an optimal traversal order.

        :param iterable nodes: A collection of nodes to sort. If none, all nodes in the graph will be used to sort.
        :return:               A list of sorted nodes.
        :rtype:                list
        """

        raise NotImplementedError()

    #
    # Public methods
    #

    def nodes(self):
        """
        Return an iterator of nodes following an optimal traversal order.

        :return:
        """

        return iter(
            self.sort_nodes()
        )

    @deprecated(replacement='nodes')
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
        self._node_to_index.clear()
        self._reached_fixedpoint.clear()

        for i, n in enumerate(self.sort_nodes()):
            self._node_to_index[n] = i
            self._sorted_nodes.add(n)

    def next_node(self):
        """
        Get the next node to visit.

        :return: A node in the graph.
        """

        if not self._sorted_nodes:
            return None

        return self._sorted_nodes.pop(last=False)

    def all_successors(self, node, skip_reached_fixedpoint=False):
        """
        Returns all successors to the specific node.

        :param node: A node in the graph.
        :return:     A set of nodes that are all successors to the given node.
        :rtype:      set
        """

        successors = set()

        stack = [ node ]
        while stack:
            n = stack.pop()
            successors.add(n)
            stack.extend(succ for succ in self.successors(n) if
                         succ not in successors and
                            (not skip_reached_fixedpoint or succ not in self._reached_fixedpoint)
                         )

        return successors

    def revisit_successors(self, node, include_self=True):
        """
        Revisit a node in the future. As a result, the successors to this node will be revisited as well.

        :param node: The node to revisit in the future.
        :return:     None
        """

        successors = self.successors(node) #, skip_reached_fixedpoint=True)

        if include_self:
            self._sorted_nodes.add(node)

        for succ in successors:
            self._sorted_nodes.add(succ)

        self._sorted_nodes = OrderedSet(sorted(self._sorted_nodes, key=lambda n: self._node_to_index[n]))

    def revisit_node(self, node):
        """
        Revisit a node in the future. Do not include its successors immediately.

        :param node:    The node to revisit in the future.
        :return:        None
        """

        self._sorted_nodes.add(node)
        self._sorted_nodes = OrderedSet(sorted(self._sorted_nodes, key=lambda n: self._node_to_index[n]))

    def reached_fixedpoint(self, node):
        """
        Mark a node as reached fixed-point. This node as well as all its successors will not be visited in the future.

        :param node: The node to mark as reached fixed-point.
        :return:     None
        """

        self._reached_fixedpoint.add(node)
