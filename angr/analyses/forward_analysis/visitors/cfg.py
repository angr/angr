from angr.analyses.cfg.cfg_utils import CFGUtils
from angr.analyses.forward_analysis.visitors.graph import GraphVisitor


class CFGVisitor(GraphVisitor):
    """
    Visit a given Control Flow Graph.
    """
    def __init__(self, cfg):
        """
        :param angr.knowledge_plugins.cfg.cfg_model.CFGModel cfg:
            The CFG to visit.
        """
        super(CFGVisitor, self).__init__()
        self._cfg = cfg
        self.reset()

    @property
    def cfg(self):
        return self._cfg

    def successors(self, node):
        """
        :return List[CFGNode]: The list of successors of a given node.
        """
        return node.successors

    def predecessors(self, node):
        """
        :return List[CFGNode]: The list of predecessors of a given node.
        """
        return node.predecessors

    def sort_nodes(self, nodes=None):
        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(self.cfg.graph)

        if nodes is not None:
            sorted_nodes = [ n for n in sorted_nodes if n in set(nodes) ]

        return sorted_nodes

    def remove_from_sorted_nodes(self, visited_blocks):
        """
        :param List[Union[Block,CFGNode]] visited_blocks: A list of visited blocks, to remove from the list of things to visit.

        Remove visited nodes from the iherited `_sorted_nodes` attribute.
        """
        visited_addresses = list(map(
            lambda n: n.addr,
            visited_blocks
        ))

        nodes_to_remove = list(filter(
            lambda n: n.addr in visited_addresses,
            self._sorted_nodes
        ))

        for n in nodes_to_remove:
            self._sorted_nodes.remove(n)
