from ..analysis import Analysis
from ..errors import AngrAnalysisError
import logging
import networkx
import collections

l = logging.getLogger(name="angr.analyses.datagraph")

class DataGraphError(AngrAnalysisError):
    pass

class Block(object):
    """
    Defs and uses in a block.
    """
    def __init__(self, irsb, live_defs, graph):
        """
        irsb: a SimIRSB object
        live_defs: a dict {addr:stmt} containing the definitions from previous
        blocks that are still live at this point, where addr is a tuple
        representing a normalized addr (see simuvex/plugins/abstract_memory.py for more)

        """
        self.irsb = irsb
        self.live_defs= live_defs
        self.graph = graph

        # A repeating block is a block creating an already existing edge in the
        # graph, which is where we want to stop analyzing a specific path
        self._read_edge = False  # The block causes a read edge in the graph
        self._new = False  # There is at least one new read edge

        for st in self.irsb.statements:
            for a in st.actions:
                if a.type == "mem":
                    addr_list = set(irsb.initial_state.memory.normalize_address(a.addr))
                    stmt = (irsb.addr, st.stmt_idx)
                    prevdefs = self._def_lookup(addr_list)

                    if a.action == "read":
                        for prev_stmt, count in prevdefs.iteritems():
                            self._read_edge = True
                            self._add_edge(prev_stmt, stmt, count)

                    if a.action == "write":
                        self._kill(addr_list, stmt)

    def _def_lookup(self, addr_list):
        """
        This is a backward lookup in the previous defs.
        @addr_list is a list of normalized addresses.
        Note that, as we are using VSA, it is possible that @a is affected by
        several definitions.
        Returns: a dict {stmt:count} where count is the number of individual
        addresses of @addr_list that are definted by stmt
        """

        prevdefs = collections.defaultdict(int)  # default value of int is 0
        for addr in addr_list:
            if addr in self.live_defs.keys():
                stmt = self.live_defs[addr]
                prevdefs[stmt] = prevdefs[stmt] + 1
        return prevdefs

    def _kill(self, addr_list, stmt):
        """
        Kill previous defs. @addr_list is a list of normalized addresses
        """

        # Case 1: address perfectly match, we kill
        # Case 2: a is a subset of the original address
        # Case 3: a is a superset of the original address
        for addr in addr_list:
            self.live_defs[addr] = stmt

    def _add_edge(self, s_a, s_b, count):
        """
         Add an edge in the graph from @s_a to statment @s_b, where @s_a and
         @s_b are tuples of statements of the form (irsb_addr, stmt_idx)
        """
        # Is that edge already in the graph ?
        # If at least one is new, then we are not redoing the same path again
        l.info("New edge from (0x%x, %d) to (0x%x, %d)" % (s_a[0], s_a[1], s_b[0], s_b[1]))
        if (s_a, s_b) not in self.graph.edges():
            self.graph.add_edge(s_a, s_b, count=count)
            self._new = True

    @property
    def stop(self):
        """
        If this block contains a read that is not creating new edges in the graph,
        then we are looping and we should stop the analysis.
        """
        return self._read_edge and not self._new


class DataGraph(Analysis):
    """
    A Data dependency graph based on VSA states.
    That means we don't (and shouldn't) expect any symbolic expressions.
    """

    def __init__(self, start_addr, interfunction_level=0):
        """
        start_addr: the address where to start the analysis (typically, a
        function's entry point)

        Returns: a NetworkX graph representing data dependency within the
        analyzed function's scope (including calls to subfunctions).

        The logic:
            Nodes in the graph are memory locations (stack, heap) represented by DataNodes.
            Edges represent their dependencies.

        """

        self._startnode = None # entry point of the analyzed function
        self._vfg = self._p.analyses.VFG(function_start=start_addr,
                                         interfunction_level=interfunction_level)
        self.graph = networkx.DiGraph()

        # Get the first node
        self._startnode = self._vfg_node(start_addr)

        if self._startnode is None:
            raise DataGraphError("No start node :(")

        # We explore one path at a time
        self._branch({}, self._startnode)

    def _irsb(self, in_state):
            """
            We expect a VSA state here.
            """
            return self._p.sim_run(in_state)

    def _vfg_node(self, addr):
        """
        Gets vfg node at @addr
        Returns VFGNode or None
        """
        for n in self._vfg._nodes.values():
            if n.addr == addr:
                return n

    def _branch(self, live_defs, node):
        """
        Recursive function, it branches in every possible path in the VFG.
        @live_defs: a dict {addr:stmt} of live definitions at the start point
        @node: the starting vfg node
        """

        irsb = self._irsb(node.state)
        l.debug("New branch starting at 0x%x" % irsb.addr)
        block = Block(irsb, live_defs, self.graph)
        if block.stop == True:
            l.info("Stopping current branch at 0x%x" % irsb.addr)
            return
        for s in self._vfg._graph.successors(node):
            self._branch(block.live_defs, s)

    def pp(self):
        for e in self.graph.edges():
            print "(0x%x, %d) -> (0x%x, %d)" % (e[0][0], e[0][1], e[1][0], e[1][1])
