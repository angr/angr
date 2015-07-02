from .datagraph_meta import DataGraphMeta, DataGraphError
import logging
import networkx
import collections
import simuvex

l = logging.getLogger(name="angr.analyses.vsa_ddg")


class VSA_DDG(DataGraphMeta):
    """
    A Data dependency graph based on VSA states.
    That means we don't (and shouldn't) expect any symbolic expressions.
    """

    def __init__(self, start_addr, interfunction_level=0,
                 context_sensitivity_level=2, keep_addrs=False):
        """
        @start_addr: the address where to start the analysis (typically, a
        function's entry point)

        @interfunction_level and @context_sensitivity_level have the same
        meaning as in the VFG analysis.

        @keep_addrs: whether we keep set of addresses as edges in the graph, or
        just the cardinality of the sets, which can be used as a "weight".

        Returns: a NetworkX graph representing data dependencies.
        """

        self._startnode = None # entry point of the analyzed function
        self._vfg = self._p.analyses.VFG(function_start=start_addr,
                                         interfunction_level=interfunction_level,
                                         context_sensitivity_level=context_sensitivity_level)
        self.graph = networkx.DiGraph()
        self.keep_addrs = keep_addrs

        self._simproc_map = {}
        self._imarks = {}

        # Get the first node
        self._startnode = self._vfg_node(start_addr)

        if self._startnode is None:
            raise DataGraphError ("No start node :(")

        # We explore one path at a time
        self._branch({}, self._startnode)

    def _make_block(self, irsb, live_defs):
        return Block(irsb, live_defs, self.graph, self.keep_addrs)

class Block(object):
    """
    Defs and uses in a block.
    """
    def __init__(self, irsb, live_defs, graph, keep_addrs):
        """
        @irsb: a SimIRSB object

        @live_defs: a dict {addr:stmt} containing the definitions from previous
        blocks that are still live at this point, where addr is a tuple
        representing a normalized addr (see simuvex/plugins/abstract_memory.py for more)

        @keep_addrs: edges in the graph may either be labelled with the
        cardinality of the set of addresses involved, or the set of addresses itself.

        """
        self.irsb = irsb
        self.live_defs= live_defs
        self.graph = graph
        self.keep_addrs = keep_addrs
        self._imarks = {}

        # A repeating block is a block creating an already existing edge in the
        # graph, which is where we want to stop analyzing a specific path
        self._read_edge = False  # The block causes a read edge in the graph
        self._new = False  # There is at least one new read edge
        if isinstance(irsb, simuvex.SimProcedure):
            # TODO: track reads and writes in SimProcedures
            self._track_actions(-1, irsb.successors[0].log.actions)
        else:
            for st in self.irsb.statements:
                self._imarks[(self.irsb.addr, st.stmt_idx)] = st.imark.addr
                self._track_actions(st.stmt_idx, st.actions)

    def _track_actions(self, stmt_idx, a_list):
        for a in a_list:
            if a.type == "mem":
                addr_list = set(self.irsb.initial_state.memory.normalize_address(a.addr.ast))

                node = (self.irsb.addr, stmt_idx)

                prevdefs = self._def_lookup(addr_list)

                if a.action == "read":
                    for prev_node, label in prevdefs.iteritems():
                        self._read_edge = True
                        self._add_edge(prev_node, node, label)

                if a.action == "write":
                    self._kill(addr_list, node)

    def _def_lookup(self, addr_list):
        """
        This is a backward lookup in the previous defs.
        @addr_list is a list of normalized addresses.
        Note that, as we are using VSA, it is possible that @a is affected by
        several definitions.
        Returns: a dict {stmt:label} where label is the number of individual
        addresses of @addr_list (or the actual set of addresses depending on the
        keep_addrs flag) that are definted by stmt.
        """

        if self.keep_addrs is True:
            prevdefs = collections.defaultdict(set)
        else:
            prevdefs = collections.defaultdict(int)  # default value of int is 0

        for addr in addr_list:
            if addr in self.live_defs.keys():
                stmt = self.live_defs[addr]
                # Label edges with cardinality or actual sets of addresses
                if self.keep_addrs is True:
                    prevdefs[stmt].add(addr)
                else:
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
            l.debug("XX Stmt (0x%x, %d) kills addr %s" % (stmt[0], stmt[1], repr(addr)))

    def _add_edge(self, s_a, s_b, label):
        """
         Add an edge in the graph from @s_a to statment @s_b, where @s_a and
         @s_b are tuples of statements of the form (irsb_addr, stmt_idx)
        """
        # Is that edge already in the graph ?
        # If at least one is new, then we are not redoing the same path again
        if (s_a, s_b) not in self.graph.edges():
            self.graph.add_edge(s_a, s_b, label=label)
            self._new = True
            l.info("New edge from (0x%x, %d) --> (0x%x, %d)" %
               (s_a[0], s_a[1],
                s_b[0], s_b[1]))


    @property
    def stop(self):
        """
        If this block contains a read that is not creating new edges in the graph,
        then we are looping and we should stop the analysis.
        """
        return self._read_edge and not self._new


