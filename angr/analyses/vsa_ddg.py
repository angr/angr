from .datagraph_meta import DataGraphMeta, DataGraphError

import logging
import collections

import networkx

import simuvex
from simuvex import SimVariable, SimRegisterVariable, SimMemoryVariable, SimTemporaryVariable

l = logging.getLogger(name="angr.analyses.vsa_ddg")

class DefUseChain(object):
    def __init__(self, def_loc, use_loc, variable):
        """

        :param def_loc:
        :param use_loc:
        :param variable:
        :return:
        """
        self.def_loc = def_loc
        self.use_loc = use_loc
        self.variable = variable

class CodeLocation(object):
    def __init__(self, simrun_addr, stmt_idx):
        """
        :param simrun_addr: Address of the SimRun
        :param stmt_idx: Statement ID. None for SimProcedures
        """

        self.simrun_addr = simrun_addr
        self.stmt_idx = stmt_idx

    def __repr__(self):
        if self.stmt_idx is None:
            return "[%#x(-)]" % (self.simrun_addr)
        else:
            return "[%#x(%d)]" % (self.simrun_addr, self.stmt_idx)

    def __eq__(self, other):
        """
        """
        return self.simrun_addr == other.simrun_addr and self.stmt_idx == other.stmt_idx

    def __hash__(self):
        """
        """
        return hash((self.simrun_addr, self.stmt_idx))

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
        self._explore()

    def _explore(self):
        """
        Starting from the start_node, explore the entire VFG, and perform the following:
        - Generate def-use chains for all registers and memory addresses using a worklist
        """

        # The worklist holds individual VFGNodes that comes from the VFG
        # Initialize the worklist with all nodes in VFG
        worklist = set(self._vfg._graph.nodes_iter())

        # A dict storing defs set
        # variable -> locations
        live_defs_per_node = { }
        # A dict storing uses set
        # variable -> locations
        uses_per_node = { }

        while worklist:
            # Pop out a node
            node = worklist.pop()

            # Grab all final states. There are usually more than one (one state for each successor), and we gotta
            # process all of them
            final_states = node.final_states

            if node in live_defs_per_node:
                live_defs = live_defs_per_node[node]
            else:
                live_defs = { }
                live_defs_per_node[node] = live_defs

            successing_nodes = self._vfg._graph.successors(node)
            for state in final_states:
                if state.scratch.jumpkind == 'Ijk_FakeRet' and len(final_states) > 1:
                    # Skip fakerets if there are other control flow transitions available
                    continue

                # TODO: Match the jumpkind
                # TODO: Support cases where IP is undecidable
                corresponding_successors = [ n for n in successing_nodes if n.addr == state.se.any_int(state.ip) ]
                if not corresponding_successors:
                    continue
                successing_node = corresponding_successors[0]

                new_defs = self._track(state, live_defs)

                if successing_node in live_defs_per_node:
                    defs_for_next_node = live_defs_per_node[successing_node]
                else:
                    defs_for_next_node = { }
                    live_defs_per_node[successing_node] = defs_for_next_node

                changed = False
                for var, code_loc_set in new_defs.iteritems():
                    if var not in defs_for_next_node:
                        defs_for_next_node[var] = code_loc_set
                        changed = True

                    else:
                        for code_loc in code_loc_set:
                            if code_loc not in defs_for_next_node[var]:
                                defs_for_next_node[var].add(code_loc)
                                changed = True

                if changed:
                    # Put all reachable successors back to our worklist again
                    worklist.add(successing_node)
                    all_successors_dict = networkx.dfs_successors(self._vfg._graph, source=successing_node)
                    for successors in all_successors_dict.values():
                        for s in successors:
                            worklist.add(s)

    def _track(self, state, live_defs):
        """

        :param state:
        :param live_defs:
        :return:
        """

        # Make a copy of live_defs
        live_defs = live_defs.copy()

        action_list = list(state.log.actions)

        for a in action_list:
            if a.type == "mem":
                if a.actual_addrs is None:
                    # For now, mem reads don't necessarily have actual_addrs set properly
                    addr_list = set(state.memory.normalize_address(a.addr.ast, convert_to_valueset=True))
                else:
                    addr_list = set(a.actual_addrs)

                current_code_loc = CodeLocation(a.bbl_addr, a.stmt_idx)

                for addr in addr_list:
                    variable = SimMemoryVariable(addr, a.data.ast.size()) # TODO: Properly unpack the SAO

                    prevdefs = self._def_lookup(live_defs, variable)

                    if a.action == "read":
                        # Create an edge between def site and use site

                        for prev_code_loc, label in prevdefs.iteritems():
                            self._read_edge = True
                            self._add_edge(prev_code_loc, current_code_loc, label)

                    if a.action == "write":

                        self._kill(live_defs, variable, current_code_loc)

                        # TODO: Create a node in our dependency graph

        return live_defs

    def _def_lookup(self, live_defs, variable):
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
            prevdefs = { }
        else:
            prevdefs = collections.defaultdict(int)  # default value of int is 0


        if variable in live_defs:
            code_loc_set = live_defs[variable]
            for code_loc in code_loc_set:
                # Label edges with cardinality or actual sets of addresses
                if self.keep_addrs is True:
                    prevdefs[code_loc] = variable
                else:
                    prevdefs[code_loc] = prevdefs[code_loc] + 1
        return prevdefs

    def _kill(self, live_defs, variable, code_loc):
        """
        Kill previous defs. @addr_list is a list of normalized addresses
        """

        # Case 1: address perfectly match, we kill
        # Case 2: a is a subset of the original address
        # Case 3: a is a superset of the original address

        live_defs[variable] = { code_loc }
        l.debug("XX CodeLoc %s kills variable %s" % (code_loc, variable))

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
            l.info("New edge: %s --> %s" % (s_a, s_b))

    @property
    def stop(self):
        """
        If this block contains a read that is not creating new edges in the graph,
        then we are looping and we should stop the analysis.
        """
        return self._read_edge and not self._new


