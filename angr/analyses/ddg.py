import logging
from collections import defaultdict

import networkx

from simuvex import SimRegisterVariable, SimMemoryVariable
from simuvex import SimSolverModeError

from ..errors import AngrDDGError
from ..analysis import Analysis, register_analysis
from .code_location import CodeLocation

l = logging.getLogger("angr.analyses.ddg")

class NodeWrapper(object):
    def __init__(self, cfg_node, call_depth):
        self.cfg_node = cfg_node
        self.call_depth = call_depth

class DDG(Analysis):
    """
    This is a fast data dependence graph directly gerenated from our CFG analysis result. The only reason for its
    existance is the speed. There is zero guarantee for being sound or accurate. You are supposed to use it only when
    you want to track the simplest data dependence, and you do not care about soundness or accuracy.

    For a better data dependence graph, please consider to perform a better static analysis first (like Value-set
    Analysis), and then construct a dependence graph on top of the analysis result (for example, the VFG in angr).

    Also note that since we are using states from CFG, any improvement in analysis performed on CFG (like a points-to
    analysis) will directly benefit the DDG.
    """
    def __init__(self, cfg, start=None, keep_data=False, call_depth=None):
        """
        :param cfg:         Control flow graph. Please make sure each node has an associated `state` with it. You may
                            want to generate your CFG with `keep_state=True`.
        :param start:       An address, Specifies where we start the generation of this data dependence graph.
        :param call_depth:  None or integers. A non-negative integer specifies how deep we would like to track in the
                            call tree. None disables call_depth limit.
        """

        # Sanity check
        if not cfg._keep_state:
            raise AngrDDGError('CFG must have "keep_state" set to True.')

        self._cfg = cfg
        self._start = self.project.entry if start is None else start
        self._call_depth = call_depth

        self._graph = networkx.DiGraph()
        self._symbolic_mem_ops = set()

        self.keep_data = keep_data

        # Data dependency graph per function
        self._function_data_dependencies = None

        # Begin construction!
        self._construct()

    #
    # Properties
    #

    @property
    def graph(self):
        """
        :returns: A networkx DiGraph instance representing the data dependence graph.
        """
        return self._graph

    #
    # Public methods
    #

    def pp(self):
        """
        Pretty printing.
        """
        # TODO: make it prettier
        for k,v in self.graph.iteritems():
            for st, tup in v.iteritems():
                print "(0x%x, %d) <- (0x%x, %d)" % (k, st,
                                                            list(tup)[0][0],
                                                            list(tup)[0][1])

    def dbg_repr(self):
        """
        Representation for debugging.
        """
        # TODO:
        return str(self._graph)

    def __contains__(self, code_location):
        """
        Returns whether `code_location` is in the graph.

        :param code_location:   A CodeLocation instance.
        :returns:               True/False
        """

        return code_location in self.graph

    def get_predecessors(self, code_location):
        """
        Returns all predecessors of the code location.

        :param code_location:   A CodeLocation instance.
        :returns:               A list of all predecessors.
        """

        return self._graph.predecessors(code_location)

    def function_dependency_graph(self, func):
        """
        Get a dependency graph for the function `func`.

        :param func:    The Function object in CFG.function_manager.
        :returns:       A networkx.DiGraph instance.
        """

        if self._function_data_dependencies is None:
            self._build_function_dependency_graphs()

        if func in self._function_data_dependencies:
            return self._function_data_dependencies[func]

        # Not found
        return None


    #
    # Private methods
    #

    def _construct(self):
        """
        Construct the data dependence graph.

        We track the following types of dependence:
        - (Intra-IRSB) temporary variable dependencies
        - Register dependencies
        - Memory dependencies, although it's very limited. See below.

        We track the following types of memory access:
        - (Intra-functional) Stack read/write.
            Trace changes of stack pointers inside a function, and the dereferences of stack pointers.
        - (Inter-functional) Stack read/write.
        - (Global) Static memory positions.
            Keep a map of all accessible memory positions to their source statements per function. After that, we
            traverse the CFG and link each pair of reads/writes together in the order of control-flow.

        We do not track the following types of memory access
        - Symbolic memory access
            Well, they cannot be tracked under fastpath mode (which is the mode we are generating the CTF) anyways.
        """

        # TODO: Here we are assuming that there is only one node whose address is the entry point. Otherwise it should
        # TODO: be fixed.
        initial_node = self._cfg.get_any_node(self._start)

        # Initialize the worklist
        nw = NodeWrapper(initial_node, 0)
        worklist = [ ]
        worklist_set = set()

        self._worklist_append(nw, worklist, worklist_set)

        # A dict storing defs set
        # variable -> locations
        live_defs_per_node = {}

        while worklist:
            # Pop out a node
            node_wrapper = worklist[0]
            node, call_depth = node_wrapper.cfg_node, node_wrapper.call_depth
            worklist = worklist[ 1 : ]
            worklist_set.remove(node)

            # Grab all final states. There are usually more than one (one state for each successor), and we gotta
            # process all of them
            final_states = node.final_states

            if node in live_defs_per_node:
                live_defs = live_defs_per_node[node]
            else:
                live_defs = {}
                live_defs_per_node[node] = live_defs

            successing_nodes = self._cfg.graph.successors(node)
            for state in final_states:
                if state.scratch.jumpkind == 'Ijk_FakeRet' and len(final_states) > 1:
                    # Skip fakerets if there are other control flow transitions available
                    continue

                new_call_depth = call_depth
                if state.scratch.jumpkind == 'Ijk_Call':
                    new_call_depth += 1
                elif state.scratch.jumpkind == 'Ijk_Ret':
                    new_call_depth -= 1

                if self._call_depth is not None and call_depth > self._call_depth:
                    l.debug('Do not trace into %s due to the call depth limit', state.ip)
                    continue

                new_defs = self._track(state, live_defs)

                # TODO: Match the jumpkind
                # TODO: Support cases where IP is undecidable
                corresponding_successors = [n for n in successing_nodes if
                                            not state.ip.symbolic and n.addr == state.se.any_int(state.ip)]
                if not corresponding_successors:
                    continue
                successing_node = corresponding_successors[0]

                if successing_node in live_defs_per_node:
                    defs_for_next_node = live_defs_per_node[successing_node]
                else:
                    defs_for_next_node = {}
                    live_defs_per_node[successing_node] = defs_for_next_node

                changed = False
                for var, code_loc_set in new_defs.iteritems():
                    if var not in defs_for_next_node:
                        l.debug('%s New var %s', state.ip, var)
                        defs_for_next_node[var] = code_loc_set
                        changed = True

                    else:
                        for code_loc in code_loc_set:
                            if code_loc not in defs_for_next_node[var]:
                                l.debug('%s New code location %s', state.ip, code_loc)
                                defs_for_next_node[var].add(code_loc)
                                changed = True

                if changed:
                    if (self._call_depth is None) or \
                        (self._call_depth is not None and new_call_depth >= 0 and new_call_depth <= self._call_depth):
                        # Put all reachable successors back to our worklist again
                        nw = NodeWrapper(successing_node, new_call_depth)
                        self._worklist_append(nw, worklist, worklist_set)

    def _track(self, state, live_defs):
        """
        Given all live definitions prior to this program point, track the changes, and return a new list of live
        definitions. We scan through the action list of the new state to track the changes.

        :param state:       The input state at that program point.
        :param live_defs:   A list of all live definitions prior to reaching this program point.
        :returns:           A list of new live definitions.
        """

        # Make a copy of live_defs
        live_defs = live_defs.copy()

        action_list = list(state.log.actions)

        # Since all temporary variables are local, we simply track them in a local dict
        temps = {}

        # All dependence edges are added to the graph either at the end of this method, or when they are going to be
        # overwritten by a new edge. This is because we sometimes have to modify a  previous edge (e.g. add new labels
        # to the edge)
        temps_to_edges = defaultdict(list)
        regs_to_edges = defaultdict(list)

        def _annotate_edges_in_dict(dict_, key, **new_labels):
            """

            :param dict_:       The dict, can be either `temps_to_edges` or `regs_to_edges`.
            :param key:         The key used in finding elements in the dict.
            :param new_labels:  New labels to be added to those edges.
            """

            for edge_tuple in dict_[key]:
                # unpack it
                _, _, labels = edge_tuple
                for k, v in new_labels.iteritems():
                    if k in labels:
                        labels[k] = labels[k] + (v,)
                    else:
                        # Construct a tuple
                        labels[k] = (v,)

        def _dump_edge_from_dict(dict_, key, del_key=True):
            """
            Pick an edge from the dict based on the key specified, add it to our graph, and remove the key from dict.

            :param dict_:   The dict, can be either `temps_to_edges` or `regs_to_edges`.
            :param key:     The key used in finding elements in the dict.
            """
            for edge_tuple in dict_[key]:
                # unpack it
                prev_code_loc, current_code_loc, labels = edge_tuple
                # Add the new edge
                self._add_edge(prev_code_loc, current_code_loc, **labels)

            # Clear it
            if del_key:
                del dict_[key]

        for a in action_list:

            if a.bbl_addr is None:
                current_code_loc = CodeLocation(None, None, sim_procedure=a.sim_procedure)
            else:
                current_code_loc = CodeLocation(a.bbl_addr, a.stmt_idx)

            if a.type == "mem":
                if a.actual_addrs is None:
                    # For now, mem reads don't necessarily have actual_addrs set properly
                    try:
                        addr_list = { state.se.any_int(a.addr.ast) }
                    except SimSolverModeError:
                        # it's symbolic... just continue
                        continue
                else:
                    addr_list = set(a.actual_addrs)

                for addr in addr_list:
                    variable = SimMemoryVariable(addr, a.data.ast.size())  # TODO: Properly unpack the SAO

                    if a.action == "read":
                        # Create an edge between def site and use site

                        prevdefs = self._def_lookup(live_defs, variable)

                        for prev_code_loc, labels in prevdefs.iteritems():
                            self._read_edge = True
                            self._add_edge(prev_code_loc, current_code_loc, **labels)

                    if a.action == "write":
                        # Kill the existing live def
                        self._kill(live_defs, variable, current_code_loc)

                    # For each of its register dependency and data dependency, we revise the corresponding edge
                    for reg_off in a.addr.reg_deps:
                        _annotate_edges_in_dict(regs_to_edges, reg_off, subtype='mem_addr')
                    for tmp in a.addr.tmp_deps:
                        _annotate_edges_in_dict(temps_to_edges, tmp, subtype='mem_addr')

                    for reg_off in a.data.reg_deps:
                        _annotate_edges_in_dict(regs_to_edges, reg_off, subtype='mem_data')
                    for tmp in a.data.tmp_deps:
                        _annotate_edges_in_dict(temps_to_edges, tmp, subtype='mem_data')

            elif a.type == 'reg':
                # For now, we assume a.offset is not symbolic
                # TODO: Support symbolic register offsets

                variable = SimRegisterVariable(a.offset, a.data.ast.size())

                if a.action == 'read':
                    # What do we want to do?
                    prevdefs = self._def_lookup(live_defs, variable)

                    if a.offset in regs_to_edges:
                        _dump_edge_from_dict(regs_to_edges, a.offset)

                    for prev_code_loc, labels in prevdefs.iteritems():
                        edge_tuple = (prev_code_loc, current_code_loc, labels)
                        regs_to_edges[a.offset].append(edge_tuple)

                else:
                    # write
                    self._kill(live_defs, variable, current_code_loc)

            elif a.type == 'tmp':
                # tmp is definitely not symbolic
                if a.action == 'read':
                    prev_code_loc = temps[a.tmp]
                    edge_tuple = (prev_code_loc, current_code_loc, {'type': 'tmp', 'data': a.tmp})

                    if a.tmp in temps_to_edges:
                        _dump_edge_from_dict(temps_to_edges, a.tmp)

                    temps_to_edges[a.tmp].append(edge_tuple)

                else:
                    # write
                    temps[a.tmp] = current_code_loc

            elif a.type == 'exit':
                # exits should only depend on tmps

                for tmp in a.tmp_deps:
                    prev_code_loc = temps[tmp]
                    edge_tuple = (prev_code_loc, current_code_loc, {'type': 'exit', 'data': tmp})

                    if tmp in temps_to_edges:
                        _dump_edge_from_dict(temps_to_edges, tmp)

                    temps_to_edges[tmp].append(edge_tuple)

        # In the end, dump all other edges in those two dicts
        for reg_offset in regs_to_edges:
            _dump_edge_from_dict(regs_to_edges, reg_offset, del_key=False)
        for tmp in temps_to_edges:
            _dump_edge_from_dict(temps_to_edges, tmp, del_key=False)

        return live_defs

    def _def_lookup(self, live_defs, variable):
        """
        This is a backward lookup in the previous defs. Note that, as we are using VSA, it is possible that `variable`
        is affected by several definitions.

        :param addr_list:   A list of normalized addresses.
        :returns:           A dict {stmt:labels} where label is the number of individual addresses of `addr_list` (or
                            the actual set of addresses depending on the keep_addrs flag) that are definted by stmt.
        """

        prevdefs = {}

        if variable in live_defs:
            code_loc_set = live_defs[variable]
            for code_loc in code_loc_set:
                # Label edges with cardinality or actual sets of addresses
                if isinstance(variable, SimMemoryVariable):
                    type_ = 'mem'
                elif isinstance(variable, SimRegisterVariable):
                    type_ = 'reg'
                else:
                    raise AngrDDGError('Unknown variable type %s' % type(variable))

                if self.keep_data is True:
                    data = variable

                    prevdefs[code_loc] = {
                        'type': type_,
                        'data': data
                    }

                else:
                    if code_loc in prevdefs:
                        count = prevdefs[code_loc]['count'] + 1
                    else:
                        count = 0
                    prevdefs[code_loc] = {
                        'type': type_,
                        'count': count
                    }
        return prevdefs

    def _kill(self, live_defs, variable, code_loc):
        """
        Kill previous defs. addr_list is a list of normalized addresses.
        """

        # Case 1: address perfectly match, we kill
        # Case 2: a is a subset of the original address
        # Case 3: a is a superset of the original address

        live_defs[variable] = {code_loc}
        #l.debug("XX CodeLoc %s kills variable %s", code_loc, variable)

    def _add_edge(self, s_a, s_b, **edge_labels):
        """
         Add an edge in the graph from `s_a` to statement `s_b`, where `s_a` and `s_b` are tuples of statements of the
         form (irsb_addr, stmt_idx).
        """
        # Is that edge already in the graph ?
        # If at least one is new, then we are not redoing the same path again
        if (s_a, s_b) not in self.graph.edges():
            self.graph.add_edge(s_a, s_b, **edge_labels)
            self._new = True
            l.info("New edge: %s --> %s", s_a, s_b)

    def _worklist_append(self, node_wrapper, worklist, worklist_set):
        """
        Append a CFGNode and its successors into the work-list, and respect the call-depth limit

        :param node_wrapper:    The NodeWrapper instance to insert.
        :param worklist:        The work-list, which is a list.
        :param worklist_set:    A set of all CFGNodes that are inside the work-list, just for the sake of fast look-up.
                                It will be updated as well.
        :returns:               A set of newly-inserted CFGNodes (not NodeWrapper instances).
        """

        if node_wrapper.cfg_node in worklist_set:
            # It's already in the work-list
            return

        worklist.append(node_wrapper)
        worklist_set.add(node_wrapper.cfg_node)

        stack = [ node_wrapper ]
        traversed_nodes = { node_wrapper.cfg_node }
        inserted = { node_wrapper.cfg_node }

        while stack:
            nw = stack.pop()
            n, call_depth = nw.cfg_node, nw.call_depth

            # Get successors
            edges = self._cfg.graph.out_edges(n, data=True)

            for _, dst, data in edges:
                if (dst not in traversed_nodes # which means we haven't touch this node in this appending procedure
                        and dst not in worklist_set): # which means this node is not in the work-list
                    # We see a new node!
                    traversed_nodes.add(dst)

                    if data['jumpkind'] == 'Ijk_Call':
                        if self._call_depth is None or call_depth < self._call_depth:
                            inserted.add(dst)
                            new_nw = NodeWrapper(dst, call_depth + 1)
                            worklist.append(new_nw)
                            worklist_set.add(dst)
                            stack.append(new_nw)
                    elif data['jumpkind'] == 'Ijk_Ret':
                        if call_depth > 0:
                            inserted.add(dst)
                            new_nw = NodeWrapper(dst, call_depth - 1)
                            worklist.append(new_nw)
                            worklist_set.add(dst)
                            stack.append(new_nw)
                    else:
                        new_nw = NodeWrapper(dst, call_depth)
                        inserted.add(dst)
                        worklist_set.add(dst)
                        worklist.append(new_nw)
                        stack.append(new_nw)

        return inserted

    def _build_function_dependency_graphs(self):
        """
        Build dependency graphs for each function, and save them in self._function_data_dependencies.
        """

        # This is a map between functions and its corresponding dependencies
        self._function_data_dependencies = defaultdict(networkx.DiGraph)

        # Group all dependencies first

        simrun_addr_to_func = { }
        for func_addr, func in self._cfg.function_manager.functions.iteritems():
            for block in func.blocks:
                simrun_addr_to_func[block] = func

        for src, dst, data in self.graph.edges_iter(data=True):
            src_target_func = None
            if src.simrun_addr in simrun_addr_to_func:
                src_target_func = simrun_addr_to_func[src.simrun_addr]
                self._function_data_dependencies[src_target_func].add_edge(src, dst, **data)

            if dst.simrun_addr in simrun_addr_to_func:
                dst_target_func = simrun_addr_to_func[dst.simrun_addr]
                if not dst_target_func is src_target_func:
                    self._function_data_dependencies[dst_target_func].add_edge(src, dst, **data)

register_analysis(DDG, 'DDG')
