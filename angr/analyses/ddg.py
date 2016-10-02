import logging
import re
from collections import defaultdict

import networkx

import pyvex
from simuvex import SimRegisterVariable, SimMemoryVariable, SimTemporaryVariable, SimConstantVariable, SimStackVariable
from simuvex import SimSolverModeError, SimUnsatError

from ..errors import AngrDDGError
from ..analysis import Analysis, register_analysis
from .code_location import CodeLocation

l = logging.getLogger("angr.analyses.ddg")


class ProgramVariable(object):
    """
    Describes a variable in the program at a specific location.

    :ivar SimVariable variable: The variable.
    :ivar CodeLocation location: Location of the variable.
    """
    def __init__(self, variable, location, initial=False):
        self.variable = variable
        self.location = location
        self.initial = initial

    def __hash__(self):
        return hash((self.variable, self.location))

    def __eq__(self, other):
        if not isinstance(other, ProgramVariable):
            return False

        return self.variable == other.variable and self.location == other.location

    def __repr__(self):
        s = "<%s @ %s>" % (self.variable, self.location)
        return s


class DDGJob(object):
    def __init__(self, cfg_node, call_depth):
        self.cfg_node = cfg_node
        self.call_depth = call_depth

    def __repr__(self):
        return "<DDGJob %s, call_depth %d>" % (self.cfg_node, self.call_depth)


class LiveDefinitions(object):
    """
    A collection of live definitions with some handy interfaces for definition killing and lookups.
    """
    def __init__(self):
        """
        Constructor.
        """

        # byte-to-byte mappings
        # TODO: make it copy-on-write in order to save memory.
        # TODO: options are either cooldict.COWDict or a modified version of simuvex.SimPagedMemory
        self._memory_map = defaultdict(set)
        self._register_map = defaultdict(set)
        self._defs = defaultdict(set)

    #
    # Overridend methods
    #

    def __contains__(self, variable):
        return variable in self._defs

    #
    # Public methods
    #

    def branch(self):
        """
        Create a branch of the current live definition collection.

        :return: A new LiveDefinition instance.
        :rtype: LiveDefinitions
        """

        ld = LiveDefinitions()
        ld._memory_map = self._memory_map.copy()
        ld._register_map = self._register_map.copy()
        ld._defs = self._defs.copy()

        return ld

    def copy(self):
        """
        Make a hard copy of `self`.

        :return: A new LiveDefinition instance.
        :rtype: LiveDefinitions
        """

        ld = LiveDefinitions()
        ld._memory_map = self._memory_map.copy()
        ld._register_map = self._register_map.copy()
        ld._defs = self._defs.copy()

        return ld

    def add_def(self, variable, location, size_threshold=32):
        """
        Add a new definition of variable.

        :param SimVariable variable: The variable being defined.
        :param CodeLocation location: Location of the varaible being defined.
        :param int size_threshold: The maximum bytes to consider for the variable.
        :return: True if the definition was new, False otherwise
        :rtype: bool
        """

        new_defs_added = False

        if isinstance(variable, SimRegisterVariable):
            if variable.reg is None:
                l.warning('add_def: Got a None for a SimRegisterVariable. Consider fixing.')
                return new_defs_added

            size = min(variable.size, size_threshold)
            offset = variable.reg
            while offset < variable.reg + size:
                if location not in self._register_map[offset]:
                    new_defs_added = True
                self._register_map[offset].add(location)
                offset += 1

            self._defs[variable].add(location)

        elif isinstance(variable, SimMemoryVariable):
            size = min(variable.size, size_threshold)
            offset = variable.addr
            while offset < variable.addr + size:
                if location not in self._memory_map[offset]:
                    new_defs_added = True
                self._memory_map[offset].add(location)
                offset += 1

            self._defs[variable].add(location)

        else:
            l.error('Unsupported variable type "%s".', type(variable))

        return new_defs_added

    def add_defs(self, variable, locations, size_threshold=32):
        """
        Add a collection of new definitions of a variable.

        :param SimVariable variable: The variable being defined.
        :param iterable locations: A collection of locations where the variable was defined.
        :param int size_threshold: The maximum bytes to consider for the variable.
        :return: True if any of the definition was new, False otherwise
        :rtype: bool
        """

        new_defs_added = False

        for loc in locations:
            new_defs_added |= self.add_def(variable, loc, size_threshold=size_threshold)

        return new_defs_added

    def kill_def(self, variable, location, size_threshold=32):
        """
        Add a new definition for variable and kill all previous definitions.

        :param SimVariable variable: The variable to kill.
        :param CodeLocation location: The location where this variable is defined.
        :param int size_threshold: The maximum bytes to consider for the variable.
        :return: None
        """

        if isinstance(variable, SimRegisterVariable):
            if variable.reg is None:
                l.warning('kill_def: Got a None for a SimRegisterVariable. Consider fixing.')
                return None

            size = min(variable.size, size_threshold)
            offset = variable.reg
            while offset < variable.reg + size:
                self._register_map[offset] = { location }
                offset += 1

            self._defs[variable] = { location }

        elif isinstance(variable, SimMemoryVariable):
            size = min(variable.size, size_threshold)
            offset = variable.addr
            while offset < variable.addr + size:
                self._memory_map[offset] = { location }
                offset += 1

            self._defs[variable] = { location }

        else:
            l.error('Unsupported variable type "%s".', type(variable))

    def lookup_defs(self, variable, size_threshold=32):
        """
        Find all definitions of the varaible

        :param SimVariable variable: The variable to lookup for.
        :param int size_threshold: The maximum bytes to consider for the variable. For example, if the variable is 100
                                   byte long, only the first `size_threshold` bytes are considered.
        :return: A set of code locations where the variable is defined.
        :rtype: set
        """

        live_def_locs = set()

        if isinstance(variable, SimRegisterVariable):

            if variable.reg is None:
                l.warning('lookup_defs: Got a None for a SimRegisterVariable. Consider fixing.')
                return live_def_locs

            size = min(variable.size, size_threshold)
            offset = variable.reg
            while offset < variable.reg + size:
                if offset in self._register_map:
                    live_def_locs |= self._register_map[offset]
                offset += 1

        elif isinstance(variable, SimMemoryVariable):
            size = min(variable.size, size_threshold)
            offset = variable.addr
            while offset < variable.addr + size:
                if offset in self._memory_map:
                    live_def_locs |= self._memory_map[offset]
                offset += 1

        else:
            # umm unsupported variable type
            l.error('Unsupported variable type "%s".', type(variable))

        return live_def_locs

    def iteritems(self):
        """
        An iterator that returns all live definitions.

        :return: The iterator.
        :rtype: iter
        """

        return self._defs.iteritems()

    def itervariables(self):
        """
        An iterator that returns all live variables.

        :return: The iterator.
        :rtype: iter
        """

        return self._defs.iterkeys()


class DDG(Analysis):
    """
    This is a fast data dependence graph directly generated from our CFG analysis result. The only reason for its
    existence is the speed. There is zero guarantee for being sound or accurate. You are supposed to use it only when
    you want to track the simplest data dependence, and you do not care about soundness or accuracy.

    For a better data dependence graph, please consider performing a better static analysis first (like Value-set
    Analysis), and then construct a dependence graph on top of the analysis result (for example, the VFG in angr).

    Also note that since we are using states from CFG, any improvement in analysis performed on CFG (like a points-to
    analysis) will directly benefit the DDG.
    """
    def __init__(self, cfg, start=None, call_depth=None):
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

        self._stmt_graph = networkx.DiGraph()
        self._data_graph = networkx.DiGraph()
        self._simplified_data_graph = None

        self._symbolic_mem_ops = set()

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
        :returns: A networkx DiGraph instance representing the dependence relations between statements.
        :rtype: networkx.DiGraph
        """

        return self._stmt_graph

    @property
    def data_graph(self):
        """
        Get the data dependence graph.

        :return: A networkx DiGraph instance representing data dependence.
        :rtype: networkx.DiGraph
        """

        return self._data_graph

    @property
    def simplified_data_graph(self):
        """

        :return:
        """

        if self._simplified_data_graph is None:
            self._simplified_data_graph = self._simplify_data_graph(self.data_graph)

        return self._simplified_data_graph

    #
    # Public methods
    #

    def pp(self):
        """
        Pretty printing.
        """
        # TODO: make it prettier
        for src, dst, data in self.graph.edges_iter(data=True):
            print "%s <-- %s, %s" % (src, dst, data)

    def dbg_repr(self):
        """
        Representation for debugging.
        """
        # TODO:
        return str(self.graph)

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

        return self.graph.predecessors(code_location)

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

    def data_sub_graph(self, pv, simplified=True, killing_edges=False, excluding_types=None):
        """
        Get a subgraph from the data graph or the simplified data graph that starts from node pv.

        :param ProgramVariable pv: The starting point of the subgraph.
        :param bool simplified: When True, the simplified data graph is used, otherwise the data graph is used.
        :param bool killing_edges: Are killing edges included or not.
        :param iterable excluding_types: Excluding edges whose types are among those excluded types.
        :return: A subgraph.
        :rtype: networkx.MultiDiGraph
        """

        result = networkx.MultiDiGraph()
        result.add_node(pv)

        base_graph = self.simplified_data_graph if simplified else self.data_graph
        if pv not in base_graph:
            return result

        # traverse all edges and add them to the result graph if needed
        queue = [ pv ]
        traversed = set()
        while queue:
            elem = queue[0]
            queue = queue[1:]
            if elem in traversed:
                continue
            traversed.add(elem)

            out_edges = base_graph.out_edges(elem, data=True)

            if not killing_edges:
                # remove killing edges
                out_edges = [ (a, b, data) for a, b, data in out_edges if 'type' not in data or data['type'] != 'kill']

            if excluding_types:
                out_edges = [ (a, b, data) for a, b, data in out_edges if
                              'type' not in data or data['type'] not in excluding_types
                              ]

            for src, dst, data in out_edges:
                result.add_edge(src, dst, **data)

                if dst not in traversed:
                    queue.append(dst)

        return result

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

        worklist = []
        worklist_set = set()

        # initial nodes are those nodes in CFG that has no in-degrees
        for n in self._cfg.graph.nodes_iter():
            if self._cfg.graph.in_degree(n) == 0:
                # Put it into the worklist
                job = DDGJob(n, 0)
                self._worklist_append(job, worklist, worklist_set)

        # A dict storing defs set
        # DDGJob -> LiveDefinition
        live_defs_per_node = {}

        while worklist:
            # Pop out a node
            ddg_job = worklist[0]
            node, call_depth = ddg_job.cfg_node, ddg_job.call_depth
            worklist = worklist[ 1 : ]
            worklist_set.remove(node)

            # Grab all final states. There are usually more than one (one state for each successor), and we gotta
            # process all of them
            final_states = node.final_states

            if node in live_defs_per_node:
                live_defs = live_defs_per_node[node]
            else:
                live_defs = LiveDefinitions()
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

                new_defs = self._track(state, live_defs, node.irsb.statements if node.irsb is not None else None)

                #corresponding_successors = [n for n in successing_nodes if
                #                            not state.ip.symbolic and n.addr == state.se.any_int(state.ip)]
                #if not corresponding_successors:
                #    continue

                changed = False

                for successing_node in successing_nodes:

                    if (state.scratch.jumpkind == 'Ijk_Call' or state.scratch.jumpkind.startswith('Ijk_Sys')) and \
                            (state.ip.symbolic or successing_node.addr != state.se.any_int(state.ip)):
                        # this might be the block after the call, and we are not tracing into the call
                        # TODO: make definition killing architecture independent and calling convention independent
                        filtered_defs = LiveDefinitions()
                        for variable, locs in new_defs.iteritems():
                            if isinstance(variable, SimRegisterVariable):
                                if variable.reg in (self.project.arch.registers['eax'][0],
                                                    self.project.arch.registers['ecx'][0],
                                                    self.project.arch.registers['edx'][0]):
                                    continue

                            filtered_defs.add_defs(variable, locs)

                        new_defs = filtered_defs

                    if successing_node in live_defs_per_node:
                        defs_for_next_node = live_defs_per_node[successing_node]
                    else:
                        defs_for_next_node = LiveDefinitions()
                        live_defs_per_node[successing_node] = defs_for_next_node

                    for var, code_loc_set in new_defs.iteritems():
                        l.debug("Adding %d new defitions for variable %s.", len(code_loc_set), var)
                        changed |= defs_for_next_node.add_defs(var, code_loc_set)

                if changed:
                    if (self._call_depth is None) or \
                            (self._call_depth is not None and 0 <= new_call_depth <= self._call_depth):
                        # Put all reachable successors back to our worklist again
                        for successing_node in successing_nodes:
                            nw = DDGJob(successing_node, new_call_depth)
                            self._worklist_append(nw, worklist, worklist_set)

    def _track(self, state, live_defs, statements):
        """
        Given all live definitions prior to this program point, track the changes, and return a new list of live
        definitions. We scan through the action list of the new state to track the changes.

        :param state:       The input state at that program point.
        :param live_defs:   A list of all live definitions prior to reaching this program point.
        :param list statements: A list of VEX statements.
        :returns:           A list of new live definitions.
        """

        # Make a copy of live_defs
        live_defs = live_defs.copy()

        action_list = list(state.log.actions)

        # Since all temporary variables are local, we simply track them in a local dict
        temp_defs = { }
        temp_variables = { }
        temp_register_symbols = { }

        # All dependence edges are added to the graph either at the end of this method, or when they are going to be
        # overwritten by a new edge. This is because we sometimes have to modify a previous edge (e.g. add new labels
        # to the edge)
        temps_to_edges = defaultdict(list)
        regs_to_edges = defaultdict(list)

        last_statement_id = None
        pv_read = None  # program variables read out in the same statement. we keep a copy of those variables here so
                        # we can link it to the tmp_write action right afterwards
        data_generated = None

        # tracks stack pointer and base pointer
        #sp = state.se.any_int(state.regs.sp) if not state.regs.sp.symbolic else None
        #bp = state.se.any_int(state.regs.bp) if not state.regs.bp.symbolic else None

        for a in action_list:

            if last_statement_id is None or last_statement_id != a.stmt_idx:
                pv_read = [ ]
                data_generated = None
                last_statement_id = a.stmt_idx

            if a.sim_procedure is None:
                current_code_location = CodeLocation(a.bbl_addr, a.stmt_idx, ins_addr=a.ins_addr)
            else:
                current_code_location = CodeLocation(None, None, sim_procedure=a.sim_procedure)

            if a.type == "mem":
                if a.actual_addrs is None:
                    # For now, mem reads don't necessarily have actual_addrs set properly
                    try:
                        addr_list = { state.se.any_int(a.addr.ast) }
                    except (SimSolverModeError, SimUnsatError, ZeroDivisionError):
                        # FIXME: ZeroDivisionError should have been caught by claripy and simuvex.
                        # FIXME: see claripy issue #75. this is just a temporary workaround.
                        # it's symbolic... just continue
                        addr_list = { 0x60000000 }  # TODO: this is a random address that I pick. Fix it.
                else:
                    addr_list = set(a.actual_addrs)

                for addr in addr_list:

                    variable = None
                    if len(addr_list) == 1 and len(a.addr.tmp_deps) == 1:
                        addr_tmp = list(a.addr.tmp_deps)[0]
                        if addr_tmp in temp_register_symbols:
                            # it must be a stack variable
                            sort, offset = temp_register_symbols[addr_tmp]
                            variable = SimStackVariable(offset, a.data.ast.size() / 8, base=sort, base_addr=addr - offset)

                    if variable is None:
                        variable = SimMemoryVariable(addr, a.data.ast.size() / 8)  # TODO: Properly unpack the SAO

                    pvs = [ ]

                    if a.action == "read":
                        # Create an edge between def site and use site

                        prevdefs = self._def_lookup(live_defs, variable)

                        # TODO: prevdefs should only contain location, not labels
                        for prev_code_loc, labels in prevdefs.iteritems():
                            self._stmt_graph_add_edge(prev_code_loc, current_code_location, **labels)

                            pvs.append(ProgramVariable(variable, prev_code_loc))

                        if not pvs:
                            pvs.append(ProgramVariable(variable, current_code_location, initial=True))
                            # make sure to put it into the killing set
                            self._kill(live_defs, variable, current_code_location)

                        for pv in pvs:
                            pv_read.append(pv)

                    if a.action == "write":
                        # Kill the existing live def
                        self._kill(live_defs, variable, current_code_location)

                        pvs.append(ProgramVariable(variable, current_code_location))

                    for pv in pvs:
                        # For each of its register dependency and data dependency, we annotate the corresponding edge
                        for reg_offset in a.addr.reg_deps:
                            self._stmt_graph_annotate_edges(regs_to_edges[reg_offset], subtype='mem_addr')
                            reg_variable = SimRegisterVariable(reg_offset, self._get_register_size(reg_offset))
                            prev_defs = self._def_lookup(live_defs, reg_variable)
                            for loc, _ in prev_defs.iteritems():
                                v = ProgramVariable(reg_variable, loc)
                                self._data_graph_add_edge(v, pv, type='mem_addr')

                        for tmp in a.addr.tmp_deps:
                            self._stmt_graph_annotate_edges(temps_to_edges[tmp], subtype='mem_addr')
                            if tmp in temp_variables:
                                self._data_graph_add_edge(temp_variables[tmp], pv, type='mem_addr')

                        for reg_offset in a.data.reg_deps:
                            self._stmt_graph_annotate_edges(regs_to_edges[reg_offset], subtype='mem_data')
                            reg_variable = SimRegisterVariable(reg_offset, self._get_register_size(reg_offset))
                            prev_defs = self._def_lookup(live_defs, reg_variable)
                            for loc, _ in prev_defs.iteritems():
                                v = ProgramVariable(reg_variable, loc)
                                self._data_graph_add_edge(v, pv, type='mem_data')

                        for tmp in a.data.tmp_deps:
                            self._stmt_graph_annotate_edges(temps_to_edges[tmp], subtype='mem_data')
                            if tmp in temp_variables:
                                self._data_graph_add_edge(temp_variables[tmp], pv, type='mem_data')

            elif a.type == 'reg':
                # TODO: Support symbolic register offsets

                reg_offset = a.offset
                variable = SimRegisterVariable(reg_offset, a.data.ast.size() / 8)

                if a.action == 'read':
                    # What do we want to do?
                    prevdefs = self._def_lookup(live_defs, variable)

                    # add edges to the statement dependence graph
                    for prev_code_loc, labels in prevdefs.iteritems():
                        self._stmt_graph_add_edge(prev_code_loc, current_code_location, **labels)
                        # record the edge
                        edge_tuple = (prev_code_loc, current_code_location)
                        regs_to_edges[reg_offset].append(edge_tuple)

                        pv_read.append(ProgramVariable(variable, prev_code_loc))

                    if not prevdefs:
                        # the register was never defined before - it must be passed in as an argument
                        pv_read.append(ProgramVariable(variable, current_code_location, initial=True))
                        # make sure to put it into the killing set
                        self._kill(live_defs, variable, current_code_location)

                    if reg_offset == self.project.arch.sp_offset:
                        data_generated = ('sp', 0)
                    elif reg_offset == self.project.arch.bp_offset:
                        data_generated = ('bp', 0)

                else:
                    # write
                    self._kill(live_defs, variable, current_code_location)

                    if reg_offset in regs_to_edges:
                        # clear the existing edges definition
                        del regs_to_edges[reg_offset]

                    # add a node on the data dependence graph
                    pv = ProgramVariable(variable, current_code_location)
                    self._data_graph_add_node(pv)

                    if not a.reg_deps and not a.tmp_deps:
                        # moving a constant into the register
                        # try to parse out the constant from statement
                        const_variable = SimConstantVariable()
                        if statements is not None:
                            stmt = statements[a.stmt_idx]
                            if isinstance(stmt.data, pyvex.IRExpr.Const):
                                const_variable = SimConstantVariable(value=stmt.data.con.value)
                        const_pv = ProgramVariable(const_variable, current_code_location)
                        self._data_graph_add_edge(const_pv, pv)

                    for tmp in a.tmp_deps:
                        if tmp in temp_variables:
                            self._data_graph_add_edge(temp_variables[tmp], pv)

            elif a.type == 'tmp':
                # tmp is definitely not symbolic
                tmp = a.tmp
                pv = ProgramVariable(SimTemporaryVariable(tmp), current_code_location)

                if a.action == 'read':
                    prev_code_loc = temp_defs[tmp]

                    self._stmt_graph_add_edge(prev_code_loc, current_code_location, type='tmp', data=a.tmp)
                    # record the edge
                    edge_tuple = (prev_code_loc, current_code_location)
                    temps_to_edges[a.tmp].append(edge_tuple)

                    if tmp in temp_register_symbols:
                        data_generated = temp_register_symbols[tmp]

                else:
                    # write
                    temp_defs[tmp] = current_code_location
                    temp_variables[tmp] = pv

                    # clear existing edges
                    if tmp in temps_to_edges:
                        del temps_to_edges[tmp]

                    for tmp_dep in a.tmp_deps:
                        if tmp_dep in temp_variables:
                            self._data_graph_add_edge(temp_variables[tmp_dep], pv)

                    if data_generated:
                        temp_register_symbols[tmp] = data_generated

                    for data in pv_read:
                        self._data_graph_add_edge(data, pv)

                    if not a.tmp_deps and not pv_read:
                        # read in a constant
                        # try to parse out the constant from statement
                        const_variable = SimConstantVariable()
                        if statements is not None:
                            stmt = statements[a.stmt_idx]
                            if isinstance(stmt, pyvex.IRStmt.Dirty):
                                l.warning('Dirty statements are not supported in DDG for now.')
                            elif isinstance(stmt.data, pyvex.IRExpr.Const):
                                const_variable = SimConstantVariable(value=stmt.data.con.value)
                        const_pv = ProgramVariable(const_variable, current_code_location)
                        self._data_graph_add_edge(const_pv, pv)

            elif a.type == 'exit':
                # exits should only depend on tmps
                for tmp in a.tmp_deps:
                    prev_code_loc = temp_defs[tmp]

                    # add the edge to the graph
                    self._stmt_graph_add_edge(prev_code_loc, current_code_location, type='exit', data='tmp')

                    # log the edge
                    edge_tuple = (prev_code_loc, current_code_location)
                    temps_to_edges[tmp].append(edge_tuple)

            elif a.type == 'operation':
                # FIXME: we should support a more complete range of operations

                if a.op.endswith('Sub32') or a.op.endswith('Sub64'):
                    # subtract
                    expr_0, expr_1 = a.exprs

                    if expr_0.tmp_deps and (not expr_1.tmp_deps and not expr_1.reg_deps):
                        # tmp - const
                        tmp = list(expr_0.tmp_deps)[0]
                        if tmp in temp_register_symbols:
                            sort, offset = temp_register_symbols[tmp]
                            offset -= expr_1.ast.args[0]
                            data_generated = (sort, offset)

                elif a.op.endswith('Add32') or a.op.endswith('Add64'):
                    # add
                    expr_0, expr_1 = a.exprs

                    if expr_0.tmp_deps and (not expr_1.tmp_deps and not expr_1.reg_deps):
                        # tmp + const
                        tmp = list(expr_0.tmp_deps)[0]
                        if tmp in temp_register_symbols:
                            sort, offset = temp_register_symbols[tmp]
                            offset += expr_1.ast.args[0]
                            data_generated = (sort, offset)

        #import pprint
        #pprint.pprint(self._data_graph.edges())
        #pprint.pprint(self.simplified_data_graph.edges())
        # import ipdb; ipdb.set_trace()

        return live_defs

    def _def_lookup(self, live_defs, variable):  # pylint:disable=no-self-use
        """
        This is a backward lookup in the previous defs. Note that, as we are using VSA, it is possible that `variable`
        is affected by several definitions.

        :param LiveDefinitions live_defs: The collection of live definitions.
        :param SimVariable: The variable to lookup for definitions.
        :returns:           A dict {stmt:labels} where label is the number of individual addresses of `addr_list` (or
                            the actual set of addresses depending on the keep_addrs flag) that are definted by stmt.
        """

        prevdefs = {}

        for code_loc in live_defs.lookup_defs(variable):
            # Label edges with cardinality or actual sets of addresses
            if isinstance(variable, SimMemoryVariable):
                type_ = 'mem'
            elif isinstance(variable, SimRegisterVariable):
                type_ = 'reg'
            else:
                raise AngrDDGError('Unknown variable type %s' % type(variable))

            prevdefs[code_loc] = {
                'type': type_,
                'data': variable
            }

        return prevdefs

    def _kill(self, live_defs, variable, code_loc):  # pylint:disable=no-self-use
        """
        Kill previous defs. addr_list is a list of normalized addresses.
        """

        # Case 1: address perfectly match, we kill
        # Case 2: a is a subset of the original address
        # Case 3: a is a superset of the original address

        # the previous definition is killed. mark it in data graph.

        if variable in live_defs:
            for loc in live_defs.lookup_defs(variable):
                pv = ProgramVariable(variable, loc)
                self._data_graph_add_edge(pv, ProgramVariable(variable, code_loc), type='kill')

        live_defs.kill_def(variable, code_loc)

    def _get_register_size(self, reg_offset):
        """
        Get the size of a register.

        :param int reg_offset: Offset of the register.
        :return: Size in bytes.
        :rtype: int
        """

        # TODO: support registers that are not aligned
        if reg_offset in self.project.arch.register_names:
            reg_name = self.project.arch.register_names[reg_offset]
            reg_size = self.project.arch.registers[reg_name][1]
            return reg_size

        l.warning("_get_register_size(): unsupported register offset %d. Assum size 1. "
                  "More register name mappings should be implemented in archinfo.", reg_offset)
        return 1

    def _data_graph_add_node(self, node):
        """
        Add a noe in the data dependence graph.

        :param ProgramVariable node: The node to add.
        :return: None
        """

        self._data_graph.add_node(node)

        self._simplified_data_graph = None

    def _data_graph_add_edge(self, src, dst, **edge_labels):
        """
        Add an edge in the data dependence graph.

        :param ProgramVariable src: Source node.
        :param ProgramVariable dst: Destination node.
        :param edge_labels: All labels associated with the edge.
        :return: None
        """

        if src in self._data_graph and dst in self._data_graph[src]:
            return

        self._data_graph.add_edge(src, dst, **edge_labels)

        self._simplified_data_graph = None

    def _stmt_graph_add_edge(self, src, dst, **edge_labels):
        """
        Add an edge in the statement dependence graph from a program location `src` to another program location `dst`.

        :param CodeLocation src: Source node.
        :param CodeLocation dst: Destination node.
        :param edge_labels: All labels associated with the edge.
        :returns: None
        """

        # Is that edge already in the graph ?
        # If at least one is new, then we are not redoing the same path again
        if src in self._stmt_graph and dst in self._stmt_graph[src]:
            return

        self._stmt_graph.add_edge(src, dst, **edge_labels)

    def _stmt_graph_annotate_edges(self, edges_to_annotate, **new_labels):
        """
        Add new annotations to edges in the statement dependence graph.

        :param list edges_to_annotate:      A list of edges to annotate.
        :param new_labels:  New labels to be added to those edges.
        :returns: None
        """

        graph = self.graph

        for src, dst in edges_to_annotate:

            if src not in graph:
                continue
            if dst not in graph[src]:
                continue

            data = graph[src][dst]

            for k, v in new_labels.iteritems():
                if k in data:
                    data[k] = data[k] + (v,)
                else:
                    # Construct a tuple
                    data[k] = (v,)

    def _simplify_data_graph(self, data_graph):  # pylint:disable=no-self-use
        """
        Simplify a data graph by removing all temp variable nodes on the graph.

        :param networkx.DiGraph data_graph: The data dependence graph to simplify.
        :return: The simplified graph.
        :rtype: networkx.MultiDiGraph
        """

        graph = networkx.MultiDiGraph(data_graph)

        all_nodes = [ n for n in graph.nodes_iter() if isinstance(n.variable, SimTemporaryVariable) ]

        for tmp_node in all_nodes:
            # remove each tmp node by linking their successors and predecessors directly
            in_edges = graph.in_edges(tmp_node, data=True)
            out_edges = graph.out_edges(tmp_node, data=True)

            for pred, _, _ in in_edges:
                graph.remove_edge(pred, tmp_node)
            for _, suc, _ in out_edges:
                graph.remove_edge(tmp_node, suc)

            for pred, _, data_in in in_edges:
                for _, suc, data_out in out_edges:
                    if pred is not tmp_node and suc is not tmp_node:
                        data = data_in.copy()
                        data.update(data_out)
                        graph.add_edge(pred, suc, **data)

            graph.remove_node(tmp_node)

        return graph

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
                            new_nw = DDGJob(dst, call_depth + 1)
                            worklist.append(new_nw)
                            worklist_set.add(dst)
                            stack.append(new_nw)
                    elif data['jumpkind'] == 'Ijk_Ret':
                        if call_depth > 0:
                            inserted.add(dst)
                            new_nw = DDGJob(dst, call_depth - 1)
                            worklist.append(new_nw)
                            worklist_set.add(dst)
                            stack.append(new_nw)
                    else:
                        new_nw = DDGJob(dst, call_depth)
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
        for _, func in self.kb.functions.iteritems():
            for block in func.blocks:
                simrun_addr_to_func[block.addr] = func

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
