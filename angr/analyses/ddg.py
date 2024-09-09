from __future__ import annotations
import logging
from collections import defaultdict

import networkx
import pyvex
from . import Analysis

from ..code_location import CodeLocation
from ..errors import SimSolverModeError, SimUnsatError, AngrDDGError
from ..sim_variable import (
    SimRegisterVariable,
    SimMemoryVariable,
    SimTemporaryVariable,
    SimConstantVariable,
    SimStackVariable,
)

l = logging.getLogger(name=__name__)


class AST:
    """
    A mini implementation for AST
    """

    def __init__(self, op, *operands):
        self.op = op
        self.operands = tuple(operands)

    def __hash__(self):
        return hash((self.op, self.operands))

    def __eq__(self, other):
        return type(other) is AST and other.op == self.op and other.operands == self.operands

    def __repr__(self):
        def _short_repr(a):
            return a.short_repr

        if len(self.operands) == 1:
            return f"{self.op}{_short_repr(self.operands[0])}"
        if len(self.operands) == 2:
            return f"{_short_repr(self.operands[0])} {self.op} {_short_repr(self.operands[1])}"
        return f"{self.op} ({self.operands})"


class ProgramVariable:
    """
    Describes a variable in the program at a specific location.

    :ivar SimVariable variable: The variable.
    :ivar CodeLocation location: Location of the variable.
    """

    def __init__(self, variable, location, initial=False, arch=None):
        self.variable = variable
        self.location = location
        self.initial = initial
        self._arch = arch  # for pretty printing

    def __hash__(self):
        return hash((self.variable, self.location))

    def __eq__(self, other):
        if not isinstance(other, ProgramVariable):
            return False

        return self.variable == other.variable and self.location == other.location

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        if self._arch is not None:
            s = f"{{{self.variable} @ {self.location}}}"
        else:
            s = f"{{{self.variable} @ {self.location}}}"
        return s

    @property
    def short_repr(self):
        if self._arch is not None:
            s = f"{{{self.variable}@{self.location.short_repr}}}"
        else:
            s = f"{{{self.variable}@{self.location.short_repr}}}"
        return s


class DDGJob:
    def __init__(self, cfg_node, call_depth):
        self.cfg_node = cfg_node
        self.call_depth = call_depth

    def __repr__(self):
        return "<DDGJob %s, call_depth %d>" % (self.cfg_node, self.call_depth)


class LiveDefinitions:
    """
    A collection of live definitions with some handy interfaces for definition killing and lookups.
    """

    def __init__(self):
        """
        Constructor.
        """

        # byte-to-byte mappings
        # TODO: make it copy-on-write in order to save memory.
        # TODO: options are either collections.ChainMap or a modified version of simuvex.SimPagedMemory
        self._memory_map = defaultdict(set)
        self._register_map = defaultdict(set)
        self._defs = defaultdict(set)

    #
    # Overridden methods
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
        :rtype: angr.analyses.ddg.LiveDefinitions
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
        :rtype: angr.analyses.ddg.LiveDefinitions
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
        :param CodeLocation location: Location of the variable being defined.
        :param int size_threshold: The maximum bytes to consider for the variable.
        :return: True if the definition was new, False otherwise
        :rtype: bool
        """

        new_defs_added = False

        if isinstance(variable, SimRegisterVariable):
            if variable.reg is None:
                l.warning("add_def: Got a None for a SimRegisterVariable. Consider fixing.")
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
                l.warning("kill_def: Got a None for a SimRegisterVariable. Consider fixing.")
                return

            size = min(variable.size, size_threshold)
            offset = variable.reg
            while offset < variable.reg + size:
                self._register_map[offset] = {location}
                offset += 1

            self._defs[variable] = {location}

        elif isinstance(variable, SimMemoryVariable):
            size = min(variable.size, size_threshold)
            offset = variable.addr
            while offset < variable.addr + size:
                self._memory_map[offset] = {location}
                offset += 1

            self._defs[variable] = {location}

        else:
            l.error('Unsupported variable type "%s".', type(variable))

    def lookup_defs(self, variable, size_threshold=32):
        """
        Find all definitions of the variable.

        :param SimVariable variable: The variable to lookup for.
        :param int size_threshold: The maximum bytes to consider for the variable. For example, if the variable is 100
                                   byte long, only the first `size_threshold` bytes are considered.
        :return: A set of code locations where the variable is defined.
        :rtype: set
        """

        live_def_locs = set()

        if isinstance(variable, SimRegisterVariable):
            if variable.reg is None:
                l.warning("lookup_defs: Got a None for a SimRegisterVariable. Consider fixing.")
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

    def items(self):
        """
        An iterator that returns all live definitions.

        :return: The iterator.
        :rtype: iter
        """

        return self._defs.items()

    def itervariables(self):
        """
        An iterator that returns all live variables.

        :return: The iterator.
        :rtype: iter
        """

        return self._defs.keys()


class DDGViewItem:
    def __init__(self, ddg, variable, simplified=False):
        self._ddg = ddg
        self._variable = variable
        self._simplified = simplified

    @property
    def depends_on(self):
        graph = self._ddg.simplified_data_graph if self._simplified else self._ddg.data_graph
        if self._variable in graph:
            return [
                self._to_viewitem(n)
                for n, _, data in graph.in_edges(self._variable, data=True)
                if data.get("type", None) != "kill"
            ]
        return None

    @property
    def dependents(self):
        graph = self._ddg.simplified_data_graph if self._simplified else self._ddg.data_graph
        if self._variable in graph:
            return [
                self._to_viewitem(n)
                for _, n, data in graph.in_edges(self._variable, data=True)
                if data.get("type", None) != "kill"
            ]
        return None

    def __repr__(self):
        return "[%s, %d dependents, depends on %d]" % (
            self._variable,
            len(self.dependents),
            len(self.depends_on),
        )

    def __eq__(self, other):
        return (
            isinstance(other, DDGViewItem)
            and self._variable == other._variable
            and self._simplified == other._simplified
        )

    def __hash__(self):
        return hash(
            (
                self._ddg,
                self._variable,
                self._simplified,
            )
        )

    def _to_viewitem(self, prog_var):
        """
        Convert a ProgramVariable instance to a DDGViewItem object.

        :param ProgramVariable prog_var: The ProgramVariable object to convert.
        :return:                         The converted DDGViewItem object.
        :rtype:                          DDGViewItem
        """

        return DDGViewItem(self._ddg, prog_var, simplified=self._simplified)


class DDGViewInstruction:
    def __init__(self, cfg, ddg, insn_addr, simplified=False):
        self._cfg = cfg
        self._ddg = ddg
        self._insn_addr = insn_addr
        self._simplified = simplified

        # shorthand
        self._project = self._ddg.project

    def __getitem__(self, key):
        arch = self._project.arch
        if key in arch.registers:
            # it's a register name
            reg_offset, size = arch.registers[key]

            # obtain the CFGNode
            cfg_node = self._cfg.model.get_any_node(self._insn_addr, anyaddr=True)
            if cfg_node is None:
                # not found
                raise KeyError(f"CFGNode for instruction {self._insn_addr:#x} is not found.")

            # determine the statement ID
            vex_block = self._project.factory.block(
                cfg_node.addr, size=cfg_node.size, opt_level=self._cfg._iropt_level
            ).vex
            stmt_idx = None
            insn_addr = cfg_node.addr
            for i, stmt in enumerate(vex_block.statements):
                if isinstance(stmt, pyvex.IRStmt.IMark):
                    insn_addr = stmt.addr + stmt.delta
                elif insn_addr == self._insn_addr:
                    if isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == reg_offset:
                        stmt_idx = i
                        break
                elif insn_addr > self._insn_addr:
                    break

            if stmt_idx is None:
                raise KeyError("Cannot find the statement.")

            # create a program variable
            variable = SimRegisterVariable(reg_offset, size)
            location = CodeLocation(cfg_node.addr, stmt_idx, ins_addr=self._insn_addr)
            pv = ProgramVariable(variable, location, arch=self._project.arch)

            return DDGViewItem(self._ddg, pv, simplified=self._simplified)
        return None

    @property
    def definitions(self) -> list[DDGViewItem]:
        """
        Get all definitions located at the current instruction address.

        :return: A list of ProgramVariable instances.
        """

        defs = set()

        graph = self._ddg.simplified_data_graph if self._simplified else self._ddg.data_graph

        n: ProgramVariable
        for n in graph.nodes():
            if n.location.ins_addr == self._insn_addr:
                defs.add(DDGViewItem(self._ddg, n, simplified=self._simplified))

        return list(defs)


class DDGView:
    """
    A view of the data dependence graph.
    """

    def __init__(self, cfg, ddg, simplified=False):
        self._cfg = cfg
        self._ddg = ddg
        self._simplified = simplified

        # shorthand
        self._project = self._ddg.project

    def __getitem__(self, key):
        if isinstance(key, int):
            # instruction address
            return DDGViewInstruction(self._cfg, self._ddg, key, simplified=self._simplified)
        return None


class DDG(Analysis):
    """
    This is a fast data dependence graph directly generated from our CFG analysis result. The only reason for its
    existence is the speed. There is zero guarantee for being sound or accurate. You are supposed to use it only when
    you want to track the simplest data dependence, and you do not care about soundness or accuracy.

    For a better data dependence graph, please consider performing a better static analysis first (like Value-set
    Analysis), and then construct a dependence graph on top of the analysis result (for example, the VFG in angr).

    The DDG is based on a CFG, which should ideally be a CFGEmulated generated with the following options:

      - keep_state=True to keep all input states
      - state_add_options=angr.options.refs to store memory, register, and temporary value accesses

    You may want to consider a high value for context_sensitivity_level as well when generating the CFG.

    Also note that since we are using states from CFG, any improvement in analysis performed on CFG (like a points-to
    analysis) will directly benefit the DDG.
    """

    def __init__(self, cfg, start=None, call_depth=None, block_addrs=None):
        """
        :param cfg:         Control flow graph. Please make sure each node has an associated `state` with it, e.g. by
                            passing the keep_state=True and state_add_options=angr.options.refs arguments to
                            CFGEmulated.
        :param start:       An address, Specifies where we start the generation of this data dependence graph.
        :param call_depth:  None or integers. A non-negative integer specifies how deep we would like to track in the
                            call tree. None disables call_depth limit.
        :param iterable or None block_addrs: A collection of block addresses that the DDG analysis should be performed
                                             on.
        """

        # Sanity check
        if not cfg._keep_state:
            raise AngrDDGError('CFG must have "keep_state" set to True.')

        self._cfg = cfg
        self._start = self.project.entry if start is None else start
        self._call_depth = call_depth
        self._block_addrs = block_addrs

        # analysis output
        self._stmt_graph = networkx.DiGraph()
        self._data_graph = networkx.DiGraph()
        self._simplified_data_graph = None

        self._ast_graph = networkx.DiGraph()  # A mapping of ProgramVariable to ASTs

        self._symbolic_mem_ops = set()

        # Data dependency graph per function
        self._function_data_dependencies = None

        self.view = DDGView(self._cfg, self, simplified=False)
        self.simple_view = DDGView(self._cfg, self, simplified=True)

        # Local variables
        self._live_defs = None
        self._temp_variables = None
        self._temp_register_symbols = None
        self._temp_edges = None
        self._temp_register_symbols = None
        self._variables_per_statement = None
        self._custom_data_per_statement = None
        self._register_edges = None

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

    @property
    def ast_graph(self):
        return self._ast_graph

    #
    # Public methods
    #

    def pp(self):
        """
        Pretty printing.
        """
        # TODO: make it prettier
        for src, dst, data in self.graph.edges(data=True):
            print(f"{src} <-- {dst}, {data}")

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
        queue = [pv]
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
                out_edges = [(a, b, data) for a, b, data in out_edges if "type" not in data or data["type"] != "kill"]

            if excluding_types:
                out_edges = [
                    (a, b, data)
                    for a, b, data in out_edges
                    if "type" not in data or data["type"] not in excluding_types
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

        # Initialize the worklist
        if self._start is None:
            # initial nodes are those nodes in CFG that has no in-degrees
            for n in self._cfg.graph.nodes():
                if self._cfg.graph.in_degree(n) == 0:
                    # Put it into the worklist
                    job = DDGJob(n, 0)
                    self._worklist_append(job, worklist, worklist_set)
        else:
            for n in self._cfg.model.get_all_nodes(self._start):
                job = DDGJob(n, 0)
                self._worklist_append(job, worklist, worklist_set)

        # A dict storing defs set
        # DDGJob -> LiveDefinition
        live_defs_per_node = {}

        while worklist:
            # Pop out a node
            ddg_job = worklist[0]
            l.debug("Processing %s.", ddg_job)
            node, call_depth = ddg_job.cfg_node, ddg_job.call_depth
            worklist = worklist[1:]
            worklist_set.remove(node)

            # Grab all final states. There are usually more than one (one state for each successor), and we gotta
            # process all of them
            final_states = node.final_states

            if node in live_defs_per_node:
                live_defs = live_defs_per_node[node]
            else:
                live_defs = LiveDefinitions()
                live_defs_per_node[node] = live_defs

            successing_nodes = list(self._cfg.graph.successors(node))

            # try to assign every final state to a successor and vice versa
            match_suc = defaultdict(bool)
            match_state = defaultdict(set)

            for suc in successing_nodes:
                matched = False
                for state in final_states:
                    try:
                        if state.solver.eval(state.ip) == suc.addr:
                            match_suc[suc.addr] = True
                            match_state[state].add(suc)
                            matched = True
                    except (SimUnsatError, SimSolverModeError, ZeroDivisionError):
                        # ignore
                        matched = matched
                if not matched:
                    break

            # whether all final states could be matched to a successor and vice versa
            matches = len(match_suc) == len(successing_nodes) and len(match_state) == len(final_states)

            for state in final_states:
                if state.history.jumpkind == "Ijk_FakeRet" and len(final_states) > 1:
                    # Skip fakerets if there are other control flow transitions available
                    continue

                new_call_depth = call_depth
                if state.history.jumpkind == "Ijk_Call":
                    new_call_depth += 1
                elif state.history.jumpkind == "Ijk_Ret":
                    new_call_depth -= 1

                if self._call_depth is not None and call_depth > self._call_depth:
                    l.debug("Do not trace into %s due to the call depth limit", state.ip)
                    continue

                new_defs = self._track(state, live_defs, node.irsb.statements if node.irsb is not None else None)

                # corresponding_successors = [n for n in successing_nodes if
                #                            not state.ip.symbolic and n.addr == state.solver.eval(state.ip)]
                # if not corresponding_successors:
                #    continue

                changed = False

                # if every successor can be matched with one or more final states (by IP address),
                # only take over the LiveDefinition of matching states
                add_state_to_sucs = match_state[state] if matches else successing_nodes

                for successing_node in add_state_to_sucs:
                    if (state.history.jumpkind == "Ijk_Call" or state.history.jumpkind.startswith("Ijk_Sys")) and (
                        state.ip.symbolic or successing_node.addr != state.solver.eval(state.ip)
                    ):
                        suc_new_defs = self._filter_defs_at_call_sites(new_defs)
                    else:
                        suc_new_defs = new_defs

                    if successing_node in live_defs_per_node:
                        defs_for_next_node = live_defs_per_node[successing_node]
                    else:
                        defs_for_next_node = LiveDefinitions()
                        live_defs_per_node[successing_node] = defs_for_next_node

                    for var, code_loc_set in suc_new_defs.items():
                        # l.debug("Adding %d new definitions for variable %s.", len(code_loc_set), var)
                        changed |= defs_for_next_node.add_defs(var, code_loc_set)

                if changed and (
                    (self._call_depth is None)
                    or (self._call_depth is not None and 0 <= new_call_depth <= self._call_depth)
                ):
                    # Put all reachable successors back to our work-list again
                    for successor in self._cfg.model.get_all_successors(node):
                        nw = DDGJob(successor, new_call_depth)
                        self._worklist_append(nw, worklist, worklist_set)

    def _track(self, state, live_defs, statements):
        """
        Given all live definitions prior to this program point, track the changes, and return a new list of live
        definitions. We scan through the action list of the new state to track the changes.

        :param state:           The input state at that program point.
        :param live_defs:       All live definitions prior to reaching this program point.
        :param list statements: A list of VEX statements.
        :returns:               A list of new live definitions.
        :rtype:                 angr.analyses.ddg.LiveDefinitions
        """

        # Make a copy of live_defs
        self._live_defs = live_defs.copy()

        action_list = list(state.history.recent_actions)

        # Since all temporary variables are local, we simply track them in a dict
        self._temp_variables = {}
        self._temp_register_symbols = {}

        # All dependence edges are added to the graph either at the end of this method, or when they are going to be
        # overwritten by a new edge. This is because we sometimes have to modify a previous edge (e.g. add new labels
        # to the edge)
        self._temp_edges = defaultdict(list)
        self._register_edges = defaultdict(list)

        last_statement_id = None
        self._variables_per_statement = (
            None  # program variables read out in the same statement. we keep a copy of those variables here so
        )
        # we can link it to the tmp_write action right afterwards
        self._custom_data_per_statement = None

        for a in action_list:
            if last_statement_id is None or last_statement_id != a.stmt_idx:
                # update statement ID
                last_statement_id = a.stmt_idx
                statement = (
                    statements[last_statement_id] if statements and last_statement_id < len(statements) else None
                )

                # initialize all per-statement data structures
                self._variables_per_statement = []
                self._custom_data_per_statement = None

            if a.sim_procedure is None:
                current_code_location = CodeLocation(a.bbl_addr, a.stmt_idx, ins_addr=a.ins_addr)
            else:
                current_code_location = CodeLocation(None, None, sim_procedure=a.sim_procedure)

            if a.type == "exit":
                self._handle_exit(a, current_code_location, state, statement)
            elif a.type == "operation":
                self._handle_operation(a, current_code_location, state, statement)
            elif a.type == "constraint":
                pass
            else:
                handler_name = f"_handle_{a.type}_{a.action}"
                if hasattr(self, handler_name):
                    getattr(self, handler_name)(a, current_code_location, state, statement)
                else:
                    l.debug("Skip an unsupported action %s.", a)

        return self._live_defs

    def _def_lookup(self, variable):  # pylint:disable=no-self-use
        """
        This is a backward lookup in the previous defs. Note that, as we are using VSA, it is possible that `variable`
        is affected by several definitions.

        :param angr.analyses.ddg.LiveDefinitions live_defs:
                            The collection of live definitions.
        :param SimVariable: The variable to lookup for definitions.
        :returns:           A dict {stmt:labels} where label is the number of individual addresses of `addr_list` (or
                            the actual set of addresses depending on the keep_addrs flag) that are definted by stmt.
        """

        prevdefs = {}

        for code_loc in self._live_defs.lookup_defs(variable):
            # Label edges with cardinality or actual sets of addresses
            if isinstance(variable, SimMemoryVariable):
                type_ = "mem"
            elif isinstance(variable, SimRegisterVariable):
                type_ = "reg"
            else:
                raise AngrDDGError(f"Unknown variable type {type(variable)}")

            prevdefs[code_loc] = {"type": type_, "data": variable}

        return prevdefs

    def _kill(self, variable, code_loc):  # pylint:disable=no-self-use
        """
        Kill previous defs. addr_list is a list of normalized addresses.
        """

        # Case 1: address perfectly match, we kill
        # Case 2: a is a subset of the original address
        # Case 3: a is a superset of the original address

        # the previous definition is killed. mark it in data graph.

        if variable in self._live_defs:
            for loc in self._live_defs.lookup_defs(variable):
                pv = ProgramVariable(variable, loc, arch=self.project.arch)
                self._data_graph_add_edge(pv, ProgramVariable(variable, code_loc, arch=self.project.arch), type="kill")

        self._live_defs.kill_def(variable, code_loc)

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
            return self.project.arch.registers[reg_name][1]

        l.warning(
            "_get_register_size(): unsupported register offset %d. Assume size 1. "
            "More register name mappings should be implemented in archinfo.",
            reg_offset,
        )
        return 1

    #
    # Action handling
    #

    @staticmethod
    def _get_actual_addrs(action, state):
        """
        For memory actions, get a list of addresses it operates on.

        :param SimAction action: The action object to work with.
        :return:                 A list of addresses that are accessed with that action.
        :rtype:                  list
        """

        if action.actual_addrs is None:
            # For now, mem reads don't necessarily have actual_addrs set properly
            try:
                addr_list = {state.solver.eval(action.addr.ast)}
            except (SimSolverModeError, SimUnsatError, ZeroDivisionError):
                # FIXME: ZeroDivisionError should have been caught by claripy and simuvex.
                # FIXME: see claripy issue #75. this is just a temporary workaround.
                # it's symbolic... just continue
                addr_list = {0x60000000}  # TODO: this is a random address that I pick. Fix it.
        else:
            addr_list = set(action.actual_addrs)

        return addr_list

    def _create_memory_variable(self, action, addr, addrs):
        """
        Create a SimStackVariable or SimMemoryVariable based on action objects and its address.

        :param SimAction action: The action to work with.
        :param int addr:         The address of the memory variable in creation.
        :param list addrs:       A list of all addresses that the action was effective on.
        :return:
        """

        variable = None
        if len(addrs) == 1 and len(action.addr.tmp_deps) == 1:
            addr_tmp = next(iter(action.addr.tmp_deps))
            if addr_tmp in self._temp_register_symbols:
                # it must be a stack variable
                sort, offset = self._temp_register_symbols[addr_tmp]
                base_addr = addr - offset
                if base_addr < 0:
                    base_addr += 1 << self.project.arch.bits
                variable = SimStackVariable(offset, action.size.ast // 8, base=sort, base_addr=base_addr)

        if variable is None:
            variable = SimMemoryVariable(addr, action.size.ast // 8)

        return variable

    def _make_edges(self, action, prog_var):
        """

        :param SimAction action:
        :param ProgramVariable prog_var:
        :return:
        """

        # For each of its register dependency and data dependency, we annotate the corresponding edge
        for reg_offset in action.addr.reg_deps:
            self._stmt_graph_annotate_edges(self._register_edges[reg_offset], subtype="mem_addr")
            reg_variable = SimRegisterVariable(reg_offset, self._get_register_size(reg_offset))
            prev_defs = self._def_lookup(reg_variable)
            for loc, _ in prev_defs.items():
                v = ProgramVariable(reg_variable, loc, arch=self.project.arch)
                self._data_graph_add_edge(v, prog_var, type="mem_addr")

        for tmp in action.addr.tmp_deps:
            self._stmt_graph_annotate_edges(self._temp_edges[tmp], subtype="mem_addr")
            if tmp in self._temp_variables:
                self._data_graph_add_edge(self._temp_variables[tmp], prog_var, type="mem_addr")

        if not action.data.reg_deps and not action.data.tmp_deps:
            # might be a constant assignment
            v = action.data.ast
            if not v.symbolic:
                const_var = SimConstantVariable(v.concrete_value)
                const_progvar = ProgramVariable(const_var, prog_var.location)
                self._data_graph_add_edge(const_progvar, prog_var, type="mem_data")

        else:
            for reg_offset in action.data.reg_deps:
                self._stmt_graph_annotate_edges(self._register_edges[reg_offset], subtype="mem_data")
                reg_variable = SimRegisterVariable(reg_offset, self._get_register_size(reg_offset))
                prev_defs = self._def_lookup(reg_variable)
                for loc, _ in prev_defs.items():
                    v = ProgramVariable(reg_variable, loc, arch=self.project.arch)
                    self._data_graph_add_edge(v, prog_var, type="mem_data")

            for tmp in action.data.tmp_deps:
                self._stmt_graph_annotate_edges(self._temp_edges[tmp], subtype="mem_data")
                if tmp in self._temp_variables:
                    self._data_graph_add_edge(self._temp_variables[tmp], prog_var, type="mem_data")

    def _handle_mem_read(self, action, code_location, state, statement):  # pylint:disable=unused-argument
        addrs = self._get_actual_addrs(action, state)

        for addr in addrs:
            variable = self._create_memory_variable(action, addr, addrs)

            variables = []

            # get all definitions
            defs = self._def_lookup(variable)

            if defs:
                # for each definition, create an edge on the graph
                for definition_location, labels in defs.items():
                    self._stmt_graph_add_edge(definition_location, code_location, **labels)
                    pv = ProgramVariable(variable, definition_location, arch=self.project.arch)
                    variables.append(pv)
                    self._make_edges(action, pv)
            else:
                # if no definition is found, then this is the first time this variable is accessed
                # mark it as "initial"
                pv = ProgramVariable(variable, code_location, initial=True, arch=self.project.arch)
                variables.append(pv)
                self._make_edges(action, pv)
                # make sure to put it into the killing set
                self._kill(variable, code_location)

            for var in variables:
                # record accessed variables in var_per_stmt
                self._variables_per_statement.append(var)

    def _handle_mem_write(self, action, location, state, statement):
        addrs = self._get_actual_addrs(action, state)

        for addr in addrs:
            variable = self._create_memory_variable(action, addr, addrs)

            # kill all previous variables
            self._kill(variable, location)

            # create a new variable at current location
            pv = ProgramVariable(variable, location, arch=self.project.arch)

            # make edges
            self._make_edges(action, pv)

            if isinstance(statement, pyvex.IRStmt.Store) and self._variables_per_statement:
                if isinstance(statement.data, pyvex.IRExpr.RdTmp):
                    # assignment
                    src_tmp_idx = statement.data.tmp
                    src_tmp_def = next(
                        s
                        for s in self._variables_per_statement
                        if isinstance(s.variable, SimTemporaryVariable) and s.variable.tmp_id == src_tmp_idx
                    )
                    self._ast_graph.add_edge(src_tmp_def, pv)
                elif isinstance(statement.data, pyvex.IRExpr.Const):
                    # assignment
                    const = statement.data.con.value
                    self._ast_graph.add_edge(ProgramVariable(SimConstantVariable(const), location), pv)

    def _handle_reg_read(self, action, location, state, statement):  # pylint:disable=unused-argument
        reg_offset = action.offset
        variable = SimRegisterVariable(reg_offset, action.data.ast.size() // 8)

        # What do we want to do?
        definitions = self._def_lookup(variable)

        # add edges to the statement dependence graph
        for definition_location, labels in definitions.items():
            self._stmt_graph_add_edge(definition_location, location, **labels)

            # record the edge
            self._register_edges[reg_offset].append((definition_location, location))

            self._variables_per_statement.append(ProgramVariable(variable, definition_location, arch=self.project.arch))

        if not definitions:
            # the register was never defined before - it must be passed in as an argument
            self._variables_per_statement.append(
                ProgramVariable(variable, location, initial=True, arch=self.project.arch)
            )
            # make sure to put it into the killing set
            self._kill(variable, location)

        if reg_offset == self.project.arch.sp_offset:
            self._custom_data_per_statement = ("sp", 0)
        elif reg_offset == self.project.arch.bp_offset:
            self._custom_data_per_statement = ("bp", 0)

    def _handle_reg_write(self, action, location, state, statement):  # pylint:disable=unused-argument
        reg_offset = action.offset
        variable = SimRegisterVariable(reg_offset, action.data.ast.size() // 8)

        self._kill(variable, location)

        if reg_offset in self._register_edges:
            # clear the recoreded edge, since we don't need to alter that edge anymore
            del self._register_edges[reg_offset]

        # add a node on the data dependence graph
        pv = ProgramVariable(variable, location, arch=self.project.arch)
        self._data_graph_add_node(pv)

        if not action.reg_deps and not action.tmp_deps:
            # moving a constant into the register
            # try to parse out the constant from statement
            const_variable = SimConstantVariable()
            if statement is not None and isinstance(statement.data, pyvex.IRExpr.Const):
                const_variable = SimConstantVariable(value=statement.data.con.value)
            const_pv = ProgramVariable(const_variable, location, arch=self.project.arch)
            self._data_graph_add_edge(const_pv, pv)

        for tmp in action.tmp_deps:
            if tmp in self._temp_variables:
                self._data_graph_add_edge(self._temp_variables[tmp], pv)

    def _handle_tmp_read(self, action, location, state, statement):  # pylint:disable=unused-argument
        tmp = action.tmp
        tmp_var = self._temp_variables[tmp]

        def_loc = tmp_var.location

        self._stmt_graph_add_edge(def_loc, location, type="tmp", data=action.tmp)
        # record the edge
        edge_tuple = (def_loc, location)
        self._temp_edges[action.tmp].append(edge_tuple)

        if tmp in self._temp_register_symbols:
            self._custom_data_per_statement = self._temp_register_symbols[tmp]

        self._variables_per_statement.append(tmp_var)

    def _handle_tmp_write(self, action, location, state, statement):  # pylint:disable=unused-argument
        ast = None

        tmp = action.tmp
        pv = ProgramVariable(SimTemporaryVariable(tmp), location, arch=self.project.arch)

        if ast is not None:
            for operand in ast.operands:
                self._ast_graph.add_edge(operand, ast)
            self._ast_graph.add_edge(ast, pv)

        self._temp_variables[tmp] = pv

        # clear existing edges
        if tmp in self._temp_edges:
            del self._temp_edges[tmp]

        for tmp_dep in action.tmp_deps:
            if tmp_dep in self._temp_variables:
                self._data_graph_add_edge(self._temp_variables[tmp_dep], pv)

        if self._custom_data_per_statement is not None:
            self._temp_register_symbols[tmp] = self._custom_data_per_statement

        for data in self._variables_per_statement:
            self._data_graph_add_edge(data, pv)

        if isinstance(statement, pyvex.IRStmt.WrTmp) and self._variables_per_statement:
            if isinstance(statement.data, pyvex.IRExpr.RdTmp):
                # assignment: dst_tmp = src_tmp
                for s in filter(
                    lambda x: isinstance(x.variable, SimTemporaryVariable) and x.variable.tmp_id != tmp,
                    self._variables_per_statement,
                ):
                    self._ast_graph.add_edge(s, pv)
            elif isinstance(statement.data, pyvex.IRExpr.Get):
                # assignment: dst_tmp = src_reg
                for s in filter(lambda x: isinstance(x.variable, SimRegisterVariable), self._variables_per_statement):
                    self._ast_graph.add_edge(s, pv)
            elif isinstance(statement.data, pyvex.IRExpr.Load):
                # assignment: dst_tmp = [ src_mem ]
                for s in filter(lambda x: isinstance(x.variable, SimMemoryVariable), self._variables_per_statement):
                    self._ast_graph.add_edge(s, pv)

        if not action.tmp_deps and not self._variables_per_statement and not ast:
            # read in a constant
            # try to parse out the constant from statement
            const_variable = SimConstantVariable()
            if statement is not None:
                if isinstance(statement, pyvex.IRStmt.Dirty):
                    l.warning("Dirty statements are not supported in DDG for now.")
                elif isinstance(statement.data, pyvex.IRExpr.Const):
                    const_variable = SimConstantVariable(value=statement.data.con.value)
            const_pv = ProgramVariable(const_variable, location, arch=self.project.arch)
            self._data_graph_add_edge(const_pv, pv)

    def _handle_exit(self, action, location, state, statement):  # pylint:disable=unused-argument
        # exits should only depend on tmps
        for tmp in action.tmp_deps:
            prev_code_loc = self._temp_variables[tmp].location

            # add the edge to the graph
            self._stmt_graph_add_edge(prev_code_loc, location, type="exit", data="tmp")

            # log the edge
            edge_tuple = (prev_code_loc, location)
            self._temp_edges[tmp].append(edge_tuple)

    def _handle_operation(self, action, location, state, statement):  # pylint:disable=unused-argument
        if action.op.endswith("Sub32") or action.op.endswith("Sub64"):
            # subtract
            expr_0, expr_1 = action.exprs

            if expr_0.tmp_deps and (not expr_1.tmp_deps and not expr_1.reg_deps):
                # tmp - const

                const_value = expr_1.ast.args[0]

                tmp = next(iter(expr_0.tmp_deps))
                if tmp in self._temp_register_symbols:
                    sort, offset = self._temp_register_symbols[tmp]
                    offset -= const_value
                    if offset < 0:
                        offset += 1 << self.project.arch.bits
                    self._custom_data_per_statement = (sort, offset)

        elif action.op.endswith("Add32") or action.op.endswith("Add64"):
            # add

            expr_0, expr_1 = action.exprs

            if expr_0.tmp_deps and (not expr_1.tmp_deps and not expr_1.reg_deps):
                # tmp + const
                const_value = expr_1.ast.args[0]

                tmp = next(iter(expr_0.tmp_deps))
                if tmp in self._temp_register_symbols:
                    sort, offset = self._temp_register_symbols[tmp]
                    offset += const_value
                    if offset >= (1 << self.project.arch.bits):
                        offset -= 1 << self.project.arch.bits
                    self._custom_data_per_statement = (sort, offset)

    def _process_operation(self, action, location, state, statement):  # pylint:disable=unused-argument
        if action.op.endswith("Sub32") or action.op.endswith("Sub64"):
            # subtract
            expr_0, expr_1 = action.exprs

            if expr_0.tmp_deps and (not expr_1.tmp_deps and not expr_1.reg_deps):
                # tmp - const
                const_value = expr_1.ast.args[0]
                tmp = next(iter(expr_0.tmp_deps))

                const_def = ProgramVariable(SimConstantVariable(const_value), location)
                tmp_def = self._temp_variables[tmp]
                return AST("-", tmp_def, const_def)

        elif action.op.endswith("Add32") or action.op.endswith("Add64"):
            # add

            expr_0, expr_1 = action.exprs

            if expr_0.tmp_deps and (not expr_1.tmp_deps and not expr_1.reg_deps):
                # tmp + const
                const_value = expr_1.ast.args[0]
                tmp = next(iter(expr_0.tmp_deps))

                const_def = ProgramVariable(SimConstantVariable(const_value), location)
                tmp_def = self._temp_variables[tmp]
                return AST("+", tmp_def, const_def)

        return None

    #
    # Graph operations
    #

    def _data_graph_add_node(self, node):
        """
        Add a node in the data dependence graph.

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

            for k, v in new_labels.items():
                if k in data:
                    if v not in data[k]:
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

        all_nodes = [n for n in graph.nodes() if isinstance(n.variable, SimTemporaryVariable)]

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
                    if pred is not tmp_node and suc is not tmp_node and suc not in graph[pred]:
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
            return None

        worklist.append(node_wrapper)
        worklist_set.add(node_wrapper.cfg_node)

        stack = [node_wrapper]
        traversed_nodes = {node_wrapper.cfg_node}
        inserted = {node_wrapper.cfg_node}

        while stack:
            nw = stack.pop()
            n, call_depth = nw.cfg_node, nw.call_depth

            # Get successors
            edges = self._cfg.graph.out_edges(n, data=True)

            for _, dst, data in edges:
                if (
                    dst not in traversed_nodes  # which means we haven't touch this node in this appending procedure
                    and dst not in worklist_set
                ):  # which means this node is not in the work-list
                    # We see a new node!
                    traversed_nodes.add(dst)

                    if data["jumpkind"] == "Ijk_Call":
                        if self._call_depth is None or call_depth < self._call_depth:
                            inserted.add(dst)
                            new_nw = DDGJob(dst, call_depth + 1)
                            worklist.append(new_nw)
                            worklist_set.add(dst)
                            stack.append(new_nw)
                    elif data["jumpkind"] == "Ijk_Ret":
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

        block_addr_to_func = {}
        for _, func in self.kb.functions.items():
            for block in func.blocks:
                block_addr_to_func[block.addr] = func

        for src, dst, data in self.graph.edges(data=True):
            src_target_func = None
            if src.block_addr in block_addr_to_func:
                src_target_func = block_addr_to_func[src.block_addr]
                self._function_data_dependencies[src_target_func].add_edge(src, dst, **data)

            if dst.block_addr in block_addr_to_func:
                dst_target_func = block_addr_to_func[dst.block_addr]
                if dst_target_func is not src_target_func:
                    self._function_data_dependencies[dst_target_func].add_edge(src, dst, **data)

    #
    # Other private methods
    #

    def _filter_defs_at_call_sites(self, defs):
        """
        If we are not tracing into the function that are called in a real execution, we should properly filter the defs
        to account for the behavior of the skipped function at this call site.

        This function is a WIP. See TODOs inside.

        :param defs:
        :return:
        """

        # TODO: make definition killing architecture independent and calling convention independent
        # TODO: use information from a calling convention analysis
        filtered_defs = LiveDefinitions()
        for variable, locs in defs.items():
            if not (
                isinstance(variable, SimRegisterVariable)
                and self.project.arch.name == "X86"
                and variable.reg
                in (
                    self.project.arch.registers["eax"][0],
                    self.project.arch.registers["ecx"][0],
                    self.project.arch.registers["edx"][0],
                )
            ):
                filtered_defs.add_defs(variable, locs)

        return filtered_defs

    def find_definitions(self, variable, location=None, simplified_graph=True):
        """
        Find all definitions of the given variable.

        :param SimVariable variable:
        :param bool simplified_graph: True if you just want to search in the simplified graph instead of the normal
                                      graph. Usually the simplified graph suffices for finding definitions of register
                                      or memory variables.
        :return: A collection of all variable definitions to the specific variable.
        :rtype: list
        """

        graph = self.simplified_data_graph if simplified_graph else self.data_graph

        defs = []

        n: ProgramVariable
        for n in graph.nodes():
            if n.variable == variable:
                if location is None:
                    defs.append(n)
                else:
                    # TODO: finish this part
                    if n.location.block_addr == location.block_addr:
                        defs.append(n)

        return defs

    def find_consumers(self, var_def, simplified_graph=True):
        """
        Find all consumers to the specified variable definition.

        :param ProgramVariable var_def: The variable definition.
        :param bool simplified_graph: True if we want to search in the simplified graph, False otherwise.
        :return: A collection of all consumers to the specified variable definition.
        :rtype: list
        """

        graph = self.simplified_data_graph if simplified_graph else self.data_graph

        if var_def not in graph:
            return []

        consumers = []
        srcs = [var_def]
        traversed = set()

        while srcs:
            src = srcs.pop()
            out_edges = graph.out_edges(src, data=True)
            for _, dst, data in out_edges:
                if "type" in data and data["type"] == "kill":
                    # skip killing edges
                    continue
                if isinstance(dst.variable, SimTemporaryVariable):
                    if dst not in traversed:
                        srcs.append(dst)
                        traversed.add(dst)
                else:
                    if dst not in consumers:
                        consumers.append(dst)

        return consumers

    def find_killers(self, var_def, simplified_graph=True):
        """
        Find all killers to the specified variable definition.

        :param ProgramVariable var_def: The variable definition.
        :param bool simplified_graph: True if we want to search in the simplified graph, False otherwise.
        :return: A collection of all killers to the specified variable definition.
        :rtype: list
        """

        graph = self.simplified_data_graph if simplified_graph else self.data_graph

        if var_def not in graph:
            return []

        killers = []
        out_edges = graph.out_edges(var_def, data=True)
        for _, dst, data in out_edges:
            if "type" in data and data["type"] == "kill":
                killers.append(dst)

        return killers

    def find_sources(self, var_def, simplified_graph=True):
        """
        Find all sources to the specified variable definition.

        :param ProgramVariable var_def: The variable definition.
        :param bool simplified_graph: True if we want to search in the simplified graph, False otherwise.
        :return: A collection of all sources to the specified variable definition.
        :rtype: list
        """

        graph = self.simplified_data_graph if simplified_graph else self.data_graph

        if var_def not in graph:
            return []

        sources = []
        defs = [var_def]
        traversed = set()

        while defs:
            definition = defs.pop()
            in_edges = graph.in_edges(definition, data=True)
            for src, _, data in in_edges:
                if "type" in data and data["type"] == "kill":
                    continue
                if isinstance(src.variable, SimTemporaryVariable):
                    if src not in traversed:
                        defs.append(src)
                        traversed.add(src)
                else:
                    if src not in sources:
                        sources.append(src)

        return sources


from angr.analyses import AnalysesHub

AnalysesHub.register_default("DDG", DDG)
