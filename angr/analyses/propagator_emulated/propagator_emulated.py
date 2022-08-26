
from collections import defaultdict
from functools import reduce

import ailment
import claripy

from ...engines.successors import SimSuccessors
from ...engines.vex import TrackActionsMixin, SimInspectMixin, HeavyResilienceMixin, SuperFastpathMixin
from ...engines.unicorn import SimEngineUnicorn
from ...engines.failure import SimEngineFailure
from ...engines.syscall import SimEngineSyscall
from ...engines.hook import HooksMixin
from ...engines.soot import SootMixin
from ..cfg.cfg_utils import CFGUtils
from .. import register_analysis
from ..analysis import Analysis
from ..cfg.cfg_vm_deobfuscation import StackTouchedAnnotation, DataRegionAnnotation, VMStackVariableAnnotation
from ..forward_analysis.visitors.graph import GraphVisitor
from ..forward_analysis import ForwardAnalysis
from .values import TOP
from .engines.engine_vex import PropagatorEmulatedHeavyVEXMixin


class PropagatorEmulatedEngine(SimEngineFailure, SimEngineSyscall, HooksMixin, SimEngineUnicorn, SuperFastpathMixin, TrackActionsMixin, SimInspectMixin, HeavyResilienceMixin, SootMixin, PropagatorEmulatedHeavyVEXMixin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _perform_vex_expr_Load(self, addr, ty, endness, **kwargs):

        simplified_addr = self.state.solver.simplify(addr[0])
        result = super()._perform_vex_expr_Load((simplified_addr, addr[1]), ty, endness, **kwargs)

        save = False
        if isinstance(result[0].args[0], str) and result[0].args[0].startswith('symbolic_read_unconstrained_'):
            for ast in simplified_addr.leaf_asts():
                if isinstance(ast.args[0], str) and ast.args[0].startswith('scanf'):
                    save = True
                    break

        if save:
            # create a solver without any constraints and use that to solve. This is equivalent to simplifying it and should not have the same issues that regular symbolic execution/solving with contraints should have
            no_constraints_solver = claripy.solvers.SolverComposite()
            conc_addrs = no_constraints_solver.eval(simplified_addr, 5)

            simp_addr = self.state.solver.simplify(simplified_addr)
            vars = simp_addr.variables

            if len(vars) > 1:
                print("More than one user inputs? or variables?")
                import ipdb;
                ipdb.set_trace()

            var_str = list(vars)[0]

            for ast in simplified_addr.leaf_asts():
                if isinstance(ast.args[0], str) and ast.args[0] == var_str:
                    var_ast = ast

            conc_addr_and_new_constraints = []
            for conc_addr in conc_addrs:
                no_constraints_solver = claripy.solvers.SolverComposite()
                no_constraints_solver.add(simplified_addr == conc_addr)
                conc_input_value = no_constraints_solver.eval(var_ast, 1)[0]
                conc_addr_and_new_constraints.append((conc_addr, var_ast == conc_input_value))

            if len(conc_addrs) == 1:
                print("Hmmmm")
                import ipdb;
                ipdb.set_trace()
            else:
                self.state.globals['concretized_load_addr_dict'][result[0]] = (
                conc_addr_and_new_constraints, self._ty_to_bytes(ty), simplified_addr)

        return result


class EmulatedCFGVisitor(GraphVisitor):

    def __init__(self, graph, start):
        super(EmulatedCFGVisitor, self).__init__()
        self._start = start
        self.graph=graph
        self.reset()

    def startpoints(self):
        return [self._start]

    def successors(self, node):
        return list(self.graph.successors(node))

    def predecessors(self, node):
        return list(self.graph.predecessors(node))

    def sort_nodes(self, nodes=None):
        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(self.graph)
        if nodes is not None:
            sorted_nodes = [ n for n in sorted_nodes if n in set(nodes) ]
        return sorted_nodes

# The base state

class PropagatorState:

    def __init__(self, arch, replacements=None, concrete_states=None):
        self.arch = arch
        self.gpr_size = arch.bits // arch.byte_width  # size of the general-purpose registers
        self._replacements = defaultdict(dict) if replacements is None else replacements
        self._concrete_states = concrete_states

    def __repr__(self):
        return "<PropagatorState>"

    def copy(self):
        raise NotImplementedError()

    def merge(self, *others):
        state = self.copy()
        for o in others:
            for loc, vars_ in o._replacements.items():
                if loc not in state._replacements:
                    state._replacements[loc] = vars_.copy()
                else:
                    for var, repl in vars_.items():
                        if var not in state._replacements[loc]:
                            state._replacements[loc][var] = repl
                        else:
                            if state._replacements[loc][var] != repl:
                                state._replacements[loc][var] = TOP
        return state


    def add_replacement(self, codeloc, old, new):
        self._replacements[codeloc][old] = new

    @property
    def concrete_states(self):
        return self._concrete_states

    @concrete_states.setter
    def concrete_states(self, v):
        self._concrete_states = v

    def get_concrete_state(self, block_id):
        """

        :param addr:
        :return:
        """
        ## This is for handling the initial concrete_states set with a list
        #if isinstance(self.concrete_states, list):
        possible_successors =self.concrete_states
        #else:
        #    possible_successors = self.concrete_states.all_successors
        for s in possible_successors:
            if s.globals['cur_block_id'] == block_id:
                return s
        return None

# VEX state

class PropagatorVEXState(PropagatorState):

    def __init__(self, arch, replacements=None, concrete_states=None):
        super().__init__(arch, replacements=replacements, concrete_states=concrete_states)
        # this mapping is used to decide which exprs to treat as symbolic in future analysis
        self.symbolic_expr_locations = defaultdict(list)

    def __repr__(self):
        return "<PropagatorVEXState>"

    def copy(self):
        cp = PropagatorVEXState(
            self.arch,
            replacements=self._replacements.copy(),
            concrete_states=self._concrete_states
        )
        return cp

    def merge(self, other):
        merged_concrete_states = self._merge_concrete_states(other)
        return PropagatorVEXState(arch=self.arch, concrete_states=merged_concrete_states)

    def _merge_concrete_states(self, other):
        """

        :param StorageState other:
        :return:
        :rtype:                             list
        """

        merged = [ ]
        # if not isinstance(self.concrete_states, list):
        #     self.concrete_states = self.concrete_states.all_successors
        for s in self.concrete_states:
            other_state = other.get_concrete_state(s.globals['cur_block_id'])
            if other_state is not None:
                s = s.merge(other_state, plugin_whitelist=['inspect', 'preconstrainer', 'globals', 'mem', 'heap', 'regs', 'solver', 'callstack', 'history', 'fs', 'scratch', 'memory', 'registers', 'libc'])
                merged.append(s[0])
        return merged

    def add_replacement(self, codeloc, old, new):
        if old not in self._replacements[codeloc]:
            self._replacements[codeloc][old] = new

        ## If it is not the same as the previous replacement then it is not a constant and should not be replaced
        elif self._replacements[codeloc][old].con.value != new.con.value:
            del self._replacements[codeloc][old]
            #self._replacements[codeloc][old] = TOP

# AIL state

class PropagatorAILState(PropagatorState):

    def __init__(self, arch, replacements=None):
        super().__init__(arch, replacements=replacements)
        self._variables = { }  # variable to values

    def __repr__(self):
        return "<PropagatorAILState>"

    def copy(self):
        rd = PropagatorAILState(
            self.arch,
            replacements=self._replacements.copy(),
        )
        rd._variables = self._variables.copy()
        return rd

    def merge(self, *others):
        state = super().merge(*others)

        for o in others:
            for k, v in o._variables.items():
                if k not in state._variables:
                    state._variables[k] = v
                else:
                    if state._variables[k] != o._variables[k]:
                        # Go to TOP
                        state._variables[k] = TOP
        return state

    def store_variable(self, old, new):
        if new is not None:
            self._variables[old] = new

    def get_variable(self, old):
        return self._variables.get(old, None)

    def remove_variable(self, old):
        self._variables.pop(old, None)

    def filter_variables(self, atom):
        keys_to_remove = set()

        for k, v in self._variables.items():
            if isinstance(v, ailment.Expr.Expression) and (v == atom or v.has_atom(atom)):
                keys_to_remove.add(k)

        for k in keys_to_remove:
            self._variables.pop(k)


class PropagatorEmulatedAnalysis(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
    """
    PropagatorAnalysis propagates values, either constants or variables, across a block or a function. It supports both
    VEX and AIL. It performs certain arithmetic operations between constants, including but are not limited to:

    - addition
    - subtraction
    - multiplication
    - division
    - xor

    It also performs the following memory operations, too:

    - Loading values from a known address
    - Writing values to a stack variable
    """

    def __init__(self, func=None, block=None, func_graph=None, base_state=None, max_iterations=1,
                 load_callback=None, stack_pointer_tracker=None, start=None, graph=None, iropt_level=None):
        graph_visitor = EmulatedCFGVisitor(graph, self.project.entry if start is None else start)
        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=False, allow_widening=False,
                                 graph_visitor=graph_visitor)
        self._graph=graph
        self._base_state = base_state
        self._function = func
        self._max_iterations = max_iterations
        self._load_callback = load_callback
        self._stack_pointer_tracker = stack_pointer_tracker  # only used when analyzing AIL functions
        self._iropt_level = iropt_level
        self._node_iterations = defaultdict(int)
        self._states = { }
        self.replacements = {}
        self.symbolic_expr_locations_block_wise = {}
        self._engine_ail = None
        self._engine= PropagatorEmulatedEngine(project=self.project)
        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        node.input_state.globals['cur_block_id'] = node.block_id
        if isinstance(node, ailment.Block):
            # AIL
            state = PropagatorAILState(arch=self.project.arch)
        else:
            # VEX
            #state = SimState(arch=self.projct.arch)
            state = PropagatorVEXState(arch=self.project.arch)
            state.concrete_states = [node.input_state]
        return state

    def _merge_states(self, node, *states):
        if len(states) == 1:
            return states[0]
        merged_abstract_state = reduce(lambda s_0, s_1: s_0.merge(s_1), states[1:], states[0])
        return merged_abstract_state, True

    # def _add_input_state(self, node, input_state):
    #     successors_to_visit = []
    #     successors = self._graph_visitor.successors(node)
    #     for succ in successors:
    #         self._state_map[succ] = input_state
    #         for concrete_state in input_state.concrete_states:
    #             if succ.addr == concrete_state.ip._model_concrete.value:
    #                 successors_to_visit.append(succ)
    #     return successors_to_visit

    def _run_on_node(self, node, abstract_state):
        print(node)
        concrete_state = abstract_state.get_concrete_state(node.block_id)
        node.input_state = concrete_state
        if concrete_state is None:
            # didn't find any state going here
            return False, abstract_state

        block_key = node.block_id
        #abstract_state = abstract_state.copy()
        if block_key in self._states:
            abstract_state = self._states[block_key]
        else:
            abstract_state = PropagatorVEXState(arch=self.project.arch)

        node.input_state.globals['abstract_state'] = abstract_state
        node.input_state.globals['cur_block_id'] = block_key
        engine = self._engine
        sim_successors = engine.process(node.input_state, opt_level=self._iropt_level, irsb=node.irsb)

        if node.is_simprocedure:
            if len(list(self._graph.successors(node))) > 1 and len(sim_successors.unconstrained_successors) > 0:
                # create successors for the sim procedure since it is unconstrained because we are not emulating the sim procedures for constant prop
                new_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
                new_sim_successors.artifacts = sim_successors.artifacts
                new_sim_successors.engine = sim_successors.engine
                new_sim_successors.processed = sim_successors.processed
                new_sim_successors.description = sim_successors.description
                new_sim_successors.sort = sim_successors.sort

                for succ in self.graph.successors(node):
                    new_state = sim_successors.unconstrained_successors[0].copy()
                    new_state.regs.ip = claripy.BVV(succ.addr, new_state.arch.bits)
                    new_sim_successors.add_successor(new_state, succ.addr,
                                                     new_state.scratch.guard,
                                                     new_state.history.jumpkind, True,
                                                     new_state.scratch.exit_stmt_idx,
                                                     new_state.scratch.exit_ins_addr,
                                                     new_state.scratch.source)

                sim_successors = new_sim_successors
                sim_successors.artifacts['irsb_direct_next'] = True

            for succ in sim_successors.all_successors:
                for graph_succ in self._graph.successors(node):
                    if succ.addr == graph_succ.addr:
                        succ.globals['cur_block_id'] = graph_succ.block_id

            symbolic_sim_successors = sim_successors

        else:
            if len(sim_successors.unconstrained_successors) == 1 and len(sim_successors.all_successors) == 1:

                new_states = []
                uncon_succ = sim_successors.unconstrained_successors[0]

                poss_target = uncon_succ.solver.simplify(uncon_succ.scratch.target).replace_dict(uncon_succ.solver._solver._replacement_cache)


                if not uncon_succ.solver.symbolic(poss_target):
                    #import ipdb;ipdb.set_trace()
                    new_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
                    new_sim_successors.artifacts = sim_successors.artifacts
                    new_sim_successors.engine = sim_successors.engine
                    new_sim_successors.processed = sim_successors.processed
                    new_sim_successors.description = sim_successors.description
                    new_sim_successors.sort = sim_successors.sort

                    targ_addr = uncon_succ.solver.simplify(uncon_succ.scratch.target)

                    if targ_addr.symbolic:
                        targ_addr = uncon_succ.solver.eval(uncon_succ.scratch.target)

                    new_sim_successors.add_successor(uncon_succ, targ_addr,
                                                     uncon_succ.scratch.guard,
                                                     uncon_succ.history.jumpkind, True,
                                                     uncon_succ.scratch.exit_stmt_idx,
                                                     uncon_succ.scratch.exit_ins_addr,
                                                     uncon_succ.scratch.source)

                    sim_successors = new_sim_successors
                    sim_successors.artifacts['irsb_direct_next'] = True

                else:
                    for ast in sim_successors.unconstrained_successors[0].regs.ip.leaf_asts():
                        if ast in sim_successors.unconstrained_successors[0].globals['concretized_load_addr_dict']:
                            conc_addr_and_new_constraints = sim_successors.unconstrained_successors[0].globals['concretized_load_addr_dict'][ast][0]
                            if len(conc_addr_and_new_constraints) > 2:
                                print("More than two possible jumps? is this not a direct jump converted to an indirect jump?")
                                import ipdb;ipdb.set_trace()
                            for conc_addr, input_constraint in conc_addr_and_new_constraints:
                                sym_addr = sim_successors.unconstrained_successors[0].globals['concretized_load_addr_dict'][ast][2]
                                size = sim_successors.unconstrained_successors[0].globals['concretized_load_addr_dict'][ast][1]
                                new_state = sim_successors.unconstrained_successors[0].copy()
                                value = new_state.memory.load(conc_addr, size, endness=new_state.arch.memory_endness)
                                #import ipdb;ipdb.set_trace()

                                new_state.add_constraints(sym_addr == conc_addr)
                                new_state.solver._solver.add_replacement(sym_addr, conc_addr, invalidate_cache=False)

                                new_state.add_constraints(ast == value)
                                new_state.solver._solver.add_replacement(ast, value, invalidate_cache=False)

                                new_state.add_constraints(input_constraint)
                                new_state.solver._solver.add_replacement(input_constraint.args[0], input_constraint.args[1], invalidate_cache=False)

                                new_state.regs.ip = new_state.solver.simplify(new_state.regs.ip).replace_dict(new_state.solver._solver._replacement_cache)
                                new_state.scratch.target = new_state.solver.simplify(new_state.scratch.target).replace_dict(new_state.solver._solver._replacement_cache)

                                # Fill the block id
                                for node_succ in self.graph.successors(node):
                                    if len(new_state.regs.ip.args) == 2 and node_succ.addr == new_state.regs.ip.args[0]:
                                        new_state.globals['cur_block_id'] = node_succ.block_id
                                    elif len(new_state.regs.ip.args) != 2:
                                        print("failed to set cur block id")
                                        import ipdb;ipdb.set_trace()
                                new_states.append(new_state)

                    if len(new_states) != 0:
                        new_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
                        new_sim_successors.artifacts = sim_successors.artifacts
                        new_sim_successors.engine = sim_successors.engine
                        new_sim_successors.processed = sim_successors.processed
                        new_sim_successors.description = sim_successors.description
                        new_sim_successors.sort = sim_successors.sort
                        for new_state in new_states:
                            new_sim_successors.add_successor(new_state, new_state.solver.eval(new_state.scratch.target), new_state.scratch.guard,
                                                                      new_state.history.jumpkind, True,
                                                                      new_state.scratch.exit_stmt_idx,
                                                                      new_state.scratch.exit_ins_addr,
                                                                      new_state.scratch.source)
                        sim_successors=new_sim_successors
                        sim_successors.artifacts['irsb_direct_next'] = True

            elif (len(sim_successors.unconstrained_successors) == 1 and len(sim_successors.all_successors) != 1) or len(sim_successors.unconstrained_successors) > 1:
                print("More than one unconstrained successor?!")
                import ipdb;ipdb.set_trace()


            symbolic_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
            symbolic_sim_successors.artifacts = sim_successors.artifacts
            symbolic_sim_successors.engine = sim_successors.engine
            symbolic_sim_successors.processed = sim_successors.processed
            symbolic_sim_successors.description = sim_successors.description
            symbolic_sim_successors.sort = sim_successors.sort

            for successor in sim_successors.all_successors:
                ## Only add those successors which have symbolic guard or which evaluates to True
                # if successor.solver.symbolic(successor.scratch.guard) or successor.solver.eval(successor.scratch.guard):
                #symbolic_sim_successors.add_successor(successor, successor.scratch.target, successor.scratch.guard,
                                                          # successor.history.jumpkind, True,
                                                          # successor.scratch.exit_stmt_idx, successor.scratch.exit_ins_addr,
                                                          # successor.scratch.source)
                is_stack_tainted = False
                is_data_region_tainted = False
                for annotation in successor.scratch.guard.annotations:
                    if isinstance(annotation, DataRegionAnnotation):
                        is_data_region_tainted = True
                        symbolic_sim_successors.add_successor(successor, successor.scratch.target,
                                                              successor.scratch.guard,
                                                              successor.history.jumpkind, True,
                                                              successor.scratch.exit_stmt_idx,
                                                              successor.scratch.exit_ins_addr,
                                                              successor.scratch.source)
                        break
                    # elif isinstance(annotation, StackTouchedAnnotation):
                    #     is_stack_tainted = True
                    #     symbolic_sim_successors.add_successor(successor, successor.scratch.target, successor.scratch.guard,
                    #                                           successor.history.jumpkind, True,
                    #                                           successor.scratch.exit_stmt_idx,
                    #                                           successor.scratch.exit_ins_addr,
                    #                                           successor.scratch.source)
                    #     break
                    elif isinstance(annotation, VMStackVariableAnnotation):
                        is_stack_tainted = True
                        symbolic_sim_successors.add_successor(successor, successor.scratch.target,
                                                              successor.scratch.guard,
                                                              successor.history.jumpkind, True,
                                                              successor.scratch.exit_stmt_idx,
                                                              successor.scratch.exit_ins_addr,
                                                              successor.scratch.source)
                        break

                if is_stack_tainted is False and is_data_region_tainted is False and (successor.solver.symbolic(successor.scratch.guard) or successor.solver.eval(
                        successor.scratch.guard)):
                    symbolic_sim_successors.add_successor(successor, successor.scratch.target, successor.scratch.guard,
                                                          successor.history.jumpkind, True,
                                                          successor.scratch.exit_stmt_idx,
                                                          successor.scratch.exit_ins_addr,
                                                          successor.scratch.source)

        node.final_states = symbolic_sim_successors
        abstract_state.concrete_states = symbolic_sim_successors.all_successors
        self._node_iterations[block_key] += 1
        self._states[block_key] = abstract_state
        self.replacements[block_key] = abstract_state._replacements
        self.symbolic_expr_locations_block_wise[block_key] = abstract_state.symbolic_expr_locations

        if self._node_iterations[block_key] <= self._max_iterations:
            return True, abstract_state
        else:
            return False, abstract_state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

register_analysis(PropagatorEmulatedAnalysis, "PropagatorEmulated")
