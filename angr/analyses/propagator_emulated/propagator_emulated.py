import weakref
from collections import defaultdict
from functools import reduce
import copy
import ailment
import claripy
import pyvex
from ..vm_deobfuscation.vm_deobfuscation import DataSensitiveRdTmp, DataSensitiveU64, DataSensitiveU32
from ...errors import SimUnsatError, SimValueError
from ...code_location import CodeLocation
from ...engines import HeavyVEXMixin

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


debug=False

class PropagatorEmulatedEngine(SimEngineFailure, SimEngineSyscall, HooksMixin, SimEngineUnicorn, SuperFastpathMixin, TrackActionsMixin, SimInspectMixin, HeavyResilienceMixin, SootMixin, HeavyVEXMixin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def is_symbolized(self, expr):
        if 'symbolified_expr' in expr.variables:
            return True
        else:
            return False
    def _handle_vex_expr(self, expr: pyvex.expr.IRExpr):
        # if self.state.scratch.ins_addr == 0x1400d2186 and self.state.scratch.stmt_idx == 5 and self.state.globals['cur_block_id'].vm_vpc == 5368832359:
        #     import ipdb;ipdb.set_trace()
        result = super()._handle_vex_expr(expr)
        simp_result = result[0]
        code_loc = CodeLocation(self.irsb.addr, self.stmt_idx, block_id=self.state.globals['cur_block_id'])

        cur_abstract_state = self.state.globals['abstract_state']()


        # if self.state.solver.symbolic(result[0]):
        #     self.state.globals['abstract_state'].symbolic_expr_locations[code_loc].append(expr)
        # else:
        if self.state.solver.symbolic(result[0]):
            skip = False
            for var in result[0].variables:
                if var.startswith('precon_sp'):
                    skip = True
                    break
            if cur_abstract_state.is_top(result[0]):
                skip = True

            if not skip:
                try:
                    eval_result = self.state.partial_symbolic_constraint_solver.eval_one(result[0])
                    simp_result = claripy.BVV(eval_result, result[0].size())
                except SimValueError:
                    pass

        # ### Only save the constant if it is not touched by the stack
        # stack_touched = False
        # for annotation in result[0].annotations:
        #     if isinstance(annotation, StackTouchedAnnotation):
        #         import ipdb;ipdb.set_trace()
        #         stack_touched = True
        #         break

        #symbolize the previously(previous analysis) found non constants and return that
        #if self.project.symbolic_expr_locations_blockwise and not self.state.solver.symbolic(result[0]) and self.state.globals['cur_block_id'] in self.project.symbolic_expr_locations_blockwise:
        if not self.state.solver.symbolic(result[0]) and self.project.prev_symbolic_expr_locations_blockwise and self.state.globals['cur_block_id'] in self.project.prev_symbolic_expr_locations_blockwise:
            for codeloc, expr_list in self.project.prev_symbolic_expr_locations_blockwise[self.state.globals['cur_block_id']].items():
                for to_repl_expr in expr_list:
                    if codeloc.stmt_idx == self.state.scratch.stmt_idx and to_repl_expr == expr:
                        sym_result = self.state.solver.BVS("symbolified_expr", result[0].size())

                        #sym_result = annotate_with_new_replacements(start_state, sym_result, )
                        #self.state.preconstrainer.preconstrain(self.state.solver.eval(result[0]), sym_result)
                        new_result = sym_result
                        return [sym_result, result[1]]

        ## Do we still need this stack touched thingy?? Not very accurate, we should actually be tracking local variables on the stack, since junk values can always be pushed and popped from the stack
        # if not stack_touched:

        # this is for the new constant propagation that doesn't merge states........... check if its a non constant
        if not self.state.solver.symbolic(simp_result) and \
                expr in cur_abstract_state._replacements[code_loc] and \
                not cur_abstract_state.is_top(cur_abstract_state._replacements[code_loc][expr]) and \
                cur_abstract_state._replacements[code_loc][expr].con.value != simp_result.args[0]:
            import ipdb;ipdb.set_trace()

            #del self.state.globals['abstract_state']._replacements[code_loc][expr]
            cur_abstract_state._replacements[code_loc][expr] = cur_abstract_state.top(simp_result.size())
            # cur_abstract_state.symbolic_expr_locations[code_loc].append(expr)
            sym_result = self.state.solver.BVS("symbolified_expr", result[0].size(), explicit_name=True)

            return [sym_result, result[1]]

        elif expr not in cur_abstract_state._replacements[code_loc] and not self.state.solver.symbolic(simp_result) \
                and not(isinstance(expr, pyvex.expr.Const)):
            const_class = pyvex.const.ty_to_const_class(expr.result_type(self.state.scratch.tyenv))
            if len(simp_result.args) > 2:
                print("Hmmm possible need to simplify the expr")
                import ipdb;ipdb.set_trace()
            if isinstance(expr, DataSensitiveRdTmp):
                if const_class == pyvex.const.U64:
                    const_class = DataSensitiveU64
                elif const_class == pyvex.const.U32:
                    const_class = DataSensitiveU32
                cur_abstract_state.add_replacement(code_loc, expr, pyvex.expr.Const(
                    const_class(simp_result.args[0], expr.block_id)))
            else:
                cur_abstract_state.add_replacement(code_loc, expr, pyvex.expr.Const(const_class(simp_result.args[0])))
        ### Check if the result is symbolic now, but was constant in some previous iteration and put in the replacements. If so then remove the replacement
        elif self.state.solver.symbolic(simp_result) and expr in cur_abstract_state._replacements[code_loc] and not cur_abstract_state.is_top(cur_abstract_state._replacements[code_loc][expr]):
            #del cur_abstract_state._replacements[code_loc][expr]
            cur_abstract_state._replacements[code_loc][expr] = cur_abstract_state.top(simp_result.size())
            # cur_abstract_state.symbolic_expr_locations[code_loc].append(expr)


        return [simp_result, result[1]]

    def _perform_vex_expr_Load(self, addr, ty, endness, **kwargs):

        #simplified_addr = self.state.solver.simplify(addr[0])
        #simplified_addr=self.state.solver.simplify(addr[0])

        simplified_addr = addr[0]
        if self.state.solver.symbolic(addr[0]):
            try:
                simplified_addr = self.state.partial_symbolic_constraint_solver.eval_one(addr[0])
            except SimValueError:
                pass
        result = super()._perform_vex_expr_Load((simplified_addr, addr[1]), ty, endness, **kwargs)



        # Check if the addr is a stack address, if so skip it
        merged_stack_address = None
        var_dict ={}
        for var in addr[0].variables:
            if var.startswith("state_merge"):
                var_dict["state_merge"] = True
            elif var.startswith("precon_sp"):
                var_dict["precon_sp"] = True
            else:
                merged_stack_address = False
                break

        if merged_stack_address is None and len(var_dict.keys()) == 2:
            merged_stack_address = True
        else:
            merged_stack_address = False

        save = False
        var_ast_list = []

        no_constraints_solver = claripy.solvers.SolverComposite()
        no_constraints_solver.add(self.state.partial_symbolic_constraint_solver.constraints)
        conc_addrs = no_constraints_solver.eval(simplified_addr, 5)
        ast_addrs = []
        for con_addr in conc_addrs:
            ast_addrs.append(claripy.BVV(con_addr, addr[0].size()))

        conc_addrs = ast_addrs

        if len(conc_addrs) < 5:
            if isinstance(result[0].args[0], str) and result[0].args[0].startswith('symbolic_read_unconstrained_') and not merged_stack_address:
                if not self.state.solver.symbolic(simplified_addr):
                    return result
                save = True
                for ast in simplified_addr.leaf_asts():
                    if isinstance(ast.args[0], str) and not ast.args[0].startswith('precon') and ast.args[0] not in \
                            self.state.globals['replaced_asts_str']:
                        var_ast_list.append(ast)
                    # if isinstance(ast.args[0], str) and ast.args[0].startswith('scanf'):
                    #     save = True
                    #     var_ast_list.append(ast)
                    # if isinstance(ast.args[0], str) and ast.args[0].startswith('symbolified_expr'):
                    #     save = True
                    #     var_ast_list.append(ast)
                if not save:
                    poss_addrs = self.state.partial_symbolic_constraint_solver.eval_upto(addr[0], 5)
                    addr_in_binary = True

                    for pos_addr in poss_addrs:
                        if not self.state.project.loader.main_object.contains_addr(pos_addr):
                            addr_in_binary = False
                            break

                    if len(poss_addrs) < 5 and addr_in_binary:
                        # import ipdb;ipdb.set_trace()
                        save = True

                        for ast in simplified_addr.leaf_asts():
                            if self.state.solver.symbolic(ast):
                                if ast.args[0] not in self.state.globals['replaced_asts_str']:
                                    var_ast_list.append(ast)

        if len(var_ast_list) > 1:
            print("More than one variables? which one to save.... maybe both")
            # import ipdb;
            # ipdb.set_trace()

        if save:
            # create a solver without any constraints and use that to solve. This is equivalent to simplifying it and should not have the same issues that regular symbolic execution/solving with contraints should have
            # no_constraints_solver = claripy.solvers.SolverComposite()
            # no_constraints_solver.add(self.state.partial_symbolic_constraint_solver.constraints)
            # conc_addrs = no_constraints_solver.eval(simplified_addr, 5)

            ## USE THIS THE PARTIAL CONSTRAINTS INSTEAD OF UNONCONSTRINAED SOLVER
            #conc_addrs = self.state.partial_symbolic_constraint_solver.eval_upto(simplified_addr, 4)

            # simp_addr = self.state.solver.simplify(simplified_addr)
            # vars = simp_addr.variables

            if len(var_ast_list) > 1:
                print("More than one variables to constrain at a time................. interesting...")
                #import ipdb;ipdb.set_trace()


            conc_addr_and_new_constraints = []
            loaded_values = []
            for conc_addr in conc_addrs:
                new_ast_constraints = []
                no_constraints_solver = claripy.solvers.SolverComposite()
                no_constraints_solver.add(self.state.partial_symbolic_constraint_solver.constraints)
                no_constraints_solver.add(simplified_addr == conc_addr)

                loaded_value = self.state.memory.load(conc_addr, self._ty_to_bytes(ty),
                                                      endness=self.state.arch.memory_endness)
                #conc_input_value = no_constraints_solver.eval(var_ast, 1)[0]
                loaded_values.append(loaded_value)

                # solve for the other variables with the above constraint on the addr
                conc_input_value = []
                for var_ast in var_ast_list:
                    conc_input_value = no_constraints_solver.eval(var_ast, 5)
                    new_ast_constraints.append(var_ast == conc_input_value[0])
                    # add this new constraint, and then solve for the rest as well
                    no_constraints_solver.add(var_ast == conc_input_value[0])

                if len(conc_input_value) == 1:
                    conc_addr_and_new_constraints.append((conc_addr, new_ast_constraints, result[0] == loaded_value))
                else:
                    #dont add a constraint on the ast since there's no single value that satisfies this, because we are going to use this for constant propagation
                    conc_addr_and_new_constraints.append((conc_addr, None, result[0] == loaded_value))

            if len(conc_addrs) == 1 or len(conc_addrs) > 2:
                print("Hmmmm")
                import ipdb;
                ipdb.set_trace()
            else:
                state_split_cond = claripy.BoolS('mba_state_split_cond')
                import ipdb;ipdb.set_trace()
                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0], claripy.If(state_split_cond, conc_addrs[0], conc_addrs[1]))
                self.state.partial_symbolic_constraint_solver._solver.add_replacement(result[0], claripy.If(state_split_cond, loaded_values[0], loaded_values[1]))
                #self.state.partial_symbolic_constraint_solver._solver.add(result[0] == claripy.If(state_split_cond, loaded_values[0], loaded_values[1]))

                self.state.globals['concretized_load_addr_dict'][result[0]] = (
                conc_addr_and_new_constraints, self._ty_to_bytes(ty), simplified_addr)

        return result

    def _handle_vex_defaultexit(self, expr, jumpkind):
        super()._handle_vex_defaultexit(expr, jumpkind)
        # if blockid is None then it's probably some weird VEX instruction and we are still in the same block most likely
        if isinstance(expr, pyvex.expr.RdTmp):
            if expr.block_id:
                self.state.globals['cur_block_id'] = expr.block_id
        else:
            if expr.con.block_id:
                self.state.globals['cur_block_id'] = expr.con.block_id

    def _handle_vex_stmt_Exit(self, stmt):
        super()._handle_vex_stmt_Exit(stmt)
        if stmt.dst.block_id:
            self.state.globals['cur_block_id'] = stmt.dst.block_id


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
  #  _tops = {}

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

    @staticmethod
    def top(bits: int) -> claripy.ast.Bits:
        """
        Get a TOP value.

        :param size:    Width of the TOP value (in bits).
        :return:        The TOP value.
        """
        # if bits in PropagatorState._tops:
        #     return PropagatorState._tops[bits]
        r = claripy.BVS("TOP", bits)#, explicit_name=True)

        # PropagatorState._tops[bits] = r
        return r

    @staticmethod
    def is_top(expr) -> bool:
        """
        Check if the given expression is a TOP value.

        :param expr:    The given expression.
        :return:        True if the expression is TOP, False otherwise.
        """
        if isinstance(expr, claripy.ast.Base):
            if expr.op == "BVS" and expr.args[0] == "TOP":
                return True
            if "TOP" in expr.variables:
                return True
            for var in expr.variables:
                if var.startswith("TOP"):
                    return True
        return False

    def _get_weakref(self):
        return weakref.proxy(self)

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

    def __repr__(self):
        return "<PropagatorVEXState>"

    def copy(self):
        new_replacements = defaultdict(dict)
        for loc, vars_ in self._replacements.items():
            new_replacements[loc] = vars_.copy()

        return PropagatorVEXState(self.arch, replacements=new_replacements)
        # return PropagatorVEXState(self.arch, replacements=self._replacements.copy())

    def merge(self, node, *all_states):
        #here we merge the input states and the input replacements
        #the replacements merge here is not what decides the fixed_point......... that happens in run_on_node
        #the replacements merge here are just to carry the replacements from other states e.g. multiple states merging into one

        #Collect all concretes states for the current node from all the abstract states and merge them

        conc_states_to_merge = []
        for state in all_states:
            other_conc_state = state.get_concrete_state(node.block_id)
            if other_conc_state is not None:
                conc_states_to_merge.append(other_conc_state)

        merged_concrete_state = None
        if len(conc_states_to_merge) != 0:
            merged_concrete_state = conc_states_to_merge[0]
            for cur_conc_state in conc_states_to_merge[1:]:
                merged_concrete_state = self._merge_concrete_states(merged_concrete_state, cur_conc_state)


            # merged_concrete_states = self._merge_concrete_states(other, node.block_id)
            merged_replacements = defaultdict(dict)
            for loc, vars_ in all_states[-1]._replacements.items():
                merged_replacements[loc] = vars_.copy()
            merge_occurred = False
            for state in all_states[:-1]:
                if state is not None:
                    merged_replacements, _ = self._merge_replacements(merged_replacements, state._replacements)

        if merged_concrete_state is None:
            import ipdb;ipdb.set_trace()

        return PropagatorVEXState(arch=self.arch, concrete_states=[merged_concrete_state], replacements=merged_replacements), None

    def _merge_concrete_states(self, state0, state1):
        """

        :param StorageState other:
        :return:
        :rtype:                             list
        """

        merged = [ ]
        # if not isinstance(self.concrete_states, list):
        #     self.concrete_states = self.concrete_states.all_successors

        merged_stuff = state0.merge(state1, plugin_whitelist=['inspect', 'preconstrainer', 'globals', 'mem', 'heap', 'regs', 'solver', 'callstack', 'history', 'fs', 'scratch', 'memory', 'registers', 'libc', 'partial_symbolic_constraint_solver'])
        return merged_stuff[0]

    def add_replacement(self, codeloc, old, new):
        if old not in self._replacements[codeloc]:
            self._replacements[codeloc][old] = new

        ## If it is not the same as the previous replacement then it is not a constant and should not be replaced
        elif self._replacements[codeloc][old].con.value != new.con.value:
            import ipdb;ipdb.set_trace()
            self._replacements[codeloc][old] = self.top(new.size())

    def _merge_replacements(self, replacements_0, replacements_1):
        merged_replacements = replacements_0
        merge_occurred = False
        for loc, vars_ in replacements_1.items():
            if loc not in merged_replacements:
                merged_replacements[loc] = vars_.copy()
                merge_occurred = True
            else:
                for var, repl in vars_.items():
                    if var not in merged_replacements[loc]:
                        merged_replacements[loc][var] = repl
                        merge_occurred = True
                    else:
                        if PropagatorState.is_top(repl) and PropagatorState.is_top(merged_replacements[loc][var]):
                            continue
                        elif PropagatorState.is_top(repl) or PropagatorState.is_top(merged_replacements[loc][var]):
                            size = None
                            if PropagatorState.is_top(repl):
                                size = repl.size()
                            else:
                                size = merged_replacements[loc][var].size()
                            t = PropagatorState.top(size)
                            merged_replacements[loc][var] = t
                            merge_occurred = True

                        elif merged_replacements[loc][var].con.value != repl.con.value:
                            t = PropagatorState.top(repl.size())
                            merged_replacements[loc][var] = t
                            merge_occurred = True

        return merged_replacements, merge_occurred


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
        self.symbolic_expr_locations_blockwise = {}
        self._engine_ail = None
        self._engine= PropagatorEmulatedEngine(project=self.project)
        self._analyze()
        self._initial_state = None

        #Merge all replacements from nodes that do not have any successors
        for node in graph.nodes():
            succs = graph.successors(node)
            if len(list(succs)) == 0:
                cur_abstract_state = self._states[node.block_id]
                self._merge_replacements(self.replacements, cur_abstract_state._replacements)
                print(node)

        #Get all the symbolic locations
        for loc, vars_ in self.replacements.items():
            for var, repl in vars_.items():
                if PropagatorState.is_top(repl):
                    if loc in self.symbolic_expr_locations_blockwise:
                        self.symbolic_expr_locations_blockwise[loc].append(var)
                    else:
                        self.symbolic_expr_locations_blockwise[loc] = [var]


        for key,value in self._states.items():
            self._states[key] = None

        print(len(self.symbolic_expr_locations_blockwise))
        print(len(self.replacements))

        # for block_key, iter in self._node_iterations.items():
        #     if iter<2:
        #         if block_key.addr == 0x48139d and block_key.vm_vpc == 4306815:
        #             print(block_key)
        #             import ipdb;ipdb.set_trace()
        #         if block_key.addr == 0x46b038 and block_key.vm_vpc == 4305884:
        #             print(block_key)
        #             import ipdb;
        #             ipdb.set_trace()
        #         if block_key.addr == 0x40a533 and block_key.vm_vpc == 4305884:
        #             print(block_key)
        #             import ipdb;
        #             ipdb.set_trace()
        #         if block_key.addr == 0x40a533 and block_key.vm_vpc == 4305884:
        #             print(block_key)
        #             import ipdb;
        #             ipdb.set_trace()

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
        self._initial_state = state
        return state

    def _merge_states(self, node, *states):
        #return states[-1], True
        if len(states) == 1:
            return states[0]
        # merged_abstract_state, fixedpoint_reached = reduce(lambda s_0, s_1: s_0.merge(s_1), states[1:], states[0])
        # return merged_abstract_state, fixedpoint_reached

        merged_state, merge_occurred = states[0].merge(node, *states)
        return merged_state, not merge_occurred
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
            print("No concrete state..... so no executing")
            # didn't find any state going here
            return False, abstract_state

        block_key = node.block_id
        #abstract_state = abstract_state.copy()
        if abstract_state is not self._initial_state:
            # make a copy of the state if it's not the initial state
            abstract_state = abstract_state.copy()
        else:
            # clear self._initial_state so that we *do not* run this optimization again!
            self._initial_state = None
        # if block_key in self._states:
        #     abstract_state = self._states[block_key]
        # else:
        #     abstract_state = PropagatorVEXState(arch=self.project.arch)


        node.input_state.globals['abstract_state'] = weakref.ref(abstract_state)
        node.input_state.globals['cur_block_id'] = block_key
        engine = self._engine
        # if node.addr == 0x1400d2181 and node.block_id.vm_vpc == 5368833050:
        #     import cProfile, pstats
        #     profiler = cProfile.Profile()
        #     profiler.enable()
        # if node.addr == 0x140061ee8 and node.block_id.vm_vpc == 5368833178:
        #     import ipdb;ipdb.set_trace()
        sim_successors = engine.process(node.input_state, opt_level=self._iropt_level, irsb=node.irsb)

        print("The length of the constraints is: "+str(len(node.input_state.solver.constraints)))
        # if node.addr == 0x1400d2181 and node.block_id.vm_vpc == 5368833050:
        #     profiler.disable()
        #     stats = pstats.Stats(profiler).sort_stats('tottime')
        #     stats.print_stats()
        #     import ipdb;
        #     ipdb.set_trace()
        print(sim_successors)

        if False:#node.is_simprocedure:
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

            if len(sim_successors.unconstrained_successors) == 1 and len(sim_successors.all_successors) == 1 and len(list(self.graph.successors(node))) !=0:

                new_states = []
                uncon_succ = sim_successors.unconstrained_successors[0]
                #poss_target = uncon_succ.partial_symbolic_constraint_solver._solver._replacement(uncon_succ.regs.ip)
                poss_target = uncon_succ.regs.ip

                # if it's till symbolic try to eval with the partial constraint solver
                #if uncon_succ.solver.symbolic(poss_target):
                try:
                    poss_target = uncon_succ.partial_symbolic_constraint_solver.eval_one(uncon_succ.regs.ip)
                except:
                    print("more than one target?, possible going to split states now")

               # poss_target = uncon_succ.solver.simplify(uncon_succ.scratch.target).replace_dict(uncon_succ.solver._solver._replacement_cache)

                if not uncon_succ.solver.symbolic(poss_target):
                    #import ipdb;ipdb.set_trace()
                    new_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
                    new_sim_successors.artifacts = sim_successors.artifacts
                    new_sim_successors.engine = sim_successors.engine
                    new_sim_successors.processed = sim_successors.processed
                    new_sim_successors.description = sim_successors.description
                    new_sim_successors.sort = sim_successors.sort

                    uncon_succ.regs.ip = poss_target

                    new_sim_successors.add_successor(uncon_succ, uncon_succ.partial_symbolic_constraint_solver.eval_one(uncon_succ.scratch.target),
                                                     uncon_succ.scratch.guard,
                                                     uncon_succ.history.jumpkind, True,
                                                     uncon_succ.scratch.exit_stmt_idx,
                                                     uncon_succ.scratch.exit_ins_addr,
                                                     uncon_succ.scratch.source)

                    sim_successors = new_sim_successors
                    sim_successors.artifacts['irsb_direct_next'] = True

                else:
                    repl_ip= sim_successors.all_successors[0].partial_symbolic_constraint_solver._solver._replacement(sim_successors.all_successors[0].regs.ip)

                    state_var_ast = []
                    for ast in repl_ip.leaf_asts():
                        if isinstance(ast.args[0], str) and ast.args[0].startswith('mba_state_split_cond') and ast.args[0] not in sim_successors.all_successors[0].globals['existing_mba_split_constraints']:
                            state_var_ast.append(ast)

                    if state_var_ast is None or len(state_var_ast) != 1:
                        import ipdb;ipdb.set_trace()

                    state_var_ast = state_var_ast[0]

                    sim_successors.all_successors[0].globals['existing_mba_split_constraints'].append(state_var_ast.args[0])

                    try:
                        # This eval result is not added to repalcements even though unsafe replacements is turned on number of solns must be only one
                        solns = sim_successors.unconstrained_successors[0].partial_symbolic_constraint_solver._solver.batch_eval([sim_successors.unconstrained_successors[0].regs.ip, state_var_ast], 4)
                    except:
                        import ipdb;ipdb.set_trace()

                    if len(solns) > 2:
                        import ipdb;ipdb.set_trace()
                    for soln_pair in solns:
                        new_state = sim_successors.unconstrained_successors[0].copy()
                        import ipdb;
                        ipdb.set_trace()

                        new_state.partial_symbolic_constraint_solver.add(state_var_ast == soln_pair[1])

                        # we are doing eval_one because only when one soln exists unsafe replacements will happen

                        k= new_state.partial_symbolic_constraint_solver.eval_one(new_state.partial_symbolic_constraint_solver._solver._replacement(new_state.regs.ip))

                        new_state.regs.ip = new_state.partial_symbolic_constraint_solver.eval_one(new_state.regs.ip)
                        new_state.scratch.target = new_state.partial_symbolic_constraint_solver.eval_one(new_state.scratch.target)


                        # Fill the block id
                        for node_succ in self.graph.successors(node):
                            try:
                                if new_state.solver.eval_one(new_state.regs.ip) == node_succ.addr:
                                    new_state.globals['cur_block_id'] = node_succ.block_id
                            except:
                                print("failed to set cur block id")
                                import ipdb;
                                ipdb.set_trace()

                        new_states.append(new_state)
                        import ipdb;ipdb.set_trace()


                    # for ast in sim_successors.unconstrained_successors[0].regs.ip.leaf_asts():
                    #     if ast in sim_successors.unconstrained_successors[0].globals['concretized_load_addr_dict']:
                    #         conc_addr_and_new_constraints = sim_successors.unconstrained_successors[0].globals['concretized_load_addr_dict'][ast][0]
                    #         if len(conc_addr_and_new_constraints) > 2:
                    #             print("More than two possible jumps? is this not a direct jump converted to an indirect jump?")
                    #             import ipdb;ipdb.set_trace()
                    #         for conc_addr, input_constraints, loaded_value_constraint in conc_addr_and_new_constraints:
                    #             sym_addr = sim_successors.unconstrained_successors[0].globals['concretized_load_addr_dict'][ast][2]
                    #             size = sim_successors.unconstrained_successors[0].globals['concretized_load_addr_dict'][ast][1]
                    #             new_state = sim_successors.unconstrained_successors[0].copy()
                    #
                    #
                    #             new_state.partial_symbolic_constraint_solver._solver.add_replacement(sym_addr, conc_addr, invalidate_cache=False)
                    #             new_state.partial_symbolic_constraint_solver.add(loaded_value_constraint)
                    #
                    #             if new_state.solver.symbolic(new_state.regs.ip):
                    #                 try:
                    #                     new_state.regs.ip = new_state.partial_symbolic_constraint_solver.eval_one(
                    #                         new_state.regs.ip)
                    #                 except:
                    #                     import ipdb;
                    #                     ipdb.set_trace()
                    #             if new_state.solver.symbolic(new_state.scratch.target):
                    #                 try:
                    #                     new_state.scratch.target = new_state.partial_symbolic_constraint_solver.eval_one(
                    #                         new_state.scratch.target)
                    #                 except:
                    #                     import ipdb;
                    #                     ipdb.set_trace()
                    #
                    #
                    #             # Fill the block id
                    #             for node_succ in self.graph.successors(node):
                    #                 try:
                    #                     if new_state.solver.eval_one(new_state.regs.ip) == node_succ.addr:
                    #                         new_state.globals['cur_block_id'] = node_succ.block_id
                    #                 except:
                    #                     print("failed to set cur block id")
                    #                     import ipdb;
                    #                     ipdb.set_trace()
                    #
                    #             new_states.append(new_state)

                    if len(new_states) != 0:
                        #import ipdb;ipdb.set_trace()
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


            for succ in sim_successors.all_successors:
                for graph_succ in self._graph.successors(node):
                    if succ.addr == graph_succ.addr:
                        succ.globals['cur_block_id'] = graph_succ.block_id

            symbolic_sim_successors = sim_successors

            if len(sim_successors.all_successors) >1:
                symbolic_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
                symbolic_sim_successors.artifacts = sim_successors.artifacts
                symbolic_sim_successors.engine = sim_successors.engine
                symbolic_sim_successors.processed = sim_successors.processed
                symbolic_sim_successors.description = sim_successors.description
                symbolic_sim_successors.sort = sim_successors.sort

                ## Only keep those successors that are already in the cfg
                for successor in sim_successors.all_successors:
                    keep=False
                    for graph_succ in self._graph.successors(node):
                        if successor.addr == graph_succ.addr:
                            keep=True

                    if keep:
                        if successor.solver.symbolic(successor.scratch.guard):
                            # special case to deal with preconstrained sp related guards
                            if len(list(successor.scratch.guard.variables)) == 1 and \
                                    list(successor.scratch.guard.variables)[0].startswith("precon_sp"):
                                try:
                                    if successor.solver.eval(successor.scratch.guard):
                                        symbolic_sim_successors.add_successor(successor, successor.scratch.target,
                                                                              successor.scratch.guard,
                                                                              successor.history.jumpkind, True,
                                                                              successor.scratch.exit_stmt_idx,
                                                                              successor.scratch.exit_ins_addr,
                                                                              successor.scratch.source)
                                except SimUnsatError:
                                    print("Hmmmmmmmmmmm")
                                    import ipdb;
                                    ipdb.set_trace()
                            else:
                                symbolic_sim_successors.add_successor(successor, successor.scratch.target,
                                                                      successor.scratch.guard,
                                                                      successor.history.jumpkind, True,
                                                                      successor.scratch.exit_stmt_idx,
                                                                      successor.scratch.exit_ins_addr,
                                                                      successor.scratch.source)


                        elif successor.scratch.guard.is_true():
                            # only adding successors that are non-symbolic and true guard
                            symbolic_sim_successors.add_successor(successor, successor.scratch.target,
                                                                  successor.scratch.guard,
                                                                  successor.history.jumpkind, True,
                                                                  successor.scratch.exit_stmt_idx,
                                                                  successor.scratch.exit_ins_addr,
                                                                  successor.scratch.source)


        print(symbolic_sim_successors.all_successors)
        print(symbolic_sim_successors)


        # If we don't do this it won't free the memory..... prolly due to cyclic references
        node.input_state.globals['abstract_state'] = None
        for succ in symbolic_sim_successors.all_successors:
            succ.globals['abstract_state'] = None
        #node.input_state.globals['cur_block_id'] = block_key

        changed = False
        prev_abstract_state = None
        if block_key in self._states:
            prev_abstract_state = self._states[block_key]
            # the comparision order matters
            changed = self._changed(prev_abstract_state._replacements, abstract_state._replacements)
        else:
            # It's the first time exploring this node
            changed = True

        if changed is False:
            merge_res = self._merge_replacements(self.replacements, abstract_state._replacements)

        print("replacemtns: "+str(len(abstract_state._replacements)))
        print("symb locs: "+str(len(self.symbolic_expr_locations_blockwise)))

        node.final_states = symbolic_sim_successors
        abstract_state.concrete_states = symbolic_sim_successors.all_successors
        self._node_iterations[block_key] += 1
        # this stores the last merged/normal state
        self._states[block_key] = abstract_state
        #self.replacements[block_key] = abstract_state._replacements

        print(self._node_iterations[block_key])
        print("Changed: "+str(changed))

        if changed:
            return True, abstract_state
        else:
            return False, abstract_state

    def _changed(self, replacements_0, replacements_1):
        #return not(replacements_1 == replacements_0)
        for loc, vars_ in replacements_1.items():
            if loc not in replacements_0:
                return True
            else:
                for var, repl in vars_.items():
                    if var not in replacements_0[loc]:
                        return True
                    else:
                        if PropagatorState.is_top(repl) and PropagatorState.is_top(replacements_0[loc][var]):
                            continue
                        elif PropagatorState.is_top(repl) or PropagatorState.is_top(replacements_0[loc][var]):
                            return True

                        elif replacements_0[loc][var].con.value != repl.con.value:
                            return True

        return False

    def _merge_replacements(self, replacements_0, replacements_1):
        merge_occurred = False
        for loc, vars_ in replacements_1.items():
            if loc not in replacements_0:
                replacements_0[loc] = vars_.copy()
                merge_occurred = True
            else:
                for var, repl in vars_.items():
                    if var not in replacements_0[loc]:
                        replacements_0[loc][var] = repl
                        merge_occurred = True
                    else:
                        if PropagatorState.is_top(repl) and PropagatorState.is_top(replacements_0[loc][var]):
                            continue
                        elif PropagatorState.is_top(repl) or PropagatorState.is_top(replacements_0[loc][var]):
                            size = None
                            if PropagatorState.is_top(repl):
                                size = repl.size()
                            else:
                                size = replacements_0[loc][var].size()
                            t = PropagatorState.top(size)
                            replacements_0[loc][var] = t
                            merge_occurred = True

                        elif replacements_0[loc][var].con.value != repl.con.value:
                            t = PropagatorState.top(repl.size())
                            replacements_0[loc][var] = t
                            merge_occurred = True

        return merge_occurred

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

register_analysis(PropagatorEmulatedAnalysis, "PropagatorEmulated")
