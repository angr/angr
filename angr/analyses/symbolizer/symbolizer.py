import weakref
from collections import defaultdict
from functools import reduce
import copy

import networkx

import ailment
import claripy
import pyvex
from angr.utils.graph import GraphUtils
from ..propagator.top_checker_mixin import TopCheckerMixin
from ..vm_deobfuscation.vm_deobfuscation import DataSensitiveRdTmp, DataSensitiveU64, DataSensitiveU32
from ...engines.light import SimEngineLightVEXMixin
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
from .. import register_analysis
from ..analysis import Analysis
from ..cfg.cfg_vm_deobfuscation import StackTouchedAnnotation, DataRegionAnnotation, VMStackVariableAnnotation
from ..forward_analysis.visitors.graph import GraphVisitor
from ..forward_analysis import ForwardAnalysis
from .values import TOP
from ...storage import SimMemoryObject

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
            # if cur_abstract_state.is_top(result[0]):
            #     skip = True

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
                not (cur_abstract_state._replacements[code_loc][expr] == "TOP") and \
                cur_abstract_state._replacements[code_loc][expr].con.value != simp_result.args[0]:

            cur_abstract_state._replacements[code_loc][expr] = "TOP"

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
        elif self.state.solver.symbolic(simp_result) and expr in cur_abstract_state._replacements[code_loc] and not (cur_abstract_state._replacements[code_loc][expr] == "TOP"):
            #del cur_abstract_state._replacements[code_loc][expr]
            cur_abstract_state._replacements[code_loc][expr] = "TOP"
            # cur_abstract_state.symbolic_expr_locations[code_loc].append(expr)


        return [simp_result, result[1]]


    def _perform_vex_expr_Load(self, addr, ty, endness, **kwargs):
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

        conc_addrs = self.state.partial_symbolic_constraint_solver.eval_upto(addr[0],5)
        ast_addrs = []
        for con_addr in conc_addrs:
            ast_addrs.append(claripy.BVV(con_addr, addr[0].size()))

        conc_addrs = ast_addrs

        if len(conc_addrs) < 5:
            if isinstance(result[0].args[0], str) and result[0].args[0].startswith('symbolic_read_unconstrained_') and not merged_stack_address:
                if not self.state.solver.symbolic(simplified_addr):
                    return result
                save = True

        if len(var_ast_list) > 1:
            print("More than one variables? which one to save.... maybe both")


        if save:
            loaded_values = []
            for conc_addr in conc_addrs:
                loaded_value = self.state.memory.load(conc_addr, self._ty_to_bytes(ty),
                                                      endness=self.state.arch.memory_endness)
                loaded_values.append(loaded_value)

            if len(conc_addrs) == 1 or len(conc_addrs) > 2:
                print("Hmmmm")
                import ipdb;
                ipdb.set_trace()
            else:
                state_split_cond = claripy.BoolS('mba_state_split_cond')
                addr_mba=claripy.If(state_split_cond, conc_addrs[0], conc_addrs[1])
                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0], addr_mba)
                to_return=claripy.If(state_split_cond, loaded_values[0], loaded_values[1])
                self.state.partial_symbolic_constraint_solver._solver.add_replacement(result[0], to_return)


                ## This to add addrs which are of the following form mba+offset, mba+4
                if addr[0].op in ["__add__","__sub__"]:
                    if len(addr[0].args) == 2:
                        if addr[0].args[0].depth == 1:
                            if addr[0].op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[1], claripy.If(state_split_cond, conc_addrs[0] - addr[0].args[0], conc_addrs[1] - addr[0].args[0]))
                            elif addr[0].op == "__sub__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[1], claripy.If(state_split_cond, addr[0].args[0] - conc_addrs[0], addr[0].args[0] - conc_addrs[1]))
                        elif addr[0].args[1].depth == 1:
                            if addr[0].op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[0] ,claripy.If(state_split_cond, conc_addrs[0] - addr[0].args[1], conc_addrs[1] - addr[0].args[1]))
                            elif addr[0].op == "__sub__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[0] ,claripy.If(state_split_cond, conc_addrs[0] + addr[0].args[1], conc_addrs[1] + addr[0].args[1]))

                    elif len(addr[0].args) == 3:
                        if addr[0].args[0].depth == 1:
                            if addr[0].op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[1] + addr[0].args[2], claripy.If(state_split_cond, conc_addrs[0] - addr[0].args[0], conc_addrs[1] - addr[0].args[0]))
                            elif addr[0].op == "__sub__":
                                print("Not implemented")
                                import ipdb;
                                ipdb.set_trace()
                        elif addr[0].args[1].depth == 1:
                            if addr[0].op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[0] + addr[0].args[2],claripy.If(state_split_cond, conc_addrs[0] - addr[0].args[1], conc_addrs[1] - addr[0].args[1]))
                            elif addr[0].op == "__sub__":
                                print("Not implemented")
                                import ipdb;
                                ipdb.set_trace()
                        elif addr[0].args[2].depth == 1:
                            if addr[0].op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[0] + addr[0].args[1],claripy.If(state_split_cond, conc_addrs[0] - addr[0].args[2], conc_addrs[1] - addr[0].args[2]))
                            elif addr[0].op == "__sub__":
                                print("Not implemented")
                                import ipdb;
                                ipdb.set_trace()

                ## Do replacement for all registers and temps just to be safe....... although the mba can still be on stack...... will deal with it later.
                ## That should not be a problem since we try to evaluate every address above, so it should be resolved
                for ind in range(len(self.state.scratch.temps)):
                    if self.state.scratch.temps[ind] is not None:
                        self.state.scratch.temps[
                            ind] = self.state.partial_symbolic_constraint_solver._solver._replacement(
                            self.state.scratch.temps[ind])

                for reg in self.state.arch.registers.keys():
                    offset = self.state.arch.registers[reg][0]
                    size = self.state.arch.registers[reg][1]
                    old_val = self.state.registers.load(offset, size)
                    new_val = self.state.partial_symbolic_constraint_solver._solver._replacement(old_val)
                    if old_val is not new_val:
                        self.state.registers.store(offset, new_val)

                return [to_return, result[1]]

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
        sorted_nodes = GraphUtils.quasi_topological_sort_nodes(self.graph)
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
        if isinstance(expr, str) and expr == "TOP":
            return True
        else:
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
        to_return = []
        possible_successors =self.concrete_states
        #else:
        #    possible_successors = self.concrete_states.all_successors
        for s in possible_successors:
            if s.globals['cur_block_id'] == block_id:
                to_return.append(s)

        return to_return

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
            other_conc_states = state.get_concrete_state(node.block_id)
            if other_conc_states is not None:
                conc_states_to_merge = conc_states_to_merge + other_conc_states

        merged_concrete_states = []
        merged_concrete_state = None
        states_on_same_sp =defaultdict(list)

        #group states based on same stack pointer value
        for cur_conc_state in conc_states_to_merge:
            states_on_same_sp[cur_conc_state.solver.eval_one(cur_conc_state.regs.sp)].append(cur_conc_state)
        # We have states which don't have matching stack pointer, so we should not be merging now

        ## make sure they have the same stack pointer exactly other merging will result in TOP
        for addr, states_to_merge_same_sp in states_on_same_sp.items():
            for cur_conc_state in states_to_merge_same_sp[1:]:
                cur_conc_state.regs.sp = states_to_merge_same_sp[0].regs.sp

        merged_concrete_states = []
        for addr, states_to_merge_same_sp in states_on_same_sp.items():
            merged_concrete_state = states_to_merge_same_sp[0]
            for cur_conc_state in states_to_merge_same_sp[1:]:
                merged_concrete_state = self._merge_concrete_states(merged_concrete_state, cur_conc_state)
            merged_concrete_states.append(merged_concrete_state)

        # if len(states_on_same_sp) != 1:
        #     import ipdb;
        #     ipdb.set_trace()


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

        return PropagatorVEXState(arch=self.arch, concrete_states=merged_concrete_states, replacements=merged_replacements), None

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
                        if self.is_top_str(repl) and self.is_top_str(merged_replacements[loc][var]):
                            continue
                        elif self.is_top_str(repl) or self.is_top_str(merged_replacements[loc][var]):
                            merged_replacements[loc][var] = "TOP"
                            merge_occurred = True

                        elif merged_replacements[loc][var].con.value != repl.con.value:
                            t = "TOP"
                            merged_replacements[loc][var] = t
                            merge_occurred = True

        return merged_replacements, merge_occurred

    def is_top_str(self, repl):
        if isinstance(repl, str) and repl == "TOP":
            return True
        return False


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


class Symbolizer(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
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
        self._prev_input_states = { }
        self._engine= PropagatorEmulatedEngine(project=self.project)
        self._analyze()
        self._initial_state = None

        for node in graph.nodes():
            ## end points which are not reachable are skippe from replacements collections
            if node.block_id in self._states:
                cur_abstract_state = self._states[node.block_id]
                self.replacements[node.block_id] = cur_abstract_state._replacements

        #Get all the symbolic locations
        self.symbolic_expr_locations_blockwise = defaultdict(dict)
        for block_id, repls in self.replacements.items():
            for codeloc, exprs_repls in repls.items():
                for expr, repl in exprs_repls.items():
                    if self.is_top_str(repl):
                        if codeloc in self.symbolic_expr_locations_blockwise[block_id]:
                            self.symbolic_expr_locations_blockwise[block_id][codeloc].append(expr)
                        else:
                            self.symbolic_expr_locations_blockwise[block_id][codeloc] = [expr]


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

    ## This mo_cmp is just to check fixed point
    @staticmethod
    def _mo_cmp(
        mo_self,
        mo_other,
        addr: int,
        size: int,
    ):  # pylint:disable=unused-argument
        # comparing bytes from two sets of memory objects
        # we don't need to resort to byte-level comparison. object-level is good enough.
        if PropagatorState.is_top(mo_self.object) and PropagatorState.is_top(mo_other.object):
            return True

        return None

    def _initial_abstract_state(self, node):
        if not node.input_state:
            # This is for nodes that do not have any concrete state yet
            return PropagatorVEXState(arch=self.project.arch, concrete_states=[])
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
        # if str(node) == "<CFGENode 0x140061ee8 ()vm-vpc:5368833178 [2]>":
        #     import ipdb;ipdb.set_trace()

        concrete_states = abstract_state.get_concrete_state(node.block_id)
        if len(concrete_states) == 0:
            print("No concrete state..... so no executing")
            # didn't find any state going here
            return False, abstract_state

        if node.block_id in self._prev_input_states and len(list(self.graph.predecessors(node))) > 1 and len(concrete_states) == 1:
            if len(self._prev_input_states[node.block_id]) > 1:
                import ipdb;ipdb.set_trace()
            # right now we assume only one concrete state
            changed = self.compare_concrete_states(concrete_states[0], self._prev_input_states[node.block_id][0])
        elif node.block_id in self._prev_input_states and len(concrete_states) == 1 and concrete_states[0].globals['same_sp_merged']:
            if len(self._prev_input_states[node.block_id]) > 1:
                import ipdb;ipdb.set_trace()
            concrete_states[0].globals['same_sp_merged'] = False
            # right now we assume only one concrete state
            changed = self.compare_concrete_states(concrete_states[0], self._prev_input_states[node.block_id][0])
        else:
            changed = True

        self._prev_input_states[node.block_id] = concrete_states


        if not changed:
            return False, abstract_state

        # if abstract_state is not self._initial_state:
        #     print("copying state")
        #     # make a copy of the state if it's not the initial state
        #     abstract_state = abstract_state.copy()
        #     print("done")
        #
        #     # clear previous saved abstract states
        #     if len(list(self.graph.predecessors(node))) == 1:
        #         for pred in self.graph.predecessors(node):
        #             if len(list(self.graph.predecessors(pred))) > 1:
        #                 continue
        #             else:
        #                 self._states[pred.block_id] = None
        #                 self._input_states[pred] = None

        if abstract_state is not self._initial_state:
            # make a copy of the state if it's not the initial state
            if node.block_id in self._states:
                prev_replacements = self._states[node.block_id]._replacements
                abstract_state = PropagatorVEXState(arch=self.project.arch, replacements=prev_replacements)
            else:
                abstract_state = PropagatorVEXState(arch=self.project.arch)



        else:
            # clear self._initial_state so that we *do not* run this optimization again!
            self._initial_state = None

        all_successors = defaultdict(list)
        changed = False


        for conc_state in concrete_states:
            block_key = node.block_id

            conc_state.globals['abstract_state'] = weakref.ref(abstract_state)
            conc_state.globals['cur_block_id'] = block_key
            conc_state.globals['cur_iter'] = self._node_iterations[block_key]
            engine = self._engine
            # if node.addr == 0x1400d2181 and node.block_id.vm_vpc == 5368833050:
            # import cProfile, pstats
            # profiler = cProfile.Profile()
            # profiler.enable()
            sim_successors = engine.process(conc_state, opt_level=self._iropt_level, irsb=node.irsb)
            # if PropagatorState.is_top(sim_successors.all_successors[0].regs.esp):
            #     import ipdb;ipdb.set_trace()
            # profiler.disable()
            # stats = pstats.Stats(profiler).sort_stats('tottime')
            #
            # if stats.total_tt > 6:
            #     stats.print_stats()
            #     import ipdb;
            #     ipdb.set_trace()

            # for connie in sim_successors.all_successors[0].solver.constraints:
            #     if connie.depth > 15:
            #         import ipdb;ipdb.set_trace()

            # for connie in sim_successors.all_successors[0].partial_symbolic_constraint_solver.constraints:
            #     if connie.depth > 15:
            #         for var in connie.variables:
            #             if var.startswith("mba") or var.startswith("TOP"):
            #                 import ipdb;ipdb.set_trace()
            #                 break

            print("The length of the constraints is: "+str(len(conc_state.solver.constraints)))
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

                        # if len(state_var_ast) != 1:
                        #     import ipdb;ipdb.set_trace()

                        if len(state_var_ast) > 0:

                            state_var_ast = state_var_ast[0]

                            sim_successors.all_successors[0].globals['existing_mba_split_constraints'].append(state_var_ast.args[0])

                            try:
                                # This eval result is not added to repalcements even though unsafe replacements is turned on number of solns must be only one
                                solns = sim_successors.unconstrained_successors[0].partial_symbolic_constraint_solver._solver.batch_eval([sim_successors.unconstrained_successors[0].regs.ip, state_var_ast], 5)
                            except:
                                import ipdb;ipdb.set_trace()

                            if len(solns) > 2:
                                import ipdb;ipdb.set_trace()

                            for soln_pair in solns:
                                new_state = sim_successors.unconstrained_successors[0].copy()


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
                                # import ipdb;ipdb.set_trace()
                        else:
                            import ipdb;
                            ipdb.set_trace()
                            new_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
                            new_sim_successors.artifacts = sim_successors.artifacts
                            new_sim_successors.engine = sim_successors.engine
                            new_sim_successors.processed = sim_successors.processed
                            new_sim_successors.description = sim_successors.description
                            new_sim_successors.sort = sim_successors.sort

                            uncon_succ.regs.ip = list(self.graph.successors(node))[0].addr

                            new_sim_successors.add_successor(uncon_succ, list(self.graph.successors(node))[0].addr,
                                                             uncon_succ.scratch.guard,
                                                             uncon_succ.history.jumpkind, True,
                                                             uncon_succ.scratch.exit_stmt_idx,
                                                             uncon_succ.scratch.exit_ins_addr,
                                                             uncon_succ.scratch.source)

                            sim_successors = new_sim_successors
                            sim_successors.artifacts['irsb_direct_next'] = True


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
                    print("Before:removing succs")
                    print(sim_successors.all_successors)
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
            conc_state.globals['abstract_state'] = None
            for succ in symbolic_sim_successors.all_successors:
                succ.globals['abstract_state'] = None
            # node.input_state.globals['cur_block_id'] = block_key

            #self._merge_replacements(self.replacements, abstract_state._replacements)

            for succ in symbolic_sim_successors.all_successors:
                all_successors[succ.regs.ip].append(succ)

            prev_abstract_state = None

            # if not changed:
            #     if block_key in self._states and self._states[block_key]:
            #         prev_abstract_state = self._states[block_key]
            #         # the comparision order matters
            #         changed = self._changed(prev_abstract_state._replacements, abstract_state._replacements)
            #     else:
            #         # It's the first time exploring this node
            #         changed = True
            #
            # if changed is False:
            #     merge_res = self._merge_replacements(self.replacements, abstract_state._replacements)

            # for succ in symbolic_sim_successors.all_successors:
            #     all_successors[succ.regs.ip].append(succ)

        print("replacemtns: "+str(len(self.replacements)))
        print("symb locs: "+str(len(self.symbolic_expr_locations_blockwise)))

        #trying to merge same addr successors, this is part of the late mergning strategy
        merged_state_collection = []
        for addr, states in all_successors.items():
            if len(states) > 2:
                import ipdb;ipdb.set_trace()

            elif len(states) == 2:
                if states[0].solver.eval_one(states[0].regs.sp) == states[1].solver.eval_one(states[1].regs.sp):
                    merged_stuff = states[0].merge(states[1],
                                                plugin_whitelist=['inspect', 'preconstrainer', 'globals', 'mem', 'heap',
                                                                  'regs', 'solver', 'callstack', 'history', 'fs', 'scratch',
                                                                  'memory', 'registers', 'libc',
                                                                  'partial_symbolic_constraint_solver'])
                    merged_stuff[0].globals["same_sp_merged"] = True

                    merged_state_collection.append(merged_stuff[0])

                else:
                    merged_state_collection = merged_state_collection + states
            else:
                merged_state_collection = merged_state_collection + states

        #node.final_states = symbolic_sim_successors
        abstract_state.concrete_states = merged_state_collection
        self._node_iterations[block_key] += 1
        # this stores the last merged/normal state
        #self.replacements[block_key] = abstract_state._replacements

        print(self._node_iterations[block_key])
        print("Changed: "+str(changed))

        # if node.block_id in self._states and len(list(self.graph.predecessors(node))) > 1:
        #     changed = self.compare_concrete_states(abstract_state, self._states[node.block_id])
        # else:
        #     changed = True

        self._states[block_key] = abstract_state

        return True, abstract_state

        # if changed:
        #     return True, abstract_state
        # else:
        #     return False, abstract_state

    def compare_concrete_states(self, conc_state0, conc_state1):
        changed = False

        # if len(conc_state1.concrete_states) == len(conc_state0.concrete_states) and len(conc_state1.concrete_states) == 1:
        all_plugins = set(conc_state1.plugins.keys())
        for p in all_plugins:
            if p in ["memory","registers"]:
                plugin0 = conc_state0.plugins[p]
                plugin1 = conc_state1.plugins[p]
                changed_pages = self.changed_pages(plugin1, plugin0)
                if len(changed_pages) != 0:
                    return True

        return changed

    def changed_pages(self,plugin0, plugin1):
        my_pages = set(plugin0._pages)
        other_pages = set(plugin1._pages)
        intersection = my_pages.intersection(other_pages)
        difference = my_pages.symmetric_difference(other_pages)
        changes= {d: None for d in difference}

        for pageno in intersection:
            my_page = plugin0._pages[pageno]
            other_page = plugin1._pages[pageno]

            if (my_page is None) ^ (other_page is None):
                changes[pageno] = None
            elif my_page is None:
                pass
            elif my_page is other_page:
                pass
            else:
                changed_offsets = self.changed_bytes(my_page, other_page, page_addr=pageno * plugin0.page_size)
                if changed_offsets:
                    changes[pageno] = changed_offsets

        return changes

    def changed_bytes(self, cur_page, other: "ListPage", page_addr: int = None):
        candidates = None
        if candidates is None:
            candidates = set()
            if cur_page.sinkhole is None:
                candidates |= cur_page.stored_offset
            else:
                for i in range(len(cur_page.content)):
                    if cur_page._contains(i, page_addr):
                        candidates.add(i)

            if other.sinkhole is None:
                candidates |= other.stored_offset
            else:
                for i in range(len(other.content)):
                    if other._contains(i, page_addr):
                        candidates.add(i)

        byte_width = 8  # TODO: Introduce self.state if we want to use self.state.arch.byte_width
        differences = set()
        for c in candidates:
            s_contains = cur_page._contains(c, page_addr)
            o_contains = other._contains(c, page_addr)
            if not s_contains and o_contains:
                differences.add(c)
            elif s_contains and not o_contains:
                differences.add(c)
            else:
                if cur_page.content[c] is None:
                    cur_page.content[c] = SimMemoryObject(
                        cur_page.sinkhole.bytes_at(page_addr + c, 1),
                        page_addr + c,
                        byte_width=byte_width,
                        endness="Iend_BE",
                    )
                if other.content[c] is None:

                    other.content[c] = SimMemoryObject(
                        other.sinkhole.bytes_at(page_addr + c, 1),
                        page_addr + c,
                        byte_width=byte_width,
                        endness="Iend_BE",
                    )

                if s_contains and cur_page.content[c] != other.content[c]:
                    same = None
                    if self._mo_cmp is not None:
                        same = self._mo_cmp(cur_page.content[c], other.content[c], page_addr + c, 1)
                    if same is None:
                        # Try to see if the bytes are equal
                        self_byte = cur_page.content[c].bytes_at(page_addr + c, 1)
                        other_byte = other.content[c].bytes_at(page_addr + c, 1)
                    #    same = self_byte is other_byte
                    # Ashwin added this to remove the problem that arises from comparing same valued asts with different(only hash is different) annotations
                        if not (self_byte == other_byte).is_true():
                            differences.add(c)

                    if same is False:
                        differences.add(c)
                else:
                    # this means the byte is in neither memory
                    pass

        return differences

    def _changed(self, replacements_0, replacements_1):
        return not(replacements_1 == replacements_0)
        # for loc, vars_ in replacements_1.items():
        #     if loc not in replacements_0:
        #         return True
        #     else:
        #         for var, repl in vars_.items():
        #             if var not in replacements_0[loc]:
        #                 return True
        #             else:
        #                 if PropagatorState.is_top(repl) and PropagatorState.is_top(replacements_0[loc][var]):
        #                     continue
        #                 elif PropagatorState.is_top(repl) or PropagatorState.is_top(replacements_0[loc][var]):
        #                     return True
        #
        #                 elif replacements_0[loc][var].con.value != repl.con.value:
        #                     return True
        #
        # return False

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
                        if self.is_top_str(repl) and self.is_top_str(replacements_0[loc][var]):
                            continue
                        elif self.is_top_str(repl) or self.is_top_str(replacements_0[loc][var]):
                            replacements_0[loc][var] = "TOP"
                            merge_occurred = True

                        elif replacements_0[loc][var].con.value != repl.con.value:
                            replacements_0[loc][var] = "TOP"
                            merge_occurred = True

        return merge_occurred

    def is_top_str(self, repl):
        if isinstance(repl, str) and repl == "TOP":
            return True
        return False


    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

register_analysis(Symbolizer, "Symbolizer")
