from itertools import count
from typing import Optional, List, Dict, Tuple, Set, Callable, Any, TYPE_CHECKING

import networkx

import claripy

from ...sim_options import NO_CROSS_INSN_OPT, SYMBOL_FILL_UNCONSTRAINED_MEMORY, SYMBOL_FILL_UNCONSTRAINED_REGISTERS
from ...state_plugins.inspect import BP_BEFORE, BP_AFTER, BP
from ..analysis import Analysis, AnalysesHub

if TYPE_CHECKING:
    from angr import SimState
    from angr.knowledge_plugins.functions import Function
    from .abstract_state import AbstractStateFields


class ConstraintLogger:
    """
    Logs constraints and where they are created via the on_adding_constraints callback.
    """
    def __init__(self, mapping: Dict[claripy.ast.Base,Tuple[int,int]]):
        self.mapping = mapping

    def on_adding_constraints(self, state: 'SimState'):
        added_constraints = state._inspect_getattr('added_constraints', None)
        if not (len(added_constraints) == 1 and (
                claripy.is_true(added_constraints[0]) or
                claripy.is_false(added_constraints[0]))):
            for constraint in added_constraints:
                self.mapping[constraint] = state.scratch.irsb.addr, state.scratch.stmt_idx


class ExpressionLogger:
    """
    Logs symbolic expressions and where they are created via the on_register_write callback.
    """
    def __init__(self, mapping: Dict[claripy.ast.Base,Tuple[int,int]], variables: Set[str]):
        self.mapping = mapping
        self.variables: Set[str] = variables if variables else set()

    def on_memory_read(self, state: 'SimState'):
        expr = state._inspect_getattr("mem_read_expr", None)
        if expr is not None and expr.symbolic and expr.variables.intersection(self.variables):
            mem_read_addr = state._inspect_getattr("mem_read_address", None)
            if mem_read_addr is not None:
                if isinstance(mem_read_addr, int):
                    self.mapping[expr] = mem_read_addr
                elif not mem_read_addr.symbolic:
                    self.mapping[expr] = mem_read_addr._model_concrete.value

    def on_register_write(self, state: 'SimState'):
        expr = state._inspect_getattr('reg_write_expr', None)
        if expr is not None and expr.symbolic and expr.variables.intersection(self.variables):
            if expr not in self.mapping:
                # do not overwrite an existing source - it might have been from a memory read, which is the real source...
                self.mapping[expr] = state.scratch.irsb.addr, state.scratch.stmt_idx


class DefinitionNode:
    def __init__(self, variable: str, block_addr: int, stmt_idx: int):
        self.variable = variable
        self.block_addr = block_addr
        self.stmt_idx = stmt_idx

    def __eq__(self, other):
        return (
                isinstance(other, DefinitionNode)
                and self.variable == other.variable
                and self.block_addr == other.block_addr
        )

    def __hash__(self):
        return hash((DefinitionNode, self.variable, self.block_addr, self.stmt_idx))

    def __repr__(self):
        return f"{self.variable}@{self.block_addr:#x}:{self.stmt_idx}"


class SliceGenerator:
    def __init__(self, symbolic_exprs: Set[claripy.ast.Base], bp: Optional[BP]=None):
        self.bp: Optional[BP] = bp
        self.symbolic_exprs = symbolic_exprs
        self.expr_variables = set()

        # FIXME: The algorithm is hackish and incorrect. We should fix it later.
        self._last_statements = { }
        self.slice = networkx.DiGraph()

        for expr in self.symbolic_exprs:
            self.expr_variables |= expr.variables

        if self.bp is not None:
            self.bp.action = self._examine_expr

    def install_expr_hook(self, state: 'SimState') -> BP:
        bp = BP(when=BP_AFTER, enabled=False, action=self._examine_expr)
        state.inspect.add_breakpoint('expr', bp)
        self.bp = bp
        return bp

    def _examine_expr(self, state: 'SimState'):
        expr = state._inspect_getattr('expr_result', None)
        if state.solver.symbolic(expr) and expr.variables.intersection(self.expr_variables):

            variables = expr.variables
            curr_loc = state.scratch.irsb.addr, state.scratch.stmt_idx
            for v in variables:
                pred = self._last_statements.get(v, None)
                if pred is not None:
                    self.slice.add_edge(DefinitionNode(v, pred[0], pred[1]),
                                        DefinitionNode(v, curr_loc[0], curr_loc[1]))
                self._last_statements[v] = curr_loc
            # print(expr, state.scratch.irsb.statements[state.scratch.stmt_idx])


class StateGraphRecoveryAnalysis(Analysis):
    """
    Traverses a function and derive a state graph with respect to given variables.
    """
    def __init__(self, func: 'Function', fields: 'AbstractStateFields', software: str,
                 time_addr: int, temp_addr: int = None,
                 init_state: Optional['SimState']=None, switch_on: Optional[Callable]=None,
                 printstate: Optional[Callable]=None,
                 config_vars: Optional[Set[claripy.ast.Base]]=None,
                 patch_callback: Optional[Callable]=None):
        self.func = func
        self.fields = fields
        self.config_vars = config_vars if config_vars is not None else set()
        self.software = software
        self.init_state = init_state
        self._switch_on = switch_on
        self._ret_trap: int = 0x1f37ff4a
        self.printstate = printstate
        self.patch_callback = patch_callback

        self._time_addr = time_addr
        self._temp_addr = temp_addr
        self._tv_sec_var = None
        self._temperature = None
        self.state_graph = None
        self._expression_source = {}

        self.traverse()

    def traverse(self):

        # create an empty state graph
        self.state_graph = networkx.DiGraph()

        # make the initial state
        init_state = self._initialize_state(init_state=self.init_state)

        symbolic_input_fields = self._symbolize_input_fields(init_state)
        symbolic_time_counters = self._symbolize_timecounter(init_state)
        if self._temp_addr is not None:
            symbolic_temperature = self._symbolize_temp(init_state)

        # setup inspection points to catch where expressions are created
        all_vars = set(symbolic_input_fields.values())
        all_vars |= set(symbolic_time_counters.values())
        if self._temp_addr is not None:
            all_vars |= set(symbolic_temperature.values())
        all_vars |= self.config_vars
        slice_gen = SliceGenerator(all_vars, bp=None)
        expression_bp = slice_gen.install_expr_hook(init_state)

        # setup inspection points to catch where expressions are written to registers
        expression_logger = ExpressionLogger(self._expression_source, { v.args[0] for v in all_vars })
        regwrite_bp = BP(when=BP_BEFORE, enabled=True, action=expression_logger.on_register_write)
        init_state.inspect.add_breakpoint('reg_write', regwrite_bp)
        memread_bp = BP(when=BP_AFTER, enabled=True, action=expression_logger.on_memory_read)
        init_state.inspect.add_breakpoint('mem_read', memread_bp)

        # Abstract state ID counter
        abs_state_id_ctr = count(0)

        abs_state = self.fields.generate_abstract_state(init_state)
        abs_state_id = next(abs_state_id_ctr)
        self.state_graph.add_node((('NODE_CTR', abs_state_id),) + abs_state, outvars = dict(abs_state))
        state_queue = [(init_state, abs_state_id, abs_state, None, None, None, None, None, None, None)]
        if self._switch_on is None:
            countdown_timer = 0
            switched_on = True
            time_delta_and_sources = self._discover_time_deltas(init_state)

            for delta, constraint, source in time_delta_and_sources:
                if source is None:
                    block_addr, stmt_idx = -1, -1
                else:
                    block_addr, stmt_idx = source
                print(f"[.] Discovered a new time interval {delta} defined at {block_addr:#x}:{stmt_idx}")
            if self._temp_addr is not None:
                temp_delta_and_sources = self._discover_temp_deltas(init_state)
                for delta, constraint, source in temp_delta_and_sources:
                    if source is None:
                        block_addr, stmt_idx = -1, -1
                    else:
                        block_addr, stmt_idx = source
                    print(f"[.] Discovered a new temperature {delta} defined at {block_addr:#x}:{stmt_idx}")

            if temp_delta_and_sources or time_delta_and_sources:

                if temp_delta_and_sources:

                    for temp_delta, temp_constraint, temp_src in temp_delta_and_sources:
                        # append two states in queue
                        op = temp_constraint.args[0].op
                        prev = init_state.memory.load(self._temp_addr, 8,
                                                      endness=self.project.arch.memory_endness).raw_to_fp()
                        prev_temp = init_state.solver.eval(prev)
                        if op in ['fpLEQ', 'fpLT', 'fpGEQ', 'fpGT']:
                            if prev_temp < temp_delta:
                                delta0, temp_constraint0, temp_src0 = None, None, None
                                delta1, temp_constraint1, temp_src1 = temp_delta + 1.0, temp_constraint, temp_src

                                new_state = self._initialize_state(init_state=init_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_input_fields = self._symbolize_input_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_input_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append(
                                    (new_state, abs_state_id, abs_state, None, None, None, None, delta1,
                                     temp_constraint1, temp_src1))
                            elif prev_temp > temp_delta:
                                delta0, temp_constraint0, temp_src0 = temp_delta - 1.0, temp_constraint, temp_src
                                delta1, temp_constraint1, temp_src1 = None, None, None

                                new_state = self._initialize_state(init_state=init_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_input_fields = self._symbolize_input_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_input_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append(
                                    (new_state, abs_state_id, abs_state, None, None, None, None, delta0,
                                     temp_constraint0, temp_src0))
                            else:
                                import ipdb;
                                ipdb.set_trace()

                        elif op in ['fpEQ']:
                            # import ipdb; ipdb.set_trace()
                            new_state = self._initialize_state(init_state=init_state)

                            # re-symbolize input fields, time counters, and update slice generator
                            symbolic_input_fields = self._symbolize_input_fields(new_state)
                            symbolic_time_counters = self._symbolize_timecounter(new_state)
                            symbolic_temperature = self._symbolize_temp(new_state)
                            all_vars = set(symbolic_input_fields.values())
                            all_vars |= set(symbolic_time_counters.values())
                            all_vars |= set(symbolic_temperature.values())
                            all_vars |= self.config_vars
                            slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                            state_queue.append((new_state, abs_state_id, abs_state, None, None, None, None,
                                                temp_delta, temp_constraint, temp_src))
                            continue

                        if time_delta_and_sources:
                            # print(time_delta_constraint)
                            for time_delta, time_constraint, time_src in time_delta_and_sources:
                                # append state satisfy constraint
                                new_state = self._initialize_state(init_state=init_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_input_fields = self._symbolize_input_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_input_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append((new_state, abs_state_id, abs_state, None, time_delta,
                                                    time_constraint, time_src, delta0, temp_constraint0, temp_src0))

                                # append state not satisfy constraint
                                new_state = self._initialize_state(init_state=init_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_input_fields = self._symbolize_input_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_input_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append((new_state, abs_state_id, abs_state, None, time_delta,
                                                    time_constraint, time_src, delta1, temp_constraint1, temp_src1))

                # only discover time delta
                else:
                    for time_delta, time_constraint, time_src in time_delta_and_sources:
                        new_state = self._initialize_state(init_state=init_state)

                        # re-symbolize input fields, time counters, and update slice generator
                        symbolic_input_fields = self._symbolize_input_fields(new_state)
                        symbolic_time_counters = self._symbolize_timecounter(new_state)
                        all_vars = set(symbolic_input_fields.values())
                        all_vars |= set(symbolic_time_counters.values())
                        if self._temp_addr is not None:
                            symbolic_temperature = self._symbolize_temp(new_state)
                            all_vars |= set(symbolic_temperature.values())
                        all_vars |= self.config_vars
                        slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                        state_queue.append((new_state, abs_state_id, abs_state, None, time_delta, time_constraint,
                                            time_src, None, None, None))

            else:
                # if time_delta is None and prev_abs_state == abs_state:
                #     continue
                new_state = self._initialize_state(init_state=init_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_input_fields = self._symbolize_input_fields(new_state)
                symbolic_time_counters = self._symbolize_timecounter(new_state)

                all_vars = set(symbolic_input_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                if self._temp_addr is not None:
                    symbolic_temperature = self._symbolize_temp(new_state)
                    all_vars |= set(symbolic_temperature.values())
                all_vars |= self.config_vars
                slice_gen = SliceGenerator(all_vars, bp=expression_bp)

                state_queue.append((new_state, abs_state_id, abs_state, None, None, None, None, None, None, None))
        else:
            countdown_timer = 2  # how many iterations to execute before switching on
            switched_on = False

        known_transitions = list()
        known_states = dict()

        absstate_to_slice = { }
        while state_queue:
            prev_state, prev_abs_state_id, prev_abs_state, prev_prev_abs, time_delta, time_delta_constraint, time_delta_src, temp_delta, temp_delta_constraint, temp_delta_src = state_queue.pop(0)
            if time_delta is None:
                pass
            else:
                # advance the time stamp as required
                self._advance_timecounter(prev_state, time_delta)

            if temp_delta is None:
                pass
            else:
                # advance the temperature stamp as required
                self._advance_temp(prev_state, temp_delta)

            # symbolically trace the state
            expression_bp.enabled = True
            next_state = self._traverse_one(prev_state)
            print(next_state.solver.eval(next_state.memory.load(self._time_addr, 4, endness=self.project.arch.memory_endness)))

            expression_bp.enabled = False

            abs_state = self.fields.generate_abstract_state(next_state)
            abs_state += (('time_delta', time_delta),
                          # ('tdc', time_delta_constraint),
                          ('td_src', time_delta_src),
                          ('temp_delta', temp_delta),
                          ('temp_src', temp_delta_src)
                          )
            if switched_on:
                if abs_state in known_states.keys():
                    abs_state_id = known_states[abs_state]
                else:
                    abs_state_id = next(abs_state_id_ctr)
                    known_states[abs_state] = abs_state_id
            else:
                abs_state_id = next(abs_state_id_ctr)
            import pprint
            print("[+] Discovered a new abstract state:")
            if self.printstate is None:
                pprint.pprint(abs_state)
            else:
                self.printstate(abs_state)
            absstate_to_slice[abs_state] = slice_gen.slice
            print("[.] There are %d nodes in the slice." % len(slice_gen.slice))

            transition = (prev_prev_abs, prev_abs_state, abs_state)
            if switched_on and transition in known_transitions:
                continue

            known_transitions.append(transition)
            self.state_graph.add_node((('NODE_CTR', abs_state_id),) + abs_state, outvars=dict(abs_state))
            self.state_graph.add_edge((('NODE_CTR', prev_abs_state_id),) + prev_abs_state,
                                      (('NODE_CTR', abs_state_id),) + abs_state,
                                      time_delta=time_delta,
                                      time_delta_constraint=time_delta_constraint,
                                      time_delta_src=time_delta_src,
                                      temp_delta=temp_delta,
                                      temp_delta_constraint=temp_delta_constraint,
                                      temp_delta_src=temp_delta_src,
                                      label = f'time_delta_constraint={time_delta_constraint},\ntemp_delta_constraint={temp_delta_constraint}'
                                      )

            # discover time deltas
            if not switched_on and self._switch_on is not None:
                if countdown_timer > 0:
                    print("[.] Pre-heat... %d" % countdown_timer)
                    countdown_timer -= 1
                    new_state = self._initialize_state(init_state=next_state)
                    state_queue.append((new_state, abs_state_id, abs_state,None, 1, None, None, None, None, None))
                    continue
                else:
                    print("[.] Switch on.")
                    self._switch_on(next_state)
                    if self.patch_callback is not None:
                        print("[.] Applying patches...")
                        self.patch_callback(next_state)
                    switched_on = True
                    time_delta_and_sources = {}
                    temp_delta_and_sources = {}
                    prev_abs_state = None
                    # state_queue.append((new_state, abs_state_id, abs_state, None, None, None, None, None, None))
            else:
                time_delta_and_sources = self._discover_time_deltas(next_state)

                for delta, constraint, source in time_delta_and_sources:
                    if source is None:
                        block_addr, stmt_idx = -1, -1
                    else:
                        block_addr, stmt_idx = source
                    print(f"[.] Discovered a new time interval {delta} defined at {block_addr:#x}:{stmt_idx}")
                if self._temp_addr is not None:
                    temp_delta_and_sources = self._discover_temp_deltas(next_state)
                    for delta, constraint, source in temp_delta_and_sources:
                        if source is None:
                            block_addr, stmt_idx = -1, -1
                        else:
                            block_addr, stmt_idx = source
                        print(f"[.] Discovered a new temperature {delta} defined at {block_addr:#x}:{stmt_idx}")

            if temp_delta_and_sources or time_delta_and_sources:

                if temp_delta_and_sources:

                    for temp_delta, temp_constraint, temp_src in temp_delta_and_sources:
                        # append two states in queue
                        op = temp_constraint.args[0].op
                        prev = next_state.memory.load(self._temp_addr, 8, endness=self.project.arch.memory_endness).raw_to_fp()
                        prev_temp = next_state.solver.eval(prev)
                        if op in ['fpLEQ', 'fpLT', 'fpGEQ', 'fpGT']:
                            if prev_temp < temp_delta:
                                delta0, temp_constraint0, temp_src0 = None, None, None
                                delta1, temp_constraint1, temp_src1 = temp_delta + 1.0, temp_constraint, temp_src

                                new_state = self._initialize_state(init_state=next_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_input_fields = self._symbolize_input_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_input_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, delta1,
                                                    temp_constraint1, temp_src1))
                            elif prev_temp > temp_delta:
                                delta0, temp_constraint0, temp_src0 = temp_delta - 1.0, temp_constraint, temp_src
                                delta1, temp_constraint1, temp_src1 = None, None, None

                                new_state = self._initialize_state(init_state=next_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_input_fields = self._symbolize_input_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_input_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, delta0,
                                                    temp_constraint0, temp_src0))
                            else:
                                import ipdb; ipdb.set_trace()

                        elif op in ['fpEQ']:
                            # import ipdb; ipdb.set_trace()
                            new_state = self._initialize_state(init_state=next_state)

                            # re-symbolize input fields, time counters, and update slice generator
                            symbolic_input_fields = self._symbolize_input_fields(new_state)
                            symbolic_time_counters = self._symbolize_timecounter(new_state)
                            symbolic_temperature = self._symbolize_temp(new_state)
                            all_vars = set(symbolic_input_fields.values())
                            all_vars |= set(symbolic_time_counters.values())
                            all_vars |= set(symbolic_temperature.values())
                            all_vars |= self.config_vars
                            slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                            state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, temp_delta, temp_constraint, temp_src))
                            continue

                        if time_delta_and_sources:
                            # print(time_delta_constraint)
                            for time_delta, time_constraint, time_src in time_delta_and_sources:
                                # append state satisfy constraint
                                new_state = self._initialize_state(init_state=next_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_input_fields = self._symbolize_input_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_input_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, time_delta, time_constraint, time_src, delta0, temp_constraint0, temp_src0))

                                # append state not satisfy constraint
                                new_state = self._initialize_state(init_state=next_state)

                                # re-symbolize input fields, time counters, and update slice generator
                                symbolic_input_fields = self._symbolize_input_fields(new_state)
                                symbolic_time_counters = self._symbolize_timecounter(new_state)
                                symbolic_temperature = self._symbolize_temp(new_state)
                                all_vars = set(symbolic_input_fields.values())
                                all_vars |= set(symbolic_time_counters.values())
                                all_vars |= set(symbolic_temperature.values())
                                all_vars |= self.config_vars
                                slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, time_delta, time_constraint, time_src, delta1, temp_constraint1, temp_src1))

                # only discover time delta
                else:
                    for time_delta, time_constraint, time_src in time_delta_and_sources:
                        new_state = self._initialize_state(init_state=next_state)

                        # re-symbolize input fields, time counters, and update slice generator
                        symbolic_input_fields = self._symbolize_input_fields(new_state)
                        symbolic_time_counters = self._symbolize_timecounter(new_state)
                        all_vars = set(symbolic_input_fields.values())
                        all_vars |= set(symbolic_time_counters.values())
                        if self._temp_addr is not None:
                            symbolic_temperature = self._symbolize_temp(new_state)
                            all_vars |= set(symbolic_temperature.values())
                        all_vars |= self.config_vars
                        slice_gen = SliceGenerator(all_vars, bp=expression_bp)
                        state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, time_delta, time_constraint, time_src, None, None, None))

            else:
            # if time_delta is None and prev_abs_state == abs_state:
            #     continue
            # if self._temp_addr:
                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_input_fields = self._symbolize_input_fields(new_state)
                symbolic_time_counters = self._symbolize_timecounter(new_state)

                all_vars = set(symbolic_input_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                if self._temp_addr is not None:
                    symbolic_temperature = self._symbolize_temp(new_state)
                    all_vars |= set(symbolic_temperature.values())
                all_vars |= self.config_vars
                slice_gen = SliceGenerator(all_vars, bp=expression_bp)

                state_queue.append((new_state, abs_state_id, abs_state, prev_abs_state, None, None, None, None, None, None))



        # test
        # from networkx.drawing.nx_agraph import write_dot
        # write_dot(self.state_graph, "testbothg.dot")
        # import ipdb; ipdb.set_trace()
        # check if any nodes need to be divided
        for state_node in list(self.state_graph):
            predecessors = list(self.state_graph.predecessors(state_node))
            successors = list(self.state_graph.successors(state_node))
            if len(predecessors) > 1:
                nin = len(predecessors)
                nout = len(successors)
                state_edge = list()
                for edge in known_transitions:
                    if state_node[1:] == edge[1]:
                        state_edge.append(edge)
                ntrans = len(state_edge)
                if ntrans == nin * nout:
                    continue
                else:
                    for pre_node in predecessors:
                        new_id = next(abs_state_id_ctr)
                        print(f"new_id:{new_id}")
                        pre_edge_data = self.state_graph.get_edge_data(pre_node, state_node)
                        self.state_graph.add_node((('NODE_CTR', new_id),) + state_node[1:], outvars=dict(state_node[1:]))
                        self.state_graph.add_edge(pre_node,
                                                  (('NODE_CTR', new_id),) + state_node[1:],
                                                  time_delta=pre_edge_data['time_delta'],
                                                  time_delta_constraint=pre_edge_data['time_delta_constraint'],
                                                  time_delta_src=pre_edge_data['time_delta_src'],
                                                  temp_delta=pre_edge_data['temp_delta'],
                                                  temp_delta_constraint=pre_edge_data['temp_delta_constraint'],
                                                  temp_delta_src=pre_edge_data['temp_delta_src'],
                                                  label=f'time_delta_constraint={pre_edge_data["time_delta_constraint"]}'
                                                  )
                        suc_nodes = [edge[2] for edge in state_edge if edge[0] == pre_node[1:] ]
                        for suc_node in suc_nodes:
                            suc_id = known_states[suc_node]
                            suc_edge_data = self.state_graph.get_edge_data(state_node, ((('NODE_CTR',suc_id),) + suc_node))
                            if suc_edge_data is None:
                                import ipdb; ipdb.set_trace()
                            self.state_graph.add_edge((('NODE_CTR', new_id),) + state_node[1:],
                                                      (('NODE_CTR', suc_id),) + suc_node,
                                                      time_delta=suc_edge_data['time_delta'],
                                                      time_delta_constraint=suc_edge_data['time_delta_constraint'],
                                                      time_delta_src=suc_edge_data['time_delta_src'],
                                                      temp_delta=suc_edge_data['temp_delta'],
                                                      temp_delta_constraint=suc_edge_data['temp_delta_constraint'],
                                                      temp_delta_src=suc_edge_data['temp_delta_src'],
                                                      label=f'time_delta_constraint={suc_edge_data["time_delta_constraint"]}'
                                                      )
                    self.state_graph.remove_node(state_node)
                    break   # TODO: this could be wrong if there is multiple nodes need to be divided



    def _discover_time_deltas(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
        """
        Discover all possible time intervals that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """

        state = self._initialize_state(state)
        time_deltas = self._symbolically_advance_timecounter(state)
        # setup inspection points to catch where comparison happens
        constraint_source = { }
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        state.inspect.add_breakpoint('constraints', bp_0)

        next_state = self._traverse_one(state)
        # import ipdb; ipdb.set_trace()
        # detect required time delta
        # TODO: Extend it to more than just seconds
        steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
        if time_deltas:
            for delta in time_deltas:
                for constraint in next_state.solver.constraints:
                    original_constraint = constraint
                    # attempt simplification if this constraint has both config variables and time delta variables
                    if any(x.args[0] in constraint.variables for x in self.config_vars) and delta.args[0] in constraint.variables:
                        simplified_constraint, self._expression_source = self._simplify_constraint(constraint,
                                                                                                   self._expression_source)
                        if simplified_constraint is not None:
                            constraint = simplified_constraint

                    if constraint.op == "__eq__" and constraint.args[0] is delta:
                        continue
                    elif constraint.op in ('ULE'):  # arduino arm32
                        if constraint.args[0].args[1] is delta:
                            if constraint.args[1].args[0].op == 'BVV':
                                step = constraint.args[1].args[0].args[0]
                                if step != 0:
                                    steps.append((
                                        step,
                                        constraint,
                                        constraint_source.get(original_constraint, None),
                                    ))
                                    continue
                    elif constraint.op in ("__le__",):  # simulink arm32
                        if constraint.args[0].args[1] is delta:
                            if constraint.args[1].op == 'BVV':
                                step = constraint.args[1].args[0]
                                if step != 0 and step < 255:
                                    steps.append((
                                        step,
                                        constraint,
                                        constraint_source.get(original_constraint, None),
                                    ))
                                    continue
                            elif constraint.args[1].args[0].op == 'BVV':    # arduino arm32 oven
                                step = constraint.args[1].args[0].args[0]
                                if step != 0:
                                    steps.append((
                                        step,
                                        constraint,
                                        constraint_source.get(original_constraint, None),
                                    ))
                                    continue
                    elif constraint.op == "__ne__":
                        if constraint.args[0] is delta:     # amd64
                            # found a potential step
                            if constraint.args[1].op == 'BVV':
                                step = constraint.args[1]._model_concrete.value
                                if step != 0 and step < 255:
                                    steps.append((
                                        step,
                                        constraint,
                                        constraint_source.get(original_constraint, None),
                                    ))
                                    continue
                            else:
                                # attempt to evaluate the right-hand side
                                values = state.solver.eval_upto(constraint.args[1], 2)
                                if len(values) == 1:
                                    # it has a single value!
                                    step = values[0]
                                    if step != 0:
                                        steps.append((
                                            step,
                                            constraint,
                                            constraint_source.get(original_constraint, None),
                                        ))
                                        continue

                        if constraint.args[1].op == "BVS":      # arm32
                            # access constraint.args[1].args[2]
                            if constraint.args[1].args[2] is delta or constraint.args[1] is delta:
                                if constraint.args[0].op == 'BVV':
                                    step = constraint.args[0].args[0]
                                    if step != 0:
                                        steps.append((
                                            step,
                                            constraint,
                                            constraint_source.get(original_constraint, None),
                                        ))
                                        continue
        return steps

    def _discover_temp_deltas(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
        """
        Discover all possible temperature that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """
        if self._temp_addr is None:
            return []
        state = self._initialize_state(state)
        temp_deltas = self._symbolically_advance_temp(state)
        # setup inspection points to catch where comparison happens
        constraint_source = { }
        constraint_logger = ConstraintLogger(constraint_source)
        bp_0 = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        state.inspect.add_breakpoint('constraints', bp_0)

        next_state = self._traverse_one(state)

        # detect required temp delta
        steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
        if temp_deltas:
            for delta in temp_deltas:
                for constraint in next_state.solver.constraints:
                    original_constraint = constraint

                    if constraint.op == "__eq__" and constraint.args[0] is delta:
                        continue
                    elif constraint.op == 'Not':
                        if len(constraint.args[0].args[1].args) > 2:
                            if constraint.args[0].args[1].args[2] is delta:
                                if constraint.args[0].args[0].op == 'FPV':
                                    step = constraint.args[0].args[0]._model_concrete.value
                                    if step != 0 and step < 10000:
                                    # if step != 0:
                                        steps.append((
                                            step,
                                            constraint,
                                            constraint_source.get(original_constraint, None),
                                        ))
                                        continue
                        elif len(constraint.args[0].args[0].args) > 2:
                            if constraint.args[0].args[0].args[2] is delta:
                                if constraint.args[0].args[1].op == 'FPV':
                                    step = constraint.args[0].args[1]._model_concrete.value
                                    if step != 0 and step < 10000:
                                        steps.append((
                                            step,
                                            constraint,
                                            constraint_source.get(original_constraint, None),
                                        ))
                                        continue

        return steps

    def _simplify_constraint(self, constraint: claripy.ast.Base, source: Dict[claripy.ast.Base,Any]) -> Tuple[Optional[claripy.ast.Base],Dict[claripy.ast.Base,Any]]:
        """
        Attempt to simplify a constraint and generate a new source mapping.

        Note that this simplification focuses on readability and is not always sound!

        :param constraint:
        :param source:
        :return:
        """

        if (constraint.op in ("__ne__", "__eq__", "ULE")
                and constraint.args[0].op == "__add__"
                and constraint.args[1].op == "__add__"):
            # remove arguments that appear in both sides of the comparison
            same_args = set(constraint.args[0].args).intersection(set(constraint.args[1].args))
            if same_args:
                left_new_args = tuple(arg for arg in constraint.args[0].args if arg not in same_args)
                left = constraint.args[0].make_like("__add__", left_new_args) if len(left_new_args) > 1 else left_new_args[0]
                if constraint.args[0] in source:
                    source[left] = source[constraint.args[0]]

                right_new_args = tuple(arg for arg in constraint.args[1].args if arg not in same_args)
                right = constraint.args[1].make_like("__add__", right_new_args) if len(right_new_args) > 1 else right_new_args[0]
                if constraint.args[1] in source:
                    source[right] = source[constraint.args[1]]

                simplified = constraint.make_like(constraint.op, (left, right))
                if constraint in source:
                    source[simplified] = source[constraint]
                return self._simplify_constraint(simplified, source)

        # Transform signed-extension of fpToSBV() to unsigned extension
        if constraint.op == "Concat":
            args = constraint.args
            if all(arg.op == "Extract" for arg in args):
                if len(set(arg.args[2] for arg in args)) == 1:
                    if all(arg.args[0:2] in ((15,15), (31,31)) for arg in args[:-1]):
                        # found it!
                        core, source = self._simplify_constraint(args[0].args[2], source)
                        if core is None:
                            core = args[0].args[2]
                        simplified = claripy.ZeroExt(len(args) - 1, core)
                        if constraint in source:
                            source[simplified] = source[constraint]
                        return simplified, source
            elif all(arg.op == "Extract" for arg in args[:-1]):
                if len(set(arg.args[2] for arg in args[:-1])) == 1:
                    v = args[0].args[2]
                    if v is args[-1]:
                        if all(arg.args[0:2] in ((15,15), (31,31)) for arg in args[:-1]):
                            # found it!
                            core, source = self._simplify_constraint(v, source)
                            if core is None:
                                core = v
                            simplified = claripy.ZeroExt(len(args) - 1, core)
                            if constraint is source:
                                source[simplified] = source[constraint]
                            return simplified, source

        elif constraint.op in ('__ne__', '__mod__', '__floordiv__'):
            left, source = self._simplify_constraint(constraint.args[0], source)
            right, source = self._simplify_constraint(constraint.args[1], source)
            if left is None and right is None:
                return None, source
            if left is None:
                left = constraint.args[0]
            if right is None:
                right = constraint.args[1]
            simplified = constraint.make_like(constraint.op, (left, right))
            if constraint in source:
                source[simplified] = source[constraint]
            return simplified, source

        elif constraint.op in ('__add__', ):
            new_args = [ ]
            simplified = False
            for arg in constraint.args:
                new_arg, source = self._simplify_constraint(arg, source)
                if new_arg is not None:
                    new_args.append(new_arg)
                    simplified = True
                else:
                    new_args.append(arg)
            if not simplified:
                return None, source
            simplified = constraint.make_like(constraint.op, tuple(new_args))
            if constraint in source:
                source[simplified] = source[constraint]
            return simplified, source

        elif constraint.op in ('fpToSBV', 'fpToFP'):
            arg1, source = self._simplify_constraint(constraint.args[1], source)
            if arg1 is None:
                return None, source
            simplified = constraint.make_like(constraint.op, (constraint.args[0], arg1, constraint.args[2]))
            if constraint in source:
                source[simplified] = source[constraint]
            return simplified, source

        elif constraint.op in ('fpMul', ):
            if constraint.args[1].op == "FPV" and constraint.args[1]._model_concrete.value == 0.0:
                return constraint.args[1], source
            elif constraint.args[2].op == "FPV" and constraint.args[2]._model_concrete.value == 0.0:
                return constraint.args[2], source
            arg1, source = self._simplify_constraint(constraint.args[1], source)
            arg2, source = self._simplify_constraint(constraint.args[2], source)
            if arg1 is None and arg2 is None:
                return None, source
            if arg1 is None:
                arg1 = constraint.args[1]
            if arg2 is None:
                arg2 = constraint.args[2]
            simplified = constraint.make_like(constraint.op, (constraint.args[0], arg1, arg2))
            if constraint in source:
                source[simplified] = source[constraint]
            return simplified, source

        return None, source

    def _symbolize_input_fields(self, state: 'SimState') -> Dict[str,claripy.ast.Base]:

        symbolic_input_vars = { }

        for name, (address, type_, size) in self.fields.fields.items():
            # print(f"[.] Symbolizing field {name}...")

            v = state.memory.load(address, size=size, endness=self.project.arch.memory_endness)
            if not state.solver.symbolic(v):
                # if type_ == "float":
                #     concrete_v = state.solver.eval(v, cast_to=float)
                #     symbolic_v = claripy.FPS(name, claripy.fp.FSORT_FLOAT)
                # elif type_ == "double":
                #     concrete_v = state.solver.eval(v, cast_to=float)
                #     symbolic_v = claripy.FPS(name, claripy.fp.FSORT_DOUBLE)
                # else:
                concrete_v = state.solver.eval(v)
                symbolic_v = claripy.BVS(name, size * self.project.arch.byte_width)
                symbolic_input_vars[name] = symbolic_v

                # update the value in memory
                state.memory.store(address, symbolic_v, endness=self.project.arch.memory_endness)

                # preconstrain it
                state.preconstrainer.preconstrain(concrete_v, symbolic_v)
            else:
                symbolic_input_vars[name] = v

        return symbolic_input_vars

    def _symbolize_timecounter(self, state: 'SimState') -> Dict[str,claripy.ast.Base]:
        if self.software == "beremiz":
            return self._symbolize_timecounter_beremiz(state)
        elif self.software == 'arduino':
            return self._symbolize_timecounter_arduino(state)
        elif self.software == 'simulink':
            return self._symbolize_timecounter_simulink(state)

    # simulink time 255
    def _symbolize_timecounter_simulink(self, state: 'SimState') -> Dict[str,claripy.ast.Base]:
        tv_sec_addr = self._time_addr
        # prev = state.memory.load(self._time_addr, size=1, endness=self.project.arch.memory_endness)
        # prev_time = state.solver.eval(prev) + 1

        self._tv_sec_var = claripy.BVS('tv_sec', 1 * self.project.arch.byte_width)
        state.memory.store(tv_sec_addr, self._tv_sec_var, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(
            claripy.BVV(0, 1 * self.project.arch.byte_width), self._tv_sec_var)

        return {'tv_sec': self._tv_sec_var}

    # Traffic_Light Beremiz
    def _symbolize_timecounter_beremiz(self, state: 'SimState') -> Dict[str,claripy.ast.Base]:
        tv_sec_addr = self._time_addr
        tv_nsec_addr = tv_sec_addr + self.project.arch.bytes

        self._tv_sec_var = claripy.BVS('tv_sec', self.project.arch.bytes * self.project.arch.byte_width)
        self._tv_nsec_var = claripy.BVS('tv_nsec', self.project.arch.bytes * self.project.arch.byte_width)

        state.memory.store(tv_sec_addr, self._tv_sec_var, endness=self.project.arch.memory_endness)
        state.memory.store(tv_nsec_addr, self._tv_nsec_var, endness=self.project.arch.memory_endness)

        # the initial timer values are 0
        state.preconstrainer.preconstrain(claripy.BVV(0, self.project.arch.bytes * self.project.arch.byte_width), self._tv_sec_var)
        state.preconstrainer.preconstrain(claripy.BVV(0, self.project.arch.bytes * self.project.arch.byte_width), self._tv_nsec_var)

        return {
            'tv_sec_var': self._tv_sec_var,
            'tv_nsec_var': self._tv_nsec_var
        }

    # reflowoven Arduino
    def _symbolize_timecounter_arduino(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
        tv_sec_addr = self._time_addr
        prev = state.memory.load(self._time_addr, size=self.project.arch.bytes, endness=self.project.arch.memory_endness)
        prev_time = state.solver.eval(prev) + 1

        self._tv_sec_var = claripy.BVS('tv_sec', self.project.arch.bytes * self.project.arch.byte_width)
        state.memory.store(tv_sec_addr, self._tv_sec_var, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.BVV(prev_time, self.project.arch.bytes * self.project.arch.byte_width), self._tv_sec_var)

        return {'tv_sec': self._tv_sec_var}

    def _symbolically_advance_timecounter(self, state: 'SimState') -> List[claripy.ast.Bits]:
        bytesize = self.project.arch.bytes
        if self.software == 'simulink':
            bytesize = 1
        sec_delta = claripy.BVS("sec_delta", bytesize * self.project.arch.byte_width)
        state.preconstrainer.preconstrain(claripy.BVV(1, bytesize * self.project.arch.byte_width), sec_delta)

        tv_sec = state.memory.load(self._time_addr, size=bytesize, endness=self.project.arch.memory_endness)
        state.memory.store(self._time_addr, tv_sec + sec_delta, endness=self.project.arch.memory_endness)

        return [sec_delta]

    def _advance_timecounter(self, state: 'SimState', delta: int) -> None:
        bytesize = self.project.arch.bytes
        if self.software == 'simulink':
            bytesize = 1
        prev = state.memory.load(self._time_addr, size=bytesize, endness=self.project.arch.memory_endness)
        state.memory.store(self._time_addr, prev + delta, endness=self.project.arch.memory_endness)

        if self.software == 'beremiz':
            tv_nsec = state.memory.load(self._time_addr + self.project.arch.bytes, size=self.project.arch.bytes,
                                        endness=self.project.arch.memory_endness)
            state.memory.store(self._time_addr + self.project.arch.bytes, tv_nsec + 200,
                               endness=self.project.arch.memory_endness)

    def _symbolize_temp(self, state: 'SimState') -> Dict[str, claripy.ast.Base]:
        temp_addr = self._temp_addr

        prev = state.memory.load(self._temp_addr, size=8, endness=self.project.arch.memory_endness)
        prev_temp = state.solver.eval(prev)

        self._temperature = claripy.FPS('temperature', claripy.fp.FSORT_DOUBLE)
        state.memory.store(temp_addr, self._temperature, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(state.solver.BVV(prev_temp, 64).raw_to_fp(), self._temperature)

        return {'temperature': self._temperature}

    def _symbolically_advance_temp(self, state: 'SimState') -> List[claripy.ast.Bits]:
        temp_delta = claripy.FPS("temp_delta", claripy.fp.FSORT_DOUBLE)
        state.preconstrainer.preconstrain(state.solver.FPV(0.5, claripy.fp.FSORT_DOUBLE), temp_delta)

        prev = state.memory.load(self._temp_addr, size=8, endness=self.project.arch.memory_endness).raw_to_fp()
        state.memory.store(self._temp_addr, prev + temp_delta, endness=self.project.arch.memory_endness)

        return [temp_delta]

    def _advance_temp(self, state: 'SimState', delta) -> None:
        self._temperature = claripy.FPS('temperature', claripy.fp.FSORT_DOUBLE)
        state.memory.store(self._temp_addr, self._temperature, endness=self.project.arch.memory_endness)
        state.preconstrainer.preconstrain(claripy.FPV(delta, claripy.fp.FSORT_DOUBLE), self._temperature)

    def _traverse_one(self, state: 'SimState'):

        simgr = self.project.factory.simgr(state)

        while simgr.active:
            s = simgr.active[0]
            # print(s)
            if len(simgr.active) > 1:
                import ipdb; ipdb.set_trace()

            # if s.addr == 0x21d5:
            #     print("IN READ!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            #     # import ipdb; ipdb.set_trace()
            # if s.addr == 0x2245:
            #     print("IN CHECk!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            #     # import ipdb; ipdb.set_trace()
            # if s.addr == 0x2315:
            #     print("IN IDLE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            #     # import ipdb; ipdb.set_trace()
            # if s.addr == 0x2349:
            #     print("IN PREHEAT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            # if s.addr == 0x2377:
            #     print("IN COOK!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            #     # import ipdb; ipdb.set_trace()
            # if s.addr == 0x23e3:
            #     print("IN COOL!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            #     import ipdb; ipdb.set_trace()
            # if s.addr == 0x2405:
            #     print("IN COMPLETE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            # if s.addr == 0x2415:
            #     print("IN TOOHOT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

            simgr.stash(lambda x: x.addr == self._ret_trap, from_stash='active', to_stash='finished')

            simgr.step()

        # import sys
        # sys.stdout.write('\n')
        assert len(simgr.finished) == 1
        return simgr.finished[0]

    def _initialize_state(self, init_state=None) -> 'SimState':
        if init_state is not None:
            s = init_state.copy()
            s.ip = self.func.addr
        else:
            s = self.project.factory.blank_state(addr=self.func.addr)
            s.regs.rdi = 0xc0000000
            s.memory.store(0xc0000000, b"\x00" * 0x1000)

        # disable cross instruction optimization so that statement IDs in symbolic execution will match the ones used in
        # static analysis
        s.options[NO_CROSS_INSN_OPT] = True
        # disable warnings
        s.options[SYMBOL_FILL_UNCONSTRAINED_MEMORY] = True
        s.options[SYMBOL_FILL_UNCONSTRAINED_REGISTERS] = True

        if self.project.arch.call_pushes_ret:
            s.stack_push(claripy.BVV(self._ret_trap, self.project.arch.bits))
        else:
            # set up the link register for the return address
            s.regs.lr = self._ret_trap

        return s


AnalysesHub.register_default('StateGraphRecovery', StateGraphRecoveryAnalysis)
