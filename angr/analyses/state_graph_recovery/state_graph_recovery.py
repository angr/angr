from typing import Optional, List, Dict, Tuple, Set, Callable, TYPE_CHECKING

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
    def __init__(self, func: 'Function', fields: 'AbstractStateFields', time_addr: int,
                 init_state: Optional['SimState']=None, switch_on: Optional[Callable]=None, printstate: Optional[Callable]=None):
        self.func = func
        self.fields = fields
        self.init_state = init_state
        self._switch_on = switch_on
        self._ret_trap: int = 0x1f37ff4a
        self.printstate = printstate

        # self._iec_time = 0x425620       # Traffic_Light_short_ped
        # self._iec_time = 0x448630       # Traffic_Light_both_green
        self._iec_time = time_addr
        self._tv_sec_var = None
        self._tv_nsec_var = None
        self.state_graph = None

        self.traverse()

    def traverse(self):

        # create an empty state graph
        self.state_graph = networkx.DiGraph()

        # make the initial state
        init_state = self._initialize_state(init_state=self.init_state)

        symbolic_input_fields = self._symbolize_input_fields(init_state)
        symbolic_time_counters = self._symbolize_timecounter(init_state)
        all_vars = set(symbolic_input_fields.values())
        all_vars |= set(symbolic_time_counters.values())
        slice_gen = SliceGenerator(all_vars, bp=None)
        expression_bp = slice_gen.install_expr_hook(init_state)

        abs_state = self.fields.generate_abstract_state(init_state)
        self.state_graph.add_node(abs_state)
        state_queue = [(init_state, abs_state, None, None, None)]
        countdown_timer = 2  # how many iterations to execute before switching on
        switched_on = False

        absstate_to_slice = { }

        while state_queue:
            prev_state, prev_abs_state, time_delta, time_delta_constraint, time_delta_src = state_queue.pop(0)
            if time_delta is None:
                pass
            else:
                # advance the time stamp as required
                self._advance_timecounter(prev_state, time_delta)

            # symbolically trace the state
            expression_bp.enabled = True
            next_state = self._traverse_one(prev_state)
            expression_bp.enabled = False

            # print(time_delta)
            abs_state = self.fields.generate_abstract_state(next_state)
            abs_state += (('time_delta', time_delta),
                          ('tdc', time_delta_constraint),
                          ('td_src', time_delta_src)
                          )

            import pprint
            print("[+] Discovered a new abstract state:")
            if self.printstate is None:
                pprint.pprint(abs_state)
            else:
                self.printstate(abs_state)
            absstate_to_slice[abs_state] = slice_gen.slice
            print("[.] There are %d nodes in the slice." % len(slice_gen.slice))

            self.state_graph.add_edge(prev_abs_state,
                                      abs_state,
                                      time_delta=time_delta,
                                      time_delta_constraint=time_delta_constraint,
                                      time_delta_src=time_delta_src,
                                      )

            # discover time deltas
            if not switched_on and self._switch_on is not None:
                if countdown_timer > 0:
                    print("[.] Pre-heat... %d" % countdown_timer)
                    countdown_timer -= 1
                    state_queue.append((next_state, abs_state, None, None, None))
                    continue
                else:
                    print("[.] Switch on.")
                    self._switch_on(next_state)
                    switched_on = True
                    delta_and_sources = {}
            else:
                delta_and_sources = self._discover_time_deltas(next_state)
                for delta, constraint, (block_addr, stmt_idx) in delta_and_sources:
                    print(f"[.] Discovered a new time interval {delta} defined at {block_addr:#x}:{stmt_idx}")

            if delta_and_sources:
                for delta, constraint, src in delta_and_sources:
                    new_state = self._initialize_state(init_state=next_state)

                    # re-symbolize input fields, time counters, and update slice generator
                    symbolic_input_fields = self._symbolize_input_fields(new_state)
                    symbolic_time_counters = self._symbolize_timecounter(new_state)
                    all_vars = set(symbolic_input_fields.values())
                    all_vars |= set(symbolic_time_counters.values())
                    slice_gen = SliceGenerator(all_vars, bp=expression_bp)

                    state_queue.append((new_state, abs_state, delta, constraint, src))
            else:
                if prev_abs_state == abs_state and time_delta is None:
                    continue
                new_state = self._initialize_state(init_state=next_state)

                # re-symbolize input fields, time counters, and update slice generator
                symbolic_input_fields = self._symbolize_input_fields(new_state)
                symbolic_time_counters = self._symbolize_timecounter(new_state)
                all_vars = set(symbolic_input_fields.values())
                all_vars |= set(symbolic_time_counters.values())
                slice_gen = SliceGenerator(all_vars, bp=expression_bp)

                state_queue.append((new_state, abs_state, None, None, None))

    def _discover_time_deltas(self, state: 'SimState') -> List[Tuple[int,claripy.ast.Base,Tuple[int,int]]]:
        """
        Discover all possible time intervals that may be required to transition the current state to successor states.

        :param state:   The current initial state.
        :return:        A list of ints where each int represents the required interval in number of seconds.
        """

        state = self._initialize_state(state)
        time_deltas = self._symbolically_advance_timecounter(state)
        # setup inspect points to catch where comparison happens
        constraint_source = { }
        constraint_logger = ConstraintLogger(constraint_source)
        bp = BP(when=BP_BEFORE, enabled=True, action=constraint_logger.on_adding_constraints)
        state.inspect.add_breakpoint('constraints', bp)
        next_state = self._traverse_one(state)

        # detect required time delta
        # TODO: Extend it to more than just seconds
        steps: List[Tuple[int,claripy.ast.Base,Tuple[int,int]]] = [ ]
        if time_deltas:
            for delta in time_deltas:
                for constraint in next_state.solver.constraints:
                    if constraint.op == "__eq__" and constraint.args[0] is delta:
                        continue
                    elif constraint.op == "__ne__":
                        if constraint.args[0] is delta:     # amd64
                            # found a potential step
                            if constraint.args[1].op == 'BVV':
                                step = constraint.args[1].args[0]
                                steps.append((
                                    step,
                                    constraint,
                                    constraint_source.get(constraint, None),
                                ))
                                continue
                        if constraint.args[1].op == "Extract":      # arm32
                            # access constraint.args[1].args[2]
                            if constraint.args[1].args[2] is delta:
                                if constraint.args[0].op == 'BVV':
                                    step = constraint.args[0].args[0]
                                    steps.append((
                                        step,
                                        constraint,
                                        constraint_source.get(constraint, None),
                                    ))
                                    continue

        return steps

    def _symbolize_input_fields(self, state: 'SimState') -> Dict[str,claripy.ast.Base]:

        symbolic_input_vars = { }

        for name, (address, size) in self.fields.fields.items():
            print(f"[.] Symbolizing field {name}...")

            v = state.memory.load(address, size=size, endness=self.project.arch.memory_endness)
            if not state.solver.symbolic(v):
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
        # TODO: Generalize it
        tv_sec_addr = self._iec_time
        tv_nsec_addr = tv_sec_addr + 8

        self._tv_sec_var = claripy.BVS('tv_sec', 64)
        self._tv_nsec_var = claripy.BVS('tv_nsec', 64)

        state.memory.store(tv_sec_addr, self._tv_sec_var, endness=self.project.arch.memory_endness)
        state.memory.store(tv_nsec_addr, self._tv_nsec_var, endness=self.project.arch.memory_endness)

        # the initial timer values are 0
        state.preconstrainer.preconstrain(claripy.BVV(0, 64), self._tv_sec_var)
        state.preconstrainer.preconstrain(claripy.BVV(0, 64), self._tv_nsec_var)

        return {
            'tv_sec_var': self._tv_sec_var,
            'tv_nsec_var': self._tv_nsec_var
        }

    def _symbolically_advance_timecounter(self, state: 'SimState') -> List[claripy.ast.Bits]:
        # TODO: Generalize it
        sec_delta = claripy.BVS("sec_delta", 64)
        state.preconstrainer.preconstrain(claripy.BVV(1, 64), sec_delta)

        tv_sec = state.memory.load(self._iec_time, size=8, endness=self.project.arch.memory_endness)
        state.memory.store(self._iec_time, tv_sec + sec_delta, endness=self.project.arch.memory_endness)

        return [sec_delta]

    def _advance_timecounter(self, state: 'SimState', delta: int) -> None:
        # TODO: Generalize it
        tv_sec = state.memory.load(self._iec_time, size=8, endness=self.project.arch.memory_endness)
        state.memory.store(self._iec_time, tv_sec + delta, endness=self.project.arch.memory_endness)

        # hack
        tv_nsec = state.memory.load(self._iec_time + 8, size=8, endness=self.project.arch.memory_endness)
        state.memory.store(self._iec_time + 8, tv_nsec + 200, endness=self.project.arch.memory_endness)

    def _traverse_one(self, state: 'SimState'):

        simgr = self.project.factory.simgr(state)

        while simgr.active:
            # print(simgr.active)
            # import sys
            # sys.stdout.write('.')

            s = simgr.active[0]
            if len(simgr.active) > 1:
                import ipdb; ipdb.set_trace()

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
