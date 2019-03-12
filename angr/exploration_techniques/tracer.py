from typing import List
import logging

from . import ExplorationTechnique
from .. import BP_BEFORE, BP_AFTER, sim_options
from ..errors import AngrTracerError

l = logging.getLogger(name=__name__)


class Tracer(ExplorationTechnique):
    """
    An exploration technique that follows an angr path with a concrete input.
    The tracing result is the state at the last address of the trace, which can be found in the
    'traced' stash.

    If the given concrete input makes the program crash, you should provide crash_addr, and the
    crashing state will be found in the 'crashed' stash.

    :param trace:               The basic block trace.
    :param resiliency:          Should we continue to step forward even if qemu and angr disagree?
    :param keep_predecessors:   Number of states before the final state we should log.
    :param crash_addr:          If the trace resulted in a crash, provide the crashing instruction
                                pointer here, and the 'crashed' stash will be populated with the
                                crashing state.
    :param copy_states:         Whether COPY_STATES should be enabled for the tracing state. It is
                                off by default because most tracing workloads benefit greatly from
                                not performing copying. You want to enable it if you want to see
                                the missed states. It will be re-added for the last 2% of the trace
                                in order to set the predecessors list correctly. If you turn this
                                on you may want to enable the LAZY_SOLVES option.

    :ivar predecessors:         A list of states in the history before the final state.
    """

    def __init__(self,
            trace=None,
            resiliency=False,
            keep_predecessors=1,
            crash_addr=None,
            copy_states=False):
        super(Tracer, self).__init__()
        self._trace = trace
        self._resiliency = resiliency
        self._crash_addr = crash_addr
        self._copy_states = copy_states

        self._aslr_slides = {}
        self._current_slide = None

        # keep track of the last basic block we hit
        self.predecessors = [None] * keep_predecessors # type: List[angr.SimState]
        self.last_state = None

        # whether we should follow the trace
        self._no_follow = self._trace is None

    def setup(self, simgr):
        simgr.populate('missed', [])
        simgr.populate('traced', [])
        simgr.populate('crashed', [])

        self.project = simgr._project
        if len(simgr.active) != 1:
            raise AngrTracerError("Tracer is being invoked on a SimulationManager without exactly one active state")

        # calc ASLR slide for main binary and find the entry point in one fell swoop
        # ...via heuristics
        for idx, addr in enumerate(self._trace):
            if ((addr - self.project.entry) & 0xfff) == 0 and (idx == 0 or abs(self._trace[idx-1] - addr) > 0x10000):
                break
        else:
            raise AngrTracerError("Could not identify program entry point in trace!")

        # pylint: disable=undefined-loop-variable
        # pylint doesn't know jack shit
        self._current_slide = self._aslr_slides[self.project.loader.main_object] = self._trace[idx] - self.project.entry

        # step to entry point
        while self._trace and self._trace[idx] != simgr.one_active.addr + self._current_slide:
            simgr.step(extra_stop_points={self._trace[idx] - self._current_slide})
            if len(simgr.active) == 0:
                raise AngrTracerError("Could not step to the first address of the trace - simgr is empty")
            elif len(simgr.active) > 1:
                raise AngrTracerError("Could not step to the first address of the trace - state split")

        # initialize the state info
        simgr.one_active.globals['trace_idx'] = idx
        simgr.one_active.globals['sync_idx'] = None
        simgr.one_active.globals['sync_timer'] = 0

        # disable state copying!
        if not self._copy_states:
            # insulate our caller from this nonsense my making a single copy at the beginning
            simgr.active[0] = simgr.active[0].copy()
            simgr.active[0].options.remove(sim_options.COPY_STATES)

    def complete(self, simgr):
        return bool(simgr.traced)

    def filter(self, simgr, state, **kwargs):
        # check completion
        if state.globals['trace_idx'] >= len(self._trace) - 1:
            # do crash windup if necessary
            if self._crash_addr is not None:
                self.last_state, crash_state = self.crash_windup(state, self._crash_addr)
                simgr.populate('crashed', [crash_state])

            return 'traced'

        return simgr.filter(state, **kwargs)

    def step(self, simgr, stash='active', **kwargs):
        simgr.drop(stash='missed')
        return simgr.step(stash=stash, **kwargs)

    def step_state(self, simgr, state, **kwargs):
        # maintain the predecessors list
        self.predecessors.append(state)
        self.predecessors.pop(0)

        if state.globals['trace_idx'] > len(self._trace) * 0.98:
            state.options.add(sim_options.COPY_STATES)
            state.options.add(sim_options.LAZY_SOLVES)

        # perform the step. ask qemu to stop at the termination point.
        stops = set(kwargs.pop('extra_stop_points', ())) | {self._trace[-1]}
        succs_dict = simgr.step_state(state, extra_stop_points=stops, **kwargs)
        succs = succs_dict[None] + succs_dict['unsat']

        # follow the trace
        if len(succs) == 1:
            self._update_state_tracking(succs[0])
        elif len(succs) == 0:
            raise Exception("All states disappeared!")
        else:
            succ = self._pick_correct_successor(succs)
            succs_dict[None] = [succ]
            succs_dict['missed'] = [s for s in succs if s is not succ]

        assert len(succs_dict[None]) == 1
        return succs_dict

    def _pick_correct_successor(self, succs):
        # there's been a branch of some sort. Try to identify which state stayed on the trace.
        assert len(succs) > 0
        idx = succs[0].globals['trace_idx']

        res = []
        for succ in succs:
            try:
                if self._compare_addr(self._trace[idx + 1], succ.addr):
                    res.append(succ)
            except AngrTracerError:
                pass

        if not res:
            raise Exception("No states followed the trace?")

        if len(res) > 1:
            raise Exception("The state split but several successors have the same (correct) address?")

        self._update_state_tracking(res[0])
        return res[0]

    def _update_state_tracking(self, state: 'angr.SimState'):
        idx = state.globals['trace_idx']
        sync = state.globals['sync_idx']
        timer = state.globals['sync_timer']

        if state.history.recent_block_count > 1:
            # multiple blocks were executed this step. they should follow the trace *perfectly*
            # or else something is up
            # "something else" so far only includes concrete transmits, or...
            # TODO: https://github.com/unicorn-engine/unicorn/issues/874
            # ^ this means we will see desyncs of the form unicorn suddenly skips a bunch of qemu blocks
            assert state.history.recent_block_count == len(state.history.recent_bbl_addrs)

            if sync is not None:
                raise Exception("TODO")

            for addr in state.history.recent_bbl_addrs:
                if addr == state.unicorn.transmit_addr:
                    continue

                if self._compare_addr(self._trace[idx], addr):
                    idx += 1
                else:
                    raise Exception('BUG! Please investigate the claim in the comment above me')

            idx -= 1 # use normal code to do the last synchronization

        if sync is not None:
            timer -= 1
            if self._compare_addr(self._trace[sync], state.addr):
                state.globals['trace_idx'] = sync
                state.globals['sync_idx'] = None
                state.globals['sync_timer'] = 0
            elif timer > 0:
                state.globals['sync_timer'] = timer
            else:
                raise Exception("Trace failed to synchronize! We expected it to hit %#x (untranslated), but it failed to do this within a timeout" % self._trace[sync])

        elif self._compare_addr(self._trace[idx + 1], state.addr):
            # normal case
            state.globals['trace_idx'] = idx + 1
        elif self.project.loader._extern_object is not None and self.project.loader.extern_object.contains_addr(state.addr):
            # externs
            proc = self.project.hooked_by(state.addr)
            if proc is None:
                raise Exception("Extremely bad news: we're executing an unhooked address in the externs space")
            if proc.is_continuation:
                orig_addr = self.project.loader.find_symbol(proc.display_name).rebased_addr
                orig_trace_addr = orig_addr + self._aslr_slides[self.project.loader.find_object_containing(orig_addr)]
                if 0 <= self._trace[idx + 1] - orig_trace_addr <= 0x10000:
                    # this is fine. we do nothing and then next round it'll get handled by the is_hooked(state.history.addr) case
                    pass
                else:
                    # this may also be triggered as a consequence of the unicorn issue linked above
                    raise Exception("BUG: State is returning to a continuation that isn't its own???")
            elif state.addr == getattr(self.project.simos, 'vsyscall_addr', None):
                if not self._sync_callsite(state, idx, state.history.addr):
                    raise AngrTracerError("Could not synchronize following vsyscall")
            else:
                # see above
                pass
        elif state.history.jumpkind.startswith('Ijk_Sys'):
            # syscalls
            state.globals['sync_idx'] = idx + 1
            state.globals['sync_timer'] = 1
        elif state.history.jumpkind.startswith('Ijk_Exit'):
            # termination!
            state.globals['trace_idx'] = len(self._trace) - 1
        elif self.project.is_hooked(state.history.addr):
            # simprocedures - is this safe..?
            self._fast_forward(state)
        elif self._analyze_misfollow(state, idx):
            # misfollow analysis will set a sync point somewhere if it succeeds
            pass
        else:
            raise AngrTracerError("Oops! angr did not follow the trace.")

        if state.globals['sync_idx'] is not None:
            l.debug("Trace: %d-%d/%d synchronizing %d", state.globals['trace_idx'], state.globals['sync_idx'], len(self._trace), state.globals['sync_timer'])
        else:
            l.debug("Trace: %d/%d", state.globals['trace_idx'], len(self._trace))

    def _translate_state_addr(self, state_addr, obj=None):
        if obj is None:
            obj = self.project.loader.find_object_containing(state_addr)
        if obj not in self._aslr_slides:
            raise Exception("Internal error: cannot translate address")
        return state_addr + self._aslr_slides[obj]

    def _translate_trace_addr(self, trace_addr, obj):
        if obj not in self._aslr_slides:
            raise Exception("Internal error: object is untranslated")
        return trace_addr - self._aslr_slides[obj]

    def _compare_addr(self, trace_addr, state_addr):
        if self._current_slide is not None and trace_addr == state_addr + self._current_slide:
            return True

        current_bin = self.project.loader.find_object_containing(state_addr)
        if current_bin is self.project.loader._extern_object or current_bin is self.project.loader._kernel_object:
            return False
        elif current_bin in self._aslr_slides:
            self._current_slide = self._aslr_slides[current_bin]
            return trace_addr == state_addr + self._current_slide
        else:
            if ((trace_addr - state_addr) & 0xfff) == 0:
                self._aslr_slides[current_bin] = self._current_slide = trace_addr - state_addr
                return True
            else:
                raise AngrTracerError("Trace desynced on jumping into %s. Did you load the right version of this library?" % current_bin.provides)

    def _analyze_misfollow(self, state, idx):
        angr_addr = state.addr
        obj = self.project.loader.find_object_containing(angr_addr)
        if obj not in self._aslr_slides: # this SHOULD be an invariant given the way _compare_addrs works
            raise Exception("BUG: misfollow analysis initiated when jumping into a new object")

        slide = self._aslr_slides[obj]
        trace_addr = self._trace[idx + 1] - slide
        l.info("Misfollow: angr says %#x, trace says %#x", angr_addr, trace_addr)

        if not obj.contains_addr(trace_addr):
            l.error("Translated trace address lives in a different object from the angr trace")
            return False

        # TODO: add rep handling

        if 'IRSB' in state.history.recent_description:
            last_block = state.block(state.history.bbl_addrs[-1])
            if self._trace[idx + 1] - slide in last_block.instruction_addrs:
                # we have disparate block sizes!
                # specifically, the angr block size is larger than the trace's.
                # allow the trace to catch up.
                while self._trace[idx + 1] - slide in last_block.instruction_addrs:
                    idx += 1

                l.info('...resolved: disparate block sizes')

                if self._trace[idx + 1] - slide == state.addr:
                    state.globals['trace_idx'] = idx + 1
                    return True
                else:
                    state.globals['trace_idx'] = idx
                    #state.globals['trace_desync'] = True
                    return True

        prev_addr = state.history.bbl_addrs[-1]
        prev_obj = self.project.loader.find_object_containing(prev_addr)

        if state.block(prev_addr).vex.jumpkind == 'Ijk_Call':
            l.info('...syncing at callsite')
            return self._sync_callsite(state, idx, prev_addr)

        if prev_addr in getattr(prev_obj, 'reverse_plt', ()):
            prev_name = prev_obj.reverse_plt[prev_addr]
            prev_prev_addr = state.history.bbl_addrs[-2]
            if not prev_obj.contains_addr(prev_prev_addr) or state.block(prev_prev_addr).vex.jumpkind != 'Ijk_Call':
                l.info('...weird interaction with PLT stub (%s), aborting analysis', prev_name)
                return False
            l.info('...syncing at PLT callsite for %s', prev_name)
            return self._sync_callsite(state, idx, prev_prev_addr)

        l.info('...all analyses failed.')
        return False

    def _sync_callsite(self, state, idx, callsite_addr):
        retsite_addr = self._translate_state_addr(state.block(callsite_addr).size + callsite_addr)
        try:
            retsite_idx = self._trace.index(retsite_addr, idx)
        except ValueError:
            l.error("Trying to fix desync at callsite but return address does not appear in trace")
            return False

        state.globals['sync_idx'] = retsite_idx
        state.globals['trace_idx'] = idx
        state.globals['sync_timer'] = 10000  # TODO: ???
        return True

    def _fast_forward(self, state):
        target_addr = state.addr
        target_obj = self.project.loader.find_object_containing(target_addr)
        if target_obj not in self._aslr_slides:
            # if you see this message, consider implementing the find-entry-point hack for this, since if we're coming
            # out of a hook and get a cache miss like this the jump between objects is probably happening in the final
            # step of the skipped trace as well
            raise AngrTracerError("Trace needs to synchronize at an address for which the ASLR slide is unavailable!")
        self._current_slide = self._aslr_slides[target_obj]
        target_addr += self._current_slide
        try:
            target_idx = self._trace.index(target_addr, state.globals['trace_idx'] + 1)
        except ValueError:
            raise AngrTracerError("Trace failed to synchronize during fast forward? You might want to unhook %s." % (self.project.hooked_by(state.history.addr).display_name))
        else:
            state.globals['trace_idx'] = target_idx

    @classmethod
    def crash_windup(cls, state, crash_addr):
        # first check: are we just executing user-controlled code?
        if not state.ip.symbolic and state.mem[state.ip].char.resolved.symbolic:
            l.debug("executing input-related code")
            return state

        state = state.copy()
        state.options.add(sim_options.COPY_STATES)
        state.options.discard(sim_options.STRICT_PAGE_ACCESS)

        # before we step through and collect the actions we have to set
        # up a special case for address concretization in the case of a
        # controlled read or write vulnerability.
        bp1 = state.inspect.b(
            'address_concretization',
            BP_BEFORE,
            action=cls._check_add_constraints)

        bp2 = state.inspect.b(
            'address_concretization',
            BP_AFTER,
            action=cls._grab_concretization_results)

        # step to the end of the crashing basic block,
        # to capture its actions with those breakpoints
        state.step()

        # Add the constraints from concretized addrs back
        for var, concrete_vals in state.preconstrainer.address_concretization:
            if len(concrete_vals) > 0:
                l.debug("constraining addr to be %#x", concrete_vals[0])
                state.add_constraints(var == concrete_vals[0])

        # then we step again up to the crashing instruction
        inst_addrs = state.block().instruction_addrs
        inst_cnt = len(inst_addrs)

        if inst_cnt == 0:
            insts = 0
        elif crash_addr in inst_addrs:
            insts = inst_addrs.index(crash_addr) + 1
        else:
            insts = inst_cnt - 1

        l.debug("windup step...")
        succs = state.step(num_inst=insts).flat_successors

        last_state = None
        if len(succs) > 0:
            if len(succs) > 1:
                succs = [s for s in succs if s.solver.satisfiable()]
            state = succs[0]
            last_state = state

        # remove the preconstraints
        l.debug("removing preconstraints")
        state.preconstrainer.remove_preconstraints()

        l.debug("reconstraining... ")
        state.preconstrainer.reconstrain()

        # now remove our breakpoints since other people might not want them
        state.inspect.remove_breakpoint("address_concretization", bp1)
        state.inspect.remove_breakpoint("address_concretization", bp2)

        l.debug("final step...")
        succs = state.step()
        successors = succs.flat_successors + succs.unconstrained_successors
        crash_state = successors[0]
        return last_state, crash_state

    # the below are utility functions for crash windup

    @classmethod
    def _grab_concretization_results(cls, state):
        """
        Grabs the concretized result so we can add the constraint ourselves.
        """
        # only grab ones that match the constrained addrs
        if cls._should_add_constraints(state):
            addr = state.inspect.address_concretization_expr
            result = state.inspect.address_concretization_result
            if result is None:
                l.warning("addr concretization result is None")
                return
            state.preconstrainer.address_concretization.append((addr, result))

    @classmethod
    def _check_add_constraints(cls, state):
        """
        Obnoxious way to handle this, should ONLY be called from crash monitor.
        """
        # for each constrained addrs check to see if the variables match,
        # if so keep the constraints
        state.inspect.address_concretization_add_constraints = cls._should_add_constraints(state)

    @classmethod
    def _should_add_constraints(cls, state):
        """
        Check to see if the current address concretization variable is any of the registered
        constrained_addrs we want to allow concretization for
        """
        expr = state.inspect.address_concretization_expr
        hit_indices = cls._to_indices(state, expr)

        for action in state.preconstrainer._constrained_addrs:
            var_indices = cls._to_indices(state, action.addr)
            if var_indices == hit_indices:
                return True
        return False

    @staticmethod
    def _to_indices(state, expr):
        indices = []
        for descr in state.solver.describe_variables(expr):
            if descr[0] == 'file' and descr[1] == state.posix.stdin.ident:
                if descr[2] == 'packet':
                    indices.append(descr[3])
                elif type(descr[2]) is int:
                    indices.append(descr[2])

        return sorted(indices)
