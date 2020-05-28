from typing import List
import logging

from . import ExplorationTechnique
from .. import BP_BEFORE, BP_AFTER, sim_options
from ..errors import AngrTracerError

l = logging.getLogger(name=__name__)


class TracingMode:
    """
    :ivar Strict:       Strict mode, the default mode, where an exception is raised immediately if tracer's path
                        deviates from the provided trace.
    :ivar Permissive:   Permissive mode, where tracer attempts to force the path back to the provided trace when a
                        deviation happens. This does not always work, especially when the cause of deviation is related
                        to input that will later be used in exploit generation. But, it might work magically sometimes.
    :ivar CatchDesync:  CatchDesync mode, catch desync because of sim_procedures. It might be a sign of something
                        interesting.
    """
    Strict = 'strict'
    Permissive = 'permissive'
    CatchDesync = 'catch_desync'


class TracerDesyncError(AngrTracerError):
    def __init__(self, msg, deviating_addr=None, deviating_trace_idx=None):
        super().__init__(msg)
        self.deviating_addr = deviating_addr
        self.deviating_trace_idx = deviating_trace_idx


class RepHook:
    def __init__(self, mnemonic):
        self.mnemonic = mnemonic

    def _inline_call(self, state, procedure, *arguments, **kwargs):
        e_args = [state.solver.BVV(a, state.arch.bits) if isinstance(a, int) else a for a in arguments]
        p = procedure(project=state.project, **kwargs)
        return p.execute(state, None, arguments=e_args)

    def run(self, state):

        from .. import SIM_PROCEDURES

        dst = state.regs.edi if state.arch.name == "X86" else state.regs.rdi

        if self.mnemonic.startswith("stos"):
            # store a string
            if self.mnemonic == "stosb":
                val = state.regs.al
                multiplier = 1
            elif self.mnemonic == "stosw":
                val = state.regs.ax
                multiplier = 2
            elif self.mnemonic == "stosd":
                val = state.regs.eax
                multiplier = 4
            elif self.mnemonic == "stosq":
                val = state.regs.rax
                multiplier = 8
            else:
                raise NotImplementedError("Unsupported mnemonic %s" % self.mnemonic)

            size = (state.regs.ecx if state.arch.name == "X86" else state.regs.rcx) * multiplier

            memset = SIM_PROCEDURES['libc']["memset"]
            memset().execute(state, arguments=[dst, val, size])

            if state.arch.name == "X86":
                state.regs.edi += size
                state.regs.ecx = 0
            else:
                state.regs.rdi += size
                state.regs.rcx = 0

        elif self.mnemonic.startswith("movs"):

            src = state.regs.esi if state.arch.name == "X86" else state.regs.rsi

            # copy a string
            if self.mnemonic == "movsb":
                multiplier = 1
            elif self.mnemonic == "movsw":
                multiplier = 2
            elif self.mnemonic == "movsd":
                multiplier = 4
            elif self.mnemonic == "movsq":
                multiplier = 8
            else:
                raise NotImplementedError("Unsupported mnemonic %s" % self.mnemonic)

            size = (state.regs.ecx if state.arch.name == "X86" else state.regs.rcx) * multiplier

            memcpy = SIM_PROCEDURES['libc']["memcpy"]
            memcpy().execute(state, arguments=[dst, src, size])

            if state.arch.name == "X86":
                state.regs.edi += size
                state.regs.esi -= size
                state.regs.ecx = 0
            else:
                state.regs.rdi += size
                state.regs.rsi -= size
                state.regs.rcx = 0

        else:
            import ipdb; ipdb.set_trace()


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
    :param mode:                Tracing mode.

    :ivar predecessors:         A list of states in the history before the final state.
    """

    def __init__(self,
            trace=None,
            resiliency=False,
            keep_predecessors=1,
            crash_addr=None,
            copy_states=False,
            mode=TracingMode.Strict):
        super(Tracer, self).__init__()
        self._trace = trace
        self._resiliency = resiliency
        self._crash_addr = crash_addr
        self._copy_states = copy_states
        self._mode = mode

        self._aslr_slides = {}
        self._current_slide = None

        # keep track of the last basic block we hit
        self.predecessors = [None] * keep_predecessors # type: List[angr.SimState]
        self.last_state = None

        # whether we should follow the trace
        self._no_follow = self._trace is None

        # sanity check: copy_states must be enabled in Permissive mode since we may need to backtrack from a previous
        # state.
        if self._mode == TracingMode.Permissive and not self._copy_states:
            raise ValueError('"copy_states" must be True when tracing in permissive mode.')

    def setup(self, simgr):
        simgr.populate('missed', [])
        simgr.populate('traced', [])
        simgr.populate('crashed', [])
        simgr.populate('desync', [])

        self.project = simgr._project
        if len(simgr.active) != 1:
            raise AngrTracerError("Tracer is being invoked on a SimulationManager without exactly one active state")

        # calc ASLR slide for main binary and find the entry point in one fell swoop
        # ...via heuristics
        for idx, addr in enumerate(self._trace):
            if self.project.loader.main_object.pic:
                if ((addr - self.project.entry) & 0xfff) == 0 and (idx == 0 or abs(self._trace[idx-1] - addr) > 0x100000):
                    break
            else:
                if addr == self.project.entry:
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
            simgr.drop(stash='unsat')

        # initialize the state info
        simgr.one_active.globals['trace_idx'] = idx
        simgr.one_active.globals['sync_idx'] = None
        simgr.one_active.globals['sync_timer'] = 0
        simgr.one_active.globals['is_desync'] = False

        # disable state copying!
        if not self._copy_states:
            # insulate our caller from this nonsense by making a single copy at the beginning
            simgr.active[0] = simgr.active[0].copy()
            simgr.active[0].options.remove(sim_options.COPY_STATES)

    def complete(self, simgr):
        return bool(simgr.traced)

    def filter(self, simgr, state, **kwargs):
        # check completion
        if state.globals['trace_idx'] >= len(self._trace) - 1:
            # if the the state is a desync state and the user wants to keep it,
            # then do what the user wants
            if self._mode == TracingMode.CatchDesync and self.project.is_hooked(state.addr):
                return 'desync'
            # do crash windup if necessary
            if self._crash_addr is not None:
                self.last_state, crash_state = self.crash_windup(state, self._crash_addr)
                simgr.populate('crashed', [crash_state])
                self.predecessors.append(state)
                self.predecessors.pop(0)

            return 'traced'

        return simgr.filter(state, **kwargs)

    def step(self, simgr, stash='active', **kwargs):
        simgr.drop(stash='missed')
        return simgr.step(stash=stash, **kwargs)

    def step_state(self, simgr, state, **kwargs):
        if state.history.jumpkind == 'Ijk_Exit':
            return {'traced': [state]}

        # maintain the predecessors list
        self.predecessors.append(state)
        self.predecessors.pop(0)

        if state.globals['trace_idx'] > len(self._trace) * 0.98:
            state.options.add(sim_options.COPY_STATES)
            state.options.add(sim_options.LAZY_SOLVES)

        # optimization:
        # look forward, is it a rep stos/movs instruction?
        # if so, we add a temporary hook to speed up constraint solving
        block = self.project.factory.block(state.addr)
        if len(block.capstone.insns) == 1 and (
                block.capstone.insns[0].mnemonic.startswith("rep m") or
                block.capstone.insns[0].mnemonic.startswith("rep s")
        ) and not self.project.is_hooked(state.addr):
            insn = block.capstone.insns[0]
            self.project.hook(state.addr, RepHook(insn.mnemonic.split(" ")[1]).run, length=insn.size)

        # perform the step. ask qemu to stop at the termination point.
        stops = set(kwargs.pop('extra_stop_points', ())) | {self._trace[-1]}
        succs_dict = simgr.step_state(state, extra_stop_points=stops, **kwargs)
        sat_succs = succs_dict[None]  # satisfiable states
        succs = sat_succs + succs_dict['unsat']  # both satisfiable and unsatisfiable states

        if self._mode == TracingMode.Permissive:
            # permissive mode
            if len(sat_succs) == 1:
                try:
                    self._update_state_tracking(sat_succs[0])
                except TracerDesyncError as ex:
                    if self._mode == TracingMode.Permissive:
                        succs_dict = self._force_resync(simgr, state, ex.deviating_trace_idx, ex.deviating_addr, kwargs)
                    else:
                        raise
            elif len(sat_succs) == 0:
                raise Exception("No satisfiable state is available!")
            else:
                succ = self._pick_correct_successor(sat_succs)
                succs_dict[None] = [succ]
                succs_dict['missed'] = [s for s in sat_succs if s is not succ]
        else:
            # strict mode
            if len(succs) == 1:
                self._update_state_tracking(succs[0])
            elif len(succs) == 0:
                raise Exception("All states disappeared!")
            else:
                succ = self._pick_correct_successor(succs)
                succs_dict[None] = [succ]
                succs_dict['missed'] = [s for s in succs if s is not succ]
        assert len(succs_dict[None]) == 1

        # if there is a catchable desync, we should return the last sync state
        if succs_dict[None][0].globals['is_desync']:
            simgr.active[0].globals['trace_idx'] = len(self._trace)
            succs_dict[None][0] = state
        return succs_dict

    def _force_resync(self, simgr, state, deviating_trace_idx, deviating_addr, kwargs):
        """
        When a deviation happens, force the tracer to take the branch specified in the trace by manually setting the
        PC to the one in the trace. This method is only used in Permissive tracing mode.

        :param simgr:               The simulation manager instance.
        :param state:               The program state before the current step.
        :param deviating_trace_idx: The index of address in the trace where a desync happens.
        :param deviating_addr:      The address that tracer takes when the desync happens. Should be different from the
                                    one in the trace.
        :param kwargs:              Other keyword arguments that will be passed to step_state().
        :return:                    A new successor dict.
        :rtype:                     dict
        """

        # if unicorn engine is enabled, disable it. forced execution requires single-stepping in angr.
        unicorn_option_removed = False
        if sim_options.UNICORN in state.options:
            state.options.remove(sim_options.UNICORN)
            unicorn_option_removed = True

        # single step until right before the deviating state
        trace_idx = state.globals['trace_idx']
        while trace_idx != deviating_trace_idx - 1:
            succs_dict = simgr.step_state(state, **kwargs)
            succs = succs_dict[None]
            assert len(succs) == 1
            self._update_state_tracking(succs[0])
            state = succs[0]
            trace_idx += 1

        # step the state further and then manually set the PC
        succs_dict = simgr.step_state(state, **kwargs)
        succs = succs_dict[None]
        if len(succs) != 1 or succs[0].addr != deviating_addr:
            raise TracerDesyncError("Address mismatch during single-stepping.")
        succ = succs[0]
        expected_addr = self._trace[deviating_trace_idx]
        current_obj = self.project.loader.find_object_containing(state.addr)
        assert current_obj is not None
        translated_addr = self._translate_trace_addr(expected_addr, current_obj)
        l.info("Attempt to fix a deviation: Forcing execution from %#x to %#x (instead of %#x).",
               state.addr, succ.addr, translated_addr)
        succ._ip = translated_addr

        succ.globals['trace_idx'] = trace_idx + 1
        succs_dict = {None: [succ]}

        if unicorn_option_removed:
            succ.options.add(sim_options.UNICORN)

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
                    raise TracerDesyncError('BUG! Please investigate the claim in the comment above me',
                                            deviating_addr=addr,
                                            deviating_trace_idx=idx)

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

        elif state.history.jumpkind.startswith('Ijk_Exit'):
            # termination! will be handled by filter
            pass
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
        elif self.project.is_hooked(state.history.addr):
            # simprocedures - is this safe..?
            self._fast_forward(state)
        elif state.addr == self._trace[-1]:
            # we may have prematurely stopped because of setting stop points. try to resync.
            state.globals['sync_idx'] = idx + 1
            state.globals['sync_timer'] = 1
        elif self._analyze_misfollow(state, idx):
            # misfollow analysis will set a sync point somewhere if it succeeds
            pass
        else:
            raise TracerDesyncError("Oops! angr did not follow the trace",
                                    deviating_addr=state.addr,
                                    deviating_trace_idx=idx+1)

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
        elif ((trace_addr - state_addr) & 0xfff) == 0:
                self._aslr_slides[current_bin] = self._current_slide = trace_addr - state_addr
                return True
        # error handling
        elif current_bin:
            raise AngrTracerError("Trace desynced on jumping into %s. Did you load the right version of this library?" % current_bin.provides)
        else:
            raise AngrTracerError("Trace desynced on jumping into %#x, where no library is mapped!" % state_addr)

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
            l.info('...syncing at PLT callsite for %s', prev_name)
            # TODO: this method is newer than sync_callsite. should it be used always?
            return self._sync_return(state, idx, assert_obj=prev_obj)

        if prev_obj is not None:
            prev_section = prev_obj.find_section_containing(prev_addr)
            if prev_section is not None:
                if prev_section.name in (".plt",):
                    l.info("...syncing at PLT callsite (type 2)")
                    return self._sync_return(state, idx, assert_obj=prev_obj)

        l.info('...all analyses failed.')
        return False

    def _sync_callsite(self, state, idx, callsite_addr):
        retsite_addr = state.block(callsite_addr).size + callsite_addr
        return self._sync(state, idx, retsite_addr)

    def _sync_return(self, state, idx, assert_obj=None):
        ret_addr_bv = self.project.factory.cc().return_addr.get_value(state)
        if state.solver.symbolic(ret_addr_bv):
            l.info('...symbolic return address. I refuse to deal with this.')
            return False

        ret_addr = state.solver.eval(ret_addr_bv)
        if assert_obj is not None and not assert_obj.contains_addr(ret_addr):
            l.info('...address is not in the correct object, aborting analysis')
            return False
        return self._sync(state, idx, ret_addr)

    def _sync(self, state, idx, addr):
        addr_translated = self._translate_state_addr(addr)
        try:
            sync_idx = self._trace.index(addr_translated, idx)
        except ValueError:
            l.error("Trying to synchronize at %#x (%#x) but it does not appear in the trace?")
            return False

        state.globals['sync_idx'] = sync_idx
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
        except ValueError as e:
            # if the user wants to catch desync caused by sim_procedure,
            # mark this state as a desync state and then end the tracing prematurely
            if self._mode == TracingMode.CatchDesync:
                state.globals['is_desync'] = True
                return
            raise AngrTracerError("Trace failed to synchronize during fast forward? You might want to unhook %s." % (self.project.hooked_by(state.history.addr).display_name)) from e
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
