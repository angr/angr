import logging

from . import ExplorationTechnique
from .. import BP_BEFORE, BP_AFTER, sim_options
from ..errors import AngrTracerError, SimMemoryError, SimEngineError

l = logging.getLogger("angr.exploration_techniques.tracer")


class Tracer(ExplorationTechnique):
    """
    An exploration technique that follows an angr path with a concrete input.
    The tracing result is the state at the last address of the trace, which can be found in the
    'traced' stash.

    If the given concrete input makes the program crash, the last correct states that you might
    want are kept in the 'predecessors' list. If you provide crash_addr, the crashing state will
    be found in the 'crashed' stash.

    :param trace:               The basic block trace.
    :param resiliency:          Should we continue to step forward even if qemu and angr disagree?
    :param keep_predecessors:   Number of states before the final state we should log.
    :param crash_addr:          If the trace resulted in a crash, provide the crashing instruction
                                pointer here, and the 'crashed' stash will be populated with the
                                crashing state.
    """

    def __init__(self,
            trace=None,
            resiliency=False,
            keep_predecessors=0,
            crash_addr=None):
        super(Tracer, self).__init__()
        self._trace = trace
        self._resiliency = resiliency
        self._crash_addr = crash_addr

        self._aslr_slides = {}
        self._current_slide = None

        # keep track of the last basic block we hit
        self.predecessors = [None] * keep_predecessors
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
        self._current_slide = self._aslr_slides[self.project.loader.main_object] = self.project.entry - self._trace[idx]

        # step to entry point
        while self._trace and self._trace[idx] != simgr.one_active.addr + self._current_slide:
            simgr.step()
            if len(simgr.active) == 0:
                raise AngrTracerError("Could not step to the first address of the trace - simgr is empty")
            elif len(simgr.active) > 1:
                raise AngrTracerError("Could not step to the first address of the trace - state split")

        # initialize the state info
        simgr.one_active.globals['trace_idx'] = idx
        simgr.one_active.globals['sync_idx'] = None

        # enable lazy solves - don't touch z3 unless I tell you so
        simgr.one_active.options.add(sim_options.LAZY_SOLVES)

    def complete(self, simgr):
        return bool(simgr.traced)

    def filter(self, simgr, state, **kwargs):
        # check completion
        if state.globals['trace_idx'] >= len(self._trace) - 1:
            # do crash windup if necessary
            if self._crash_addr is not None:
                simgr.populate('crashed', [self._crash_windup(state)])

            return 'traced'

        return simgr.filter(state, **kwargs)

    def _compare_addr(self, trace_addr, state_addr, state=None):
        if self._current_slide is not None and trace_addr == state_addr + self._current_slide:
            return True

        current_bin = self.project.loader.find_object_containing(state_addr)
        if current_bin is self.project.loader._extern_object:
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



    def _update_state_tracking(self, state):
        idx = state.globals['trace_idx']
        sync = state.globals['sync_idx']

        if state.history.recent_block_count > 1:
            # multiple blocks were executed this step. they should follow the trace *perfectly*
            # or else something is up
            # "something else" so far only includes concrete transmits
            assert state.history.recent_block_count == len(state.history.recent_bbl_addrs)

            if sync is not None:
                raise Exception("TODO")

            for addr in state.history.recent_bbl_addrs:
                if addr == state.unicorn.transmit_addr:
                    continue

                if self._compare_addr(self._trace[idx], addr):
                    idx += 1
                else:
                    raise Exception('BUG! Please investivate the claim in the comment above me')

            idx -= 1 # use normal code to do the last synchronization

        if sync is not None:
            if self._compare_addr(self._trace[sync], state.addr):
                state.globals['trace_idx'] = sync
                state.globals['sync_idx'] = None
            else:
                raise Exception("Trace did not sync after 1 step, you knew this would happen")

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
                    raise Exception("BUG: State is returning to a continuation that isn't its own???")
            else:
                # see above
                pass
        elif state.history.jumpkind.startswith('Ijk_Sys'):
            # syscalls
            state.globals['sync_idx'] = idx + 1
        elif self.project.is_hooked(state.history.addr):
            # simprocedures - is this safe..?
            self._fast_forward(state)
        else:
            raise AngrTracerError("Oops! angr did not follow the trace.")

        l.debug("Trace: %d/%d", state.globals['trace_idx'], len(self._trace))

    def _fast_forward(self, state):
        target_addr = state.addr
        target_obj = self.project.loader.find_object_containing(target_addr)
        if target_obj not in self._aslr_slides:
            # if you see this message, consider implementing the find-entry-point hack for this, since if we're coming
            # out of a hook and get a cache miss like this the jump between objects is probably happening in the final
            # step of the skipped trace as well
            raise AngrTracerError("Trace needs to syncronize at an address for which the ASLR slide is unavailable!")
        self._current_slide = self._aslr_slides[target_obj]
        target_addr += self._current_slide
        try:
            target_idx = self._trace.index(target_addr, state.globals['trace_idx'] + 1)
        except ValueError:
            raise AngrTracerError("Trace failed to synchronize during fast forward? You might want to unhook %s." % (self.project.hooked_by(state.history.addr).display_name))
        else:
            state.globals['trace_idx'] = target_idx

    def _pick_correct_successor(self, succs):
        # there's been a branch of some sort. Try to identify which state stayed on the trace.
        assert len(succs) > 0
        idx = succs[0].globals['trace_idx']

        res = []
        for succ in succs:
            if succ.addr == self._trace[idx + 1]:
                res.append(succ)

        if not res:
            raise Exception("No states followed the trace?")

        if len(res) > 1:
            raise Exception("The state split but several successors have the same (correct) address?")

        self._update_state_tracking(res[0])
        return res[0]

    def step_state(self, simgr, state, **kwargs):
        # maintain the predecessors list
        self.predecessors.append(state)
        self.predecessors.pop(0)

        # perform the step. ask qemu to stop at the termination point.
        stops = set(kwargs.pop('extra_stop_points', ())) | {self._trace[-1]}
        succs_dict = simgr.step_state(state, extra_stop_points=stops, **kwargs)
        succs = succs_dict[None]

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

        if len(simgr.active) == 1:
            current = simgr.active[0]

            if current.history.recent_block_count > 1:
                # executed unicorn fix trace_idx
                current.globals['trace_idx'] += current.history.recent_block_count - 1 - current.history.recent_syscall_count

            if not self._no_follow:
                # termination condition: we exhausted the dynamic trace log
                if current.globals['trace_idx'] >= len(self._trace):
                    return simgr
# now, we switch through several ways that the dynamic and symbolic traces can interact

                # basic, convenient case: the two traces match
                if current.addr == self._trace[current.globals['trace_idx']]:
                    current.globals['trace_idx'] += 1

                # angr will count a syscall as a step, qemu will not. they will sync next step.
                elif current.history.jumpkind.startswith("Ijk_Sys"):
                    pass

                # handle library calls and simprocedures
                elif self.project.is_hooked(current.addr)              \
                  or self.project.simos.is_syscall_addr(current.addr) \
                  or not self._address_in_binary(current.addr):
                    # If dynamic trace is in the PLT stub, update trace_idx until it's out
                    while current.globals['trace_idx'] < len(self._trace) and self._addr_in_plt(self._trace[current.globals['trace_idx']]):
                        current.globals['trace_idx'] += 1

                # handle hooked functions
                # TODO: this branch is totally missed by the test cases
                elif self.project.is_hooked(current.history.addr) \
                 and current.history.addr in self.project._sim_procedures:
                    l.debug("ending hook for %s", self.project.hooked_by(current.history.addr))
                    l.debug("previous addr %#x", current.history.addr)
                    l.debug("trace_idx %d", current.globals['trace_idx'])
                    # we need step to the return
                    current_addr = current.addr
                    while current.globals['trace_idx'] < len(self._trace) and current_addr != self._trace[current.globals['trace_idx']]:
                        current.globals['trace_idx'] += 1
                    # step 1 more for the normal step that would happen
                    current.globals['trace_idx'] += 1
                    l.debug("trace_idx after the correction %d", current.globals['trace_idx'])
                    if current.globals['trace_idx'] >= len(self._trace):
                        return simgr

                else:
                    l.error( "the dynamic trace and the symbolic trace disagreed")

                    l.error("[%s] dynamic [0x%x], symbolic [0x%x]",
                            self.project.filename,
                            self._trace[current.globals['trace_idx']],
                            current.addr)

                    if self._resiliency:
                        l.error("TracerMisfollowError encountered")
                        l.warning("entering no follow mode")
                        self._no_follow = True
                    else:
                        raise AngrTracerError("misfollow")

            # maintain the predecessors list
            self.predecessors.append(current)
            self.predecessors.pop(0)

            # Basic block's max size in angr is greater than the one in Qemu
            # We follow the one in Qemu
            if current.globals['trace_idx'] >= len(self._trace):
                bbl_max_bytes = 800
            else:
                y2 = self._trace[current.globals['trace_idx']]
                y1 = self._trace[current.globals['trace_idx'] - 1]
                bbl_max_bytes = y2 - y1
                if bbl_max_bytes <= 0:
                    bbl_max_bytes = 800

            # detect back loops (a block jumps back to the middle of itself) that have to be differentiated from the
            # case where max block sizes doesn't match.

            # this might still break for huge basic blocks with back loops, but it seems unlikely.
            try:
                bl = self.project.factory.block(self._trace[current.globals['trace_idx']-1],
                        backup_state=current)
                back_targets = set(bl.vex.constant_jump_targets) & set(bl.instruction_addrs)
                if current.globals['trace_idx'] < len(self._trace) and self._trace[current.globals['trace_idx']] in back_targets:
                    target_to_jumpkind = bl.vex.constant_jump_targets_and_jumpkinds
                    if target_to_jumpkind[self._trace[current.globals['trace_idx']]] == "Ijk_Boring":
                        bbl_max_bytes = 800
            except (SimMemoryError, SimEngineError):
                bbl_max_bytes = 800

            # drop the missed stash before stepping, since driller needs missed paths later.
            simgr.drop(stash='missed')

            simgr.step(stash=stash, size=bbl_max_bytes)

            # if our input was preconstrained we have to keep on the lookout for unsat paths.
            simgr.stash(from_stash='unsat', to_stash='active')

            simgr.drop(stash='unsat')

        # if we stepped to a point where there are no active paths, return the simgr.
        if len(simgr.active) == 0:
            # possibly we want to have different behaviour if we're in crash mode.
            return simgr

        if len(simgr.active) > 1:
            # if we get to this point there's more than one active path
            # if we have to ditch the trace we use satisfiability
            # or if a split occurs in a library routine
            a_paths = simgr.active

            if self._no_follow or all(map( lambda p: not self._address_in_binary(p.addr), a_paths)):
                simgr.prune(to_stash='missed')
            else:
                l.debug("bb %d / %d", current.globals['trace_idx'], len(self._trace))
                if current.globals['trace_idx'] < len(self._trace):
                    simgr.stash(lambda s: s.addr != self._trace[current.globals['trace_idx']], to_stash='missed')
            if len(simgr.active) > 1: # rarely we get two active paths
                simgr.prune(to_stash='missed')

            if len(simgr.active) > 1: # might still be two active
                simgr.stash(to_stash='missed', filter_func=lambda x: x.jumpkind == "Ijk_EmWarn")

            # make sure we only have one or zero active paths at this point
            assert len(simgr.active) < 2

            # something weird... maybe we hit a rep instruction?
            # qemu and vex have slightly different behaviors...
            if not simgr.active[0].solver.satisfiable():
                l.info("detected small discrepancy between qemu and angr, "
                        "attempting to fix known cases...")

                # Have we corrected it?
                corrected = False

                # did our missed branch try to go back to a rep?
                target = simgr.missed[0].addr
                if self.project.arch.name == 'X86' or self.project.arch.name == 'AMD64':

                    # does it looks like a rep? rep ret doesn't count!
                    if self.project.factory.block(target).bytes.startswith(b"\xf3") and \
                       not self.project.factory.block(target).bytes.startswith(b"\xf3\xc3"):

                        l.info("rep discrepency detected, repairing...")
                        # swap the stashes
                        simgr.move('missed', 'chosen')
                        simgr.move('active', 'missed')
                        simgr.move('chosen', 'active')

                        corrected = True
                    else:
                        l.info("...not rep showing up as one/many basic blocks")

                if not corrected:
                    l.warning("Unable to correct discrepancy between qemu and angr.")

    def _address_in_binary(self, addr):
        """
        Determine if the given address is in the binary being traced.

        :param addr: the address to test
        :return: True if the address is in between the binary's min and max addresses.
        """

        mb = self.project.loader.main_object
        return mb.min_addr <= addr < mb.max_addr

    def _addr_in_plt(self, addr):
        """
        Check if an address is inside the plt section
        """
        plt = self.project.loader.main_object.sections_map.get('.plt', None)
        return False if plt is None else plt.min_addr <= addr < plt.max_addr

    def _crash_windup(self, state):
        # first check: are we just executing user-controlled code?
        if not state.ip.symbolic and state.mem[state.ip].char.resolved.symbolic:
            l.debug("executing input-related code")
            return state

        # before we step through and collect the actions we have to set
        # up a special case for address concretization in the case of a
        # controlled read or write vulnerability.
        bp1 = state.inspect.b(
            'address_concretization',
            BP_BEFORE,
            action=self._check_add_constraints)

        bp2 = state.inspect.b(
            'address_concretization',
            BP_AFTER,
            action=self._grab_concretization_results)

        # step to the end of the crashing basic block,
        # to capture its actions with those breakpoints
        # TODO should this be using simgr.successors?
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
        elif self._crash_addr in inst_addrs:
            insts = inst_addrs.index(self._crash_addr) + 1
        else:
            insts = inst_cnt - 1

        l.debug("windup step...")
        succs = state.step(num_inst=insts).flat_successors

        if len(succs) > 0:
            if len(succs) > 1:
                succs = [s for s in succs if s.solver.satisfiable()]
            state = succs[0]
            self.last_state = state

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
        return successors[0]

    # the below are utility functions for crash windup

    def _grab_concretization_results(self, state):
        """
        Grabs the concretized result so we can add the constraint ourselves.
        """
        # only grab ones that match the constrained addrs
        if self._should_add_constraints(state):
            addr = state.inspect.address_concretization_expr
            result = state.inspect.address_concretization_result
            if result is None:
                l.warning("addr concretization result is None")
                return
            state.preconstrainer.address_concretization.append((addr, result))

    def _check_add_constraints(self, state):
        """
        Obnoxious way to handle this, should ONLY be called from crash monitor.
        """
        # for each constrained addrs check to see if the variables match,
        # if so keep the constraints
        state.inspect.address_concretization_add_constraints = self._should_add_constraints(state)

    def _should_add_constraints(self, state):
        """
        Check to see if the current address concretization variable is any of the registered
        constrained_addrs we want to allow concretization for
        """
        expr = state.inspect.address_concretization_expr
        hit_indices = self._to_indices(state, expr)

        for action in state.preconstrainer._constrained_addrs:
            var_indices = self._to_indices(state, action.addr)
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
