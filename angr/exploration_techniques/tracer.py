import logging

from . import ExplorationTechnique
from .. import BP_BEFORE, sim_options
from ..calling_conventions import SYSCALL_CC
from ..errors import AngrTracerError, SimMemoryError, SimEngineError

l = logging.getLogger("angr.exploration_techniques.tracer")


class Tracer(ExplorationTechnique):
    """
    An exploration technique that follows an angr path with a concrete input.
    The tracing result is the state after executing the last basic block of the
    given trace and can be found in 'traced' stash.

    If the given concrete input makes the program crash, the last correct
    states that you might want are kept in the 'predecessors' list. The crashed
    state can be found with CrashMonitor exploration technique.
    """

    def __init__(self, trace=None, resiliency=True, dump_syscall=False, keep_predecessors=1):
        """
        :param trace:               The basic block trace.
        :param resiliency:          Should we continue to step forward even if qemu and angr disagree?
        :param dump_syscall:        True if we want to dump the syscall information.
        :param keep_predecessors:   Number of states before the final state we should preserve.
                                    Default 1, must be greater than 0.
        """

        super(Tracer, self).__init__()
        self._trace = trace
        self._resiliency = resiliency
        self._dump_syscall = dump_syscall

        # keep track of the last basic block we hit
        if keep_predecessors < 1:
            raise ValueError("Must have keep_predecessors >= 1")
        self.predecessors = [None] * keep_predecessors

        # whether we should follow the trace
        self._no_follow = self._trace is None

        # initilize the syscall statistics if the flag is on
        if self._dump_syscall:
            self._syscalls = []

    def setup(self, simgr):
        simgr.populate('missed', [])  # create the 'missed' stash

        self.project = simgr._project
        if len(simgr.active) != 1:
            raise Exception("Tracer is being invoked on a SimulationManager without exactly one active state")

        # initialize the basic block counter to 0
        simgr.one_active.globals['trace_idx'] = 0
        simgr.one_active.globals['sync_idx'] = None

        if self._dump_syscall:
            simgr.one_active.inspect.b('syscall', when=BP_BEFORE, action=self._syscall)

        elif self.project.loader.main_object.os != 'cgc':
            # Step forward until we catch up with QEMU
            while self._trace and simgr.one_active.addr != self._trace[0]:
                simgr.step()
                if len(simgr.active) == 0:
                    raise Exception("Could not step to the first address of the trace - simgr is empty")
                elif len(simgr.active) > 1:
                    raise Exception("Could not step to the first address of the trace - state split")

        simgr.one_active.options.add(sim_options.LAZY_SOLVES)

    def complete(self, simgr):
        if not simgr.active or simgr.one_active.globals['trace_idx'] >= len(self._trace) - 1:
            simgr.stash(from_stash='active', to_stash='traced')
            return True

        return False

    def _update_state_tracking(self, state):
        idx = state.globals['trace_idx']
        sync = state.globals['sync_idx']

        if state.history.recent_block_count > 1:
            # multiple blocks were executed this step. they should follow the trace *perfectly*
            # or else something is up
            # "something else" so far only includes concrete transmits
            assert state.history.recent_block_count == len(state.history.recent_bbl_addrs)

            # clear the concrete transmit address out
            i = 0
            step_addrs = [addr for addr in state.history.recent_bbl_addrs if addr != state.unicorn.transmit_addr]

            if sync is not None:
                raise Exception("TODO")
            if step_addrs == self._trace[idx:idx+len(step_addrs)]:
                idx = state.globals['trace_idx'] = idx + len(step_addrs) - 1
            else:
                raise Exception('BUG! Please investivate the claim in the comment above me')


        if sync is not None:
            if state.addr == self._trace[sync]:
                state.globals['trace_idx'] = sync
                state.globals['sync_idx'] = None
            else:
                raise Exception("Trace did not sync after 1 step, you knew this would happen")

        elif state.addr == self._trace[idx + 1]:
            state.globals['trace_idx'] = idx + 1
        elif state.history.jumpkind.startswith('Ijk_Sys'):
            state.globals['sync_idx'] = idx + 1
        else:
            raise Exception("Oops! The state did not follow the trace.")

        l.debug("Trace: %d/%d", state.globals['trace_idx'], len(self._trace))

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

    def step_state(self, simgr, state, extra_stop_points=(), **kwargs):
        stops = set(extra_stop_points) | {self._trace[-1]}
        succs_dict = simgr.step_state(state, extra_stop_points=stops, **kwargs)
        succs = succs_dict[None]

        if len(succs) == 1:
            self._update_state_tracking(succs[0])
        elif len(succs) == 0:
            raise Exception("All states disappeared!")
        else:
            succ = self._pick_correct_successor(succs)
            succs_dict[None] = [succ]
            succs_dict['missed'] = [s for s in succs if s is not succ]

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

    def _syscall(self, state):
        syscall_addr = state.solver.eval(state.ip)
        args = None

        # 0xa000008 is terminate, which we exclude from syscall statistics.
        if self.project.loader.main_object.os == 'cgc' and syscall_addr != 0xa000008:
            args = SYSCALL_CC['X86']['CGC'](self.project.arch).get_args(state, 4)
        else:
            args = SYSCALL_CC[self.project.arch.name]['Linux'](self.project.arch).get_arbs(state, 4)

        if args is not None:
            d = {'addr': syscall_addr}
            for i in range(4):
                d['arg_%d' % i] = args[i]
                d['arg_%d_symbolic' % i] = args[i].symbolic
            self._syscalls.append(d)

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
