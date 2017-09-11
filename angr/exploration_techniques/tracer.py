import angr
import claripy
import logging

from . import ExplorationTechnique
from .oppologist import Oppologist

from .. import SIM_LIBRARIES, BP_AFTER, BP_BEFORE

from ..calling_conventions import SYSCALL_CC
from ..errors import AngrTracerError, TracerEnvironmentError
from ..misc.tracer.tracerpov import TracerPoV
from ..misc.tracer.simprocedures import receive

l = logging.getLogger("angr.exploration_techniques.tracer")

# global writable attribute used for specifying cache procedures
#GlobalCacheManager = None

EXEC_STACK = 'EXEC_STACK'
QEMU_CRASH = 'SEG_FAULT'

class Tracer(ExplorationTechnique):
    """
    An exploration technique that follows an angr path with a concrete input.
    The result of this is a tuple of:
    - a deadended path of a complete symbolic run of the program with input/pov_file,
    - the final state after execution with input/pov_file.
    """

    def __init__(self, trace=None, crash_mode=False, crash_addr=None, resiliency=True,
                 trim_history=True, dump_syscall=False, keep_predecessors=1):
        """
        :param trace            : The basic block trace.
        :param crash_mode       : Whether or not the preconstrained input causes a crash.
        :param crash_addr       : If the input caused a crash, what address did it crash at?
        :param resiliency       : Should we continue to step forward even if qemu and angr disagree?
        :param trim_history     : Trim the history of a path.
        :param dump_syscall     : True if we want to dump the syscall information.
        :param keep_predecessors: Number of states before the final state we should preserve.
                                  Default 1, must be greater than 0.
        """

        self._trace = trace
        self._crash_mode = crash_mode
        self._crash_addr = crash_addr
        self._resiliency = resiliency
        self._trim_history = trim_history
        self._dump_syscall = dump_syscall

        # keep track of the last basic block we hit
        if keep_predecessors < 1:
            raise ValueError("Must have keep_predecessors >= 1")
        self._predecessors = [None] * keep_predecessors

        self._crash_type = None
        self._crash_state = None

       #cm = LocalCacheManager(dump_cache=dump_cache) if GlobalCacheManager is None else GlobalCacheManager
       ## cache managers need the tracer to be set for them
       #self._cache_manager = cm
       #self._cache_manager.set_tracer(self)

       ## set by a cache manager
       #self._loaded_from_cache = False

       ## set up cache hook
       #receive.cache_hook = self._cache_manager.cacher

        # initialize the basic block counter to 0
        self._bb_cnt = 0

        # whether we should follow the qemu trace
        self._no_follow = self._trace is None

        # initilize the syscall statistics if the flag is on
        if self._dump_syscall:
            self._syscall = []

        self.results = None

    def setup(self, simgr):
        self.project = simgr._project
        s = simgr.active[0]

        if self.project.loader.main_object.os == 'cgc':
            if self._dump_syscall:
                s.inspect.b('syscall', when=BP_BEFORE, action=self._syscall)

            simgr.use_technique(Oppologist())
            l.info("Oppologist enabled.")

        elif self.project.loader.main_object.os.startswith('UNIX'):
            # Step forward until we catch up with QEMU
            if self._trace and s.addr != self._trace[0]:
                simgr = simgr.explore(find=self.project.entry)
                simgr = simgr.drop(stash="unsat")
                simgr = simgr.unstash(from_stash="found",to_stash="active")

        s.inspect.b('state_step', when=BP_AFTER, action=self._check_stack)

    def complete(self, simgr):
        # if we spot a crashed path in crash mode return the goods
        if self._crash_type == EXEC_STACK:
            self.results = (simgr.crashed[0], self._crash_state)
            return True

        elif self._crash_mode and self._bb_cnt >= len(self._trace):
            self._crash_type == QEMU_CRASH
            simgr.stash(from_stash='active', to_stash='crashed')

            last_block = self._trace[self._bb_cnt - 1]
            l.info("crash occured in basic block %x", last_block)

            # time to recover the crashing state
            final_state = self._crash_windup()
            l.debug("tracing done!")
            self.results = (self._predecessors[-1], final_state)
            return True

        if not len(simgr.active) or self._bb_cnt >= len(self._trace):
            # this is a concrete trace, there should only be ONE path
            all_paths = simgr.active + simgr.deadended

            if len(all_paths) != 1:
                raise AngrTracerError("Program did not behave correctly, expected only one path.")

            # the caller is responsible for removing preconstraints
            self.results = (all_paths[0], None)
            return True

        return False

    def step(self, simgr, stash, **kwargs):
        while len(simgr.active) == 1:
            current = simgr.active[0]

            if current.history.recent_block_count > 1:
                # executed unicorn fix bb_cnt
                self._bb_cnt += current.history.recent_block_count - 1 - current.history.recent_syscall_count

            if not self._no_follow:
                # termination condition: we exhausted the dynamic trace log
                if self._bb_cnt >= len(self._trace):
                    return simgr

                # now, we switch through several ways that the dynamic and symbolic traces can interact

                # basic, convenient case: the two traces match
                if current.addr == self._trace[self._bb_cnt]:
                    self._bb_cnt += 1

                # angr will count a syscall as a step, qemu will not. they will sync next step.
                elif current.history.jumpkind.startswith("Ijk_Sys"):
                    pass

                # handle library calls and simprocedures
                elif self.project.is_hooked(current.addr)              \
                  or self.project._simos.is_syscall_addr(current.addr) \
                  or not self._address_in_binary(current.addr):
                    # If dynamic trace is in the PLT stub, update bb_cnt until it's out
                    while self._addr_in_plt(self._trace[self._bb_cnt]):
                        self._bb_cnt += 1

                # handle hooked functions
                # TODO: this branch is totally missed by the test cases
                elif self.project.is_hooked(current.history.addr) \
                 and current.history.addr in self.project._sim_procedures:
                    l.debug("ending hook for %s", self.project.hooked_by(current.history.addr))
                    l.debug("previous addr %#x", current.history.addr)
                    l.debug("bb_cnt %d", self._bb_cnt)
                    # we need step to the return
                    current_addr = current.addr
                    while current_addr != self._trace[self._bb_cnt] and self._bb_cnt < len(self._trace):
                        self._bb_cnt += 1
                    # step 1 more for the normal step that would happen
                    self._bb_cnt += 1
                    l.debug("bb_cnt after the correction %d", self._bb_cnt)
                    if self._bb_cnt >= len(self._trace):
                        return simgr

                else:
                    l.error( "the dynamic trace and the symbolic trace disagreed")

                    l.error("[%s] dynamic [0x%x], symbolic [0x%x]",
                            self.project.filename,
                            self._trace[self._bb_cnt],
                            current.addr)

                    l.error("inputs was %r", self.input)
                    if self.resiliency:
                        l.error("TracerMisfollowError encountered")
                        l.warning("entering no follow mode")
                        self._no_follow = True
                    else:
                        raise AngrTracerError

            # maintain the predecessors list
            self._predecessors.append(current)
            self._predecessors.pop(0)

            # Basic block's max size in angr is greater than the one in Qemu
            # We follow the one in Qemu
            if self._bb_cnt >= len(self._trace):
                bbl_max_bytes = 800
            else:
                y2 = self._trace[self._bb_cnt]
                y1 = self._trace[self._bb_cnt - 1]
                bbl_max_bytes = y2 - y1
                if bbl_max_bytes <= 0:
                    bbl_max_bytes = 800

            # detect back loops (a block jumps back to the middle of itself) that have to be differentiated from the
            # case where max block sizes doesn't match.

            # this might still break for huge basic blocks with back loops, but it seems unlikely.
            try:
                bl = self.project.factory.block(self._trace[self._bb_cnt-1],
                        backup_state=current)
                back_targets = set(bl.vex.constant_jump_targets) & set(bl.instruction_addrs)
                if self._bb_cnt < len(self._trace) and self._trace[self._bb_cnt] in back_targets:
                    target_to_jumpkind = bl.vex.constant_jump_targets_and_jumpkinds
                    if target_to_jumpkind[self._trace[self._bb_cnt]] == "Ijk_Boring":
                        bbl_max_bytes = 800
            except (angr.errors.SimMemoryError, angr.errors.SimEngineError):
                bbl_max_bytes = 800

            # if we're not in crash mode we don't care about the history
            if self._trim_history and not self._crash_mode:
                current.history.trim()

            # drop the missed stash before stepping, since driller needs missed paths later.
            simgr.drop(stash='missed')

            simgr.step(size=bbl_max_bytes)

            if self._crash_type == EXEC_STACK:
                simgr.stash(from_stash='active', to_stash='crashed')
                return simgr

            # if our input was preconstrained we have to keep on the lookout for unsat paths.
            if current.preconstrainer._preconstrain_input:
                simgr.stash(from_stash='unsat', to_stash='active')

            simgr.drop(stash='unsat')

            # check to see if we reached a deadend
            if self._bb_cnt >= len(self._trace) and self._crash_mode:
                # if we're in crash mode, let complete() populate the crashed stash.
                simgr.step()

        # if we stepped to a point where there are no active paths, return the simgr.
        if len(simgr.active) == 0:
            # possibly we want to have different behaviour if we're in crash mode.
            return simgr

        # if we get to this point there's more than one active path
        # if we have to ditch the trace we use satisfiability
        # or if a split occurs in a library routine
        a_paths = simgr.active

        if self._no_follow or all(map(
                lambda p: not self._address_in_binary(p.addr), a_paths
                )):
            simgr.prune(to_stash='missed')
        else:
            l.debug("bb %d / %d", self._bb_cnt, len(self._trace))
            simgr.stash_not_addr(self._trace[self._bb_cnt], to_stash='missed')
        if len(simgr.active) > 1: # rarely we get two active paths
            simgr.prune(to_stash='missed')

        if len(simgr.active) > 1: # might still be two active
            simgr.stash(to_stash='missed', filter_func=lambda x: x.jumpkind == "Ijk_EmWarn")

        # make sure we only have one or zero active paths at this point
        assert len(simgr.active) < 2

        # something weird... maybe we hit a rep instruction?
        # qemu and vex have slightly different behaviors...
        if not simgr.active[0].se.satisfiable():
            l.info("detected small discrepancy between qemu and angr, "
                    "attempting to fix known cases")

            # Have we corrected it?
            corrected = False

            # did our missed branch try to go back to a rep?
            target = simgr.missed[0].addr
            if self.project.arch.name == 'X86' or self.project.arch.name == 'AMD64':

                # does it looks like a rep? rep ret doesn't count!
                if self.project.factory.block(target).bytes.startswith("\xf3") and \
                   not self.project.factory.block(target).bytes.startswith("\xf3\xc3"):

                    l.info("rep discrepency detected, repairing...")
                    # swap the stashes
                    simgr.move('missed', 'chosen')
                    simgr.move('active', 'missed')
                    simgr.move('chosen', 'active')

                    corrected = True

            if not corrected:
                l.warning("Unable to correct discrepancy between qemu and angr.")

        return simgr

    def _syscall(self, state):
        syscall_addr = state.se.eval(state.ip)
        # 0xa000008 is terminate, which we exclude from syscall statistics.
        if syscall_addr != 0xa000008:
            args = angr.SYSCALL_CC['X86']['CGC'](self._p.arch).get_args(state, 4)
            d = {'addr': syscall_addr}
            for i in xrange(4):
                d['arg_%d' % i] = args[i]
                d['arg_%d_symbolic' % i] = args[i].ast.symbolic
            self._syscall.append(d)

    def _check_stack(self, state):
        if state.memory.load(state.ip, state.ip.length).symbolic:
            l.debug("executing input-related code")
            self._crash_type = EXEC_STACK
            self._crash_state = state

    def _address_in_binary(self, addr):
        """
        Determine if address @addr is in the binary being traced.
        :param addr: the address to test

        :return: True if the address is in between the binary's min and max addresses.
        """

        mb = self.project.loader.main_object
        return mb.min_addr <= addr and addr < mb.max_addr

    def _addr_in_plt(self, addr):
        """
        Check if an address is inside the ptt section
        """
        plt = self.project.loader.main_object.sections_map['.plt']
        return addr >= plt.min_addr and addr <= plt.max_addr

    def _crash_windup(self):
        # before we step through and collect the actions we have to set
        # up a special case for address concretization in the case of a
        # controlled read or write vulnerability.
        state = self._predecessors[-1]

        bp1 = state.inspect.b(
            'address_concretization',
            BP_BEFORE,
            action=self._dont_add_constraints)

        bp2 = state.inspect.b(
            'address_concretization',
            BP_AFTER,
            action=self._grab_concretization_results)

        # step to the end of the crashing basic block,
        # to capture its actions with those breakpoints
        state.step()

        # Add the constraints from concretized addrs back
        for var, concrete_vals in state.preconstrainer.address_concretization:
            if len(concrete_vals) > 0:
                l.debug("constraining addr to be %#x", concrete_vals[0])
                state.add_constraints(var == concrete_vals[0])

        # then we step again up to the crashing instruction
        p_block = state.block()

        inst_cnt = len(p_block.instruction_addrs)
        insts = 0 if inst_cnt == 0 else inst_cnt - 1
        succs = state.step(num_inst=insts).flat_successors

        if len(succs) > 0:
            if len(succs) > 1:
                succs = [s for s in succs if s.se.satisfiable()]
            state = succs[0]

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

    @staticmethod
    def _grab_concretization_results(state):
        """
        Grabs the concretized result so we can add the constraint ourselves.
        """

        # only grab ones that match the constrained addrs
        if angr.exploration_techniques.tracer.Tracer._add_constraints(state):
            addr = state.inspect.address_concretization_expr
            result = state.inspect.address_concretization_result
            if result is None:
                l.warning("addr concretization result is None")
                return
            self.address_concretization.append((addr, result))

    @staticmethod
    def _dont_add_constraints(state):
        """
        Obnoxious way to handle this, should ONLY be called from tracer.
        """

        # for each constrained addrs check to see if the variables match,
        # if so keep the constraints
        state.inspect.address_concretization_add_constraints = angr.exploration_techniques.tracer.Tracer._add_constraints(state)

    @staticmethod
    def _add_constraints(state):
        variables = state.inspect.address_concretization_expr.variables
        hit_indices = angr.exploration_techniques.tracer.Tracer._to_indices(variables)

        for action in state.preconstrainer._constrained_addrs:
            var_indices = self._to_indices(action.addr.variables)
            if var_indices == hit_indices:
                return True
        return False

    @staticmethod
    def _to_indices(variables):
        variables = [v for v in variables if v.startswith("file_/dev/stdin")]
        indices = map(lambda y: int(y.split("_")[3], 16), variables)
        return sorted(indices)
