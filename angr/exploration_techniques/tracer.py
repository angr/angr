from typing import List, Dict, TYPE_CHECKING
import logging
import cle

from capstone import CS_GRP_CALL, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET

from . import ExplorationTechnique
from .. import BP_BEFORE, BP_AFTER, sim_options
from ..errors import AngrTracerError, SimIRSBNoDecodeError

if TYPE_CHECKING:
    from angr.sim_state import SimState


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

    Strict = "strict"
    Permissive = "permissive"
    CatchDesync = "catch_desync"


class TracerDesyncError(AngrTracerError):
    """
    An error class to report tracing Tracing desyncronization error
    """

    def __init__(self, msg, deviating_addr=None, deviating_trace_idx=None):
        super().__init__(msg)
        self.deviating_addr = deviating_addr
        self.deviating_trace_idx = deviating_trace_idx


class RepHook:
    """
    Hook rep movs/stos to speed up constraint solving
    TODO: This should be made an exploration technique later
    """

    def __init__(self, mnemonic):
        self.mnemonic = mnemonic

    @staticmethod
    def _inline_call(state, procedure, *arguments, **kwargs):
        e_args = [state.solver.BVV(a, state.arch.bits) if isinstance(a, int) else a for a in arguments]
        p = procedure(project=state.project, **kwargs)
        return p.execute(state, None, arguments=e_args)

    def run(self, state):
        from .. import SIM_PROCEDURES  # pylint: disable=import-outside-toplevel

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

            memset = SIM_PROCEDURES["libc"]["memset"]
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

            memcpy = SIM_PROCEDURES["libc"]["memcpy"]
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
            raise NotImplementedError("Unsupported mnemonic %s" % self.mnemonic)


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
    :param syscall_data:        Data related to various syscalls recorded by tracer for replaying
    :param copy_states:         Whether COPY_STATES should be enabled for the tracing state. It is
                                off by default because most tracing workloads benefit greatly from
                                not performing copying. You want to enable it if you want to see
                                the missed states. It will be re-added for the last 2% of the trace
                                in order to set the predecessors list correctly. If you turn this
                                on you may want to enable the LAZY_SOLVES option.
    :param mode:                Tracing mode.
    :param aslr:                Whether there are aslr slides. if not, tracer uses trace address
                                as state address.
    :param follow_unsat:        Whether unsatisfiable states should be treated as potential
                                successors or not.

    :ivar predecessors:         A list of states in the history before the final state.
    """

    def __init__(
        self,
        trace=None,
        resiliency=False,
        keep_predecessors=1,
        crash_addr=None,
        syscall_data=None,
        copy_states=False,
        fast_forward_to_entry=True,
        mode=TracingMode.Strict,
        aslr=True,
        follow_unsat=False,
    ):
        super().__init__()
        self._trace = trace
        self._resiliency = resiliency
        self._crash_addr = crash_addr
        self._syscall_data = syscall_data
        self._copy_states = copy_states
        self._mode = mode
        self._aslr = aslr
        self._follow_unsat = follow_unsat
        self._fast_forward_to_entry = fast_forward_to_entry

        self._aslr_slides: Dict[cle.Backend, int] = {}
        self._current_slide = None

        self._fd_bytes = None

        # keep track of the last basic block we hit
        self.predecessors: List["SimState"] = [None] * keep_predecessors
        self.last_state = None

        # whether we should follow the trace
        self._no_follow = self._trace is None

        # Keep track of count of termination point
        self._last_block_total_count = self._trace.count(self._trace[-1])
        self._last_block_seen_count = 0

        # sanity check: copy_states must be enabled in Permissive mode since we may need to backtrack from a previous
        # state.
        if self._mode == TracingMode.Permissive and not self._copy_states:
            raise ValueError('"copy_states" must be True when tracing in permissive mode.')

    def _locate_entry_point(self, angr_addr):
        # ...via heuristics
        indices = set()
        threshold = 0x40000
        while not indices and threshold > 0x2000:
            for idx, addr in enumerate(self._trace):
                if ((addr - angr_addr) & 0xFFF) == 0 and (idx == 0 or abs(self._trace[idx - 1] - addr) > threshold):
                    indices.add(idx)

            indices = {i for i in indices if self._filter_idx(angr_addr, i)}
            threshold //= 2

        return indices

    def _identify_aslr_slides(self):
        """
        libraries can be mapped differently in the original run(in the trace) and in angr
        this function identifies the difference(called aslr slides) of each library to help angr translate
        original address and address in angr back and forth
        """
        if self._aslr:
            # if we don't know whether there is any slide, we need to identify the slides via heuristics
            for obj in self.project.loader.all_objects:
                # do not analyze pseudo-objects
                if obj.binary_basename.startswith("cle##"):
                    continue

                # heuristic 1: non-PIC  objects are loaded without aslr slides
                if not obj.pic:
                    self._aslr_slides[obj] = 0
                    continue

                # heuristic 2: library objects with custom_base_addr are loaded at the correct locations
                if obj._custom_base_addr:
                    l.info("%s is assumed to be loaded at the address matching the one in the trace", obj)
                    self._aslr_slides[obj] = 0
                    continue

                # heuristic 3: entry point of an object should appear in the trace
                possibilities = None
                for entry in obj.initializers + ([obj.entry] if obj.is_main_bin else []):
                    indices = self._locate_entry_point(entry)
                    slides = {self._trace[idx] - entry for idx in indices}
                    if possibilities is None:
                        possibilities = slides
                    else:
                        possibilities.intersection_update(slides)

                if possibilities is None:
                    continue

                if len(possibilities) == 0:
                    raise AngrTracerError(
                        "Trace does not seem to contain object initializers for %s. "
                        "Do you want to have a Tracer(aslr=False)?" % obj
                    )
                if len(possibilities) == 1:
                    self._aslr_slides[obj] = next(iter(possibilities))
                else:
                    raise AngrTracerError(
                        "Trace seems ambiguous with respect to what the ASLR slides are for %s. "
                        "This is surmountable, please open an issue." % obj
                    )
        else:
            # if we know there is no slides, just trust the address in the loader
            for obj in self.project.loader.all_objects:
                # do not analyze pseudo-objects
                if obj.binary_basename.startswith("cle##"):
                    continue
                self._aslr_slides[obj] = 0
            self._current_slide = 0

    def _filter_idx(self, angr_addr, idx):
        slide = self._trace[idx] - angr_addr
        block = self.project.factory.block(angr_addr)
        legal_next = block.vex.constant_jump_targets
        if legal_next:
            return any(a + slide == self._trace[idx + 1] for a in legal_next)
        else:
            # the intuition is that if the first block of an initializer does an indirect jump,
            # it's probably a call out to another binary (notably __libc_start_main)
            # this is an awful fucking heuristic but it's as good as we've got
            return abs(self._trace[idx] - self._trace[idx + 1]) > 0x1000

    def set_fd_data(self, fd_data: Dict[int, bytes]):
        """
        Set concrete bytes of various fds read by the program
        """

        self._fd_bytes = fd_data

    def setup(self, simgr):
        simgr.populate("missed", [])
        simgr.populate("traced", [])
        simgr.populate("crashed", [])
        simgr.populate("desync", [])

        if len(simgr.active) != 1:
            raise AngrTracerError("Tracer is being invoked on a SimulationManager without exactly one active state")

        self._identify_aslr_slides()

        if self._fast_forward_to_entry:
            idx = self._trace.index(self._translate_state_addr(self.project.entry))
            # step to entry point
            while simgr.one_active.addr != self.project.entry:
                simgr.step(extra_stop_points={self.project.entry})
                if len(simgr.active) == 0:
                    raise AngrTracerError("Could not step to the first address of the trace - simgr is empty")
                if len(simgr.active) > 1:
                    raise AngrTracerError(
                        "Could not step to the first address of the trace - state split. "
                        "Do you want to have a Tracer(fast_forward_to_entry=False)?"
                    )
                simgr.drop(stash="unsat")
        else:
            idx = 0

        # initialize the state info
        simgr.one_active.globals["trace_idx"] = idx
        simgr.one_active.globals["sync_idx"] = None
        simgr.one_active.globals["sync_timer"] = 0
        simgr.one_active.globals["is_desync"] = False

        # disable state copying!
        if not self._copy_states:
            # insulate our caller from this nonsense by making a single copy at the beginning
            simgr.active[0] = simgr.active[0].copy()
            simgr.active[0].options.remove(sim_options.COPY_STATES)

    def complete(self, simgr):
        return bool(simgr.traced)

    def filter(self, simgr, state, **kwargs):
        # check completion
        if state.globals["trace_idx"] >= len(self._trace) - 1:
            # if the the state is a desync state and the user wants to keep it,
            # then do what the user wants
            if self._mode == TracingMode.CatchDesync and self.project.is_hooked(state.addr):
                return "desync"
            # do crash windup if necessary
            if self._crash_addr is not None:
                self.last_state, crash_state = self.crash_windup(state, self._crash_addr)
                simgr.populate("crashed", [crash_state])
                self.predecessors.append(state)
                self.predecessors.pop(0)

            return "traced"

        return simgr.filter(state, **kwargs)

    def step(self, simgr, stash="active", **kwargs):
        simgr.drop(stash="missed")
        return simgr.step(stash=stash, syscall_data=self._syscall_data, fd_bytes=self._fd_bytes, **kwargs)

    def step_state(self, simgr, state, **kwargs):
        if state.history.jumpkind == "Ijk_Exit":
            return {"traced": [state]}

        # maintain the predecessors list
        self.predecessors.append(state)
        self.predecessors.pop(0)

        if state.globals["trace_idx"] > len(self._trace) * 0.98:
            state.options.add(sim_options.COPY_STATES)
            state.options.add(sim_options.LAZY_SOLVES)

        # optimization:
        # look forward, is it a rep stos/movs instruction?
        # if so, we add a temporary hook to speed up constraint solving
        if not self.project.is_hooked(state.addr):
            block = self.project.factory.block(state.addr)

            if len(block.capstone.insns) == 1 and (
                block.capstone.insns[0].mnemonic.startswith("rep m")
                or block.capstone.insns[0].mnemonic.startswith("rep s")
            ):
                insn = block.capstone.insns[0]
                self.project.hook(state.addr, RepHook(insn.mnemonic.split(" ")[1]).run, length=insn.size)

        # perform the step. ask qemu to stop at the termination point.
        # if termination point occurs multiple times in trace, pass details to SimEngineUnicorn's native interface so
        # that it can stop at last block
        if self._last_block_total_count > 1:
            stops = set(kwargs.pop("extra_stop_points", ()))
            last_block_details = {
                "addr": self._trace[-1],
                "tot_count": self._last_block_total_count,
                "curr_count": self._last_block_seen_count,
            }
        else:
            stops = set(kwargs.pop("extra_stop_points", ())) | {self._trace[-1]}
            last_block_details = None

        succs_dict = simgr.step_state(state, extra_stop_points=stops, last_block_details=last_block_details, **kwargs)
        if None not in succs_dict and simgr.errored:
            raise simgr.errored[-1].error
        sat_succs = succs_dict[None]  # satisfiable states
        succs = sat_succs + succs_dict["unsat"]  # both satisfiable and unsatisfiable states

        if not self._follow_unsat:
            # Only satisfiable states need to be checked for correct successor
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
                succs_dict["missed"] = [s for s in sat_succs if s is not succ]
        else:
            # Check all states for correct successor
            if len(succs) == 1:
                self._update_state_tracking(succs[0])
            elif len(succs) == 0:
                raise Exception("All states disappeared!")
            else:
                succ = self._pick_correct_successor(succs)
                succs_dict[None] = [succ]
                succs_dict["missed"] = [s for s in succs if s is not succ]
        assert len(succs_dict[None]) == 1

        # if there is a catchable desync, we should return the last sync state
        if succs_dict[None][0].globals["is_desync"]:
            simgr.active[0].globals["trace_idx"] = len(self._trace)
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
        trace_idx = state.globals["trace_idx"]
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
        l.info(
            "Attempt to fix a deviation: Forcing execution from %#x to %#x (instead of %#x).",
            state.addr,
            succ.addr,
            translated_addr,
        )
        succ._ip = translated_addr

        succ.globals["trace_idx"] = trace_idx + 1
        succs_dict = {None: [succ]}

        if unicorn_option_removed:
            succ.options.add(sim_options.UNICORN)

        return succs_dict

    def _pick_correct_successor(self, succs):
        # there's been a branch of some sort. Try to identify which state stayed on the trace.
        assert len(succs) > 0
        idx = succs[0].globals["trace_idx"]

        res = []
        last_description = succs[0].history.descriptions[-1]
        if "Unicorn" in last_description:
            # Multiple new states were created in SimEngineUnicorn. State which has non-zero recent block count is a
            # valid successor since only correct successor is sync'd with native state
            for succ in succs:
                if succ.history.recent_block_count > 0:
                    res.append(succ)
        else:
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

    def _update_state_tracking(self, state: "SimState"):
        idx = state.globals["trace_idx"]
        sync = state.globals["sync_idx"]
        timer = state.globals["sync_timer"]

        self._last_block_seen_count += state.history.recent_bbl_addrs.count(self._trace[-1])

        if state.history.recent_block_count > 1:
            # multiple blocks were executed this step. they should follow the trace *perfectly*
            # or else something is up
            # "something else" so far only includes concrete transmits, or...
            # TODO: https://github.com/unicorn-engine/unicorn/issues/874
            # ^ this means we will see desyncs of the form unicorn suddenly skips a bunch of qemu blocks
            assert state.history.recent_block_count == len(state.history.recent_bbl_addrs)

            for addr_idx, addr in enumerate(state.history.recent_bbl_addrs):
                if addr in [
                    state.unicorn.cgc_transmit_addr,
                    state.unicorn.cgc_receive_addr,
                    state.unicorn.cgc_random_addr,
                ]:
                    continue

                if sync is not None and sync != "entry":
                    if self._compare_addr(self._trace[sync], addr):
                        # Found the address in trace. Start normal trace checks from next address
                        idx = sync + 1
                        state.globals["sync_idx"] = None
                        sync = None

                    continue

                if self._compare_addr(self._trace[idx], addr) or self._check_qemu_unicorn_large_block_split(
                    state, idx, addr_idx
                ):
                    idx += 1
                else:
                    is_contained, increment = self._check_qemu_block_in_unicorn_block(state, idx, addr_idx)
                    if is_contained:
                        idx += increment
                        # Big block is now skipped in qemu trace. Perform compare at correct index again.
                        if self._compare_addr(self._trace[idx], addr):
                            idx += 1
                            continue

                    raise TracerDesyncError(
                        "Oops! angr did not follow the trace", deviating_addr=addr, deviating_trace_idx=idx
                    )

            idx -= 1  # use normal code to do the last synchronization

        if sync == "entry":
            trace_addr = self._translate_state_addr(state.addr)
            # this address should only ever appear once in the trace. we verified this during setup.
            idx = self._trace.index(trace_addr)
            state.globals["trace_idx"] = idx
            state.globals["sync_idx"] = None
        elif sync is not None:
            timer -= 1
            if self._compare_addr(self._trace[sync], state.addr):
                state.globals["trace_idx"] = sync
                state.globals["sync_idx"] = None
                state.globals["sync_timer"] = 0
            elif timer > 0:
                state.globals["sync_timer"] = timer
            else:
                raise Exception(
                    "Trace failed to synchronize! We expected it to hit %#x (trace addr), "
                    "but it failed to do this within a timeout" % self._trace[sync]
                )

        elif state.history.jumpkind.startswith("Ijk_Exit"):
            # termination! will be handled by filter
            pass
        elif self.project.is_hooked(state.addr) and not self.project.loader.extern_object.contains_addr(state.addr):
            # handle simprocedures
            self._sync_return(state, idx)
        elif self._compare_addr(self._trace[idx + 1], state.addr):
            # normal case
            state.globals["trace_idx"] = idx + 1
        elif self.project.loader._extern_object is not None and self.project.loader.extern_object.contains_addr(
            state.addr
        ):
            # externs
            proc = self.project.hooked_by(state.addr)
            if proc is None:
                raise Exception("Extremely bad news: we're executing an unhooked address in the externs space")
            if proc.display_name == "LinuxLoader":
                state.globals["sync_idx"] = "entry"
            elif proc.is_continuation:
                orig_addr = self.project.loader.find_symbol(proc.display_name).rebased_addr
                obj = self.project.loader.find_object_containing(orig_addr)
                orig_trace_addr = self._translate_state_addr(orig_addr, obj)
                if 0 <= self._trace[idx + 1] - orig_trace_addr <= 0x10000:
                    # this is fine. we do nothing and then next round
                    # it'll get handled by the is_hooked(state.history.addr) case
                    pass
                else:
                    # this may also be triggered as a consequence of the unicorn issue linked above
                    raise Exception("BUG: State is returning to a continuation that isn't its own???")
            elif state.addr == getattr(self.project.simos, "vsyscall_addr", None):
                if not self._sync_callsite(state, idx, state.history.addr):
                    raise AngrTracerError("Could not synchronize following vsyscall")
            elif self.project.hooked_by(state.addr).display_name.startswith("IFuncResolver"):
                if not self._sync_return(state, idx):
                    raise AngrTracerError("Could not synchronize at ifunc return address")
            else:
                # see above
                pass
        elif state.history.jumpkind.startswith("Ijk_Sys"):
            # syscalls
            state.globals["sync_idx"] = idx + 1
            state.globals["sync_timer"] = 1
        elif self.project.is_hooked(state.history.addr):
            # simprocedures - is this safe..?
            self._fast_forward(state)
        elif state.addr == self._trace[-1]:
            # we may have prematurely stopped because of setting stop points. try to resync.
            state.globals["sync_idx"] = idx + 1
            state.globals["sync_timer"] = 1
        elif (
            self.project.is_hooked(state.addr)
            and self.project.loader.find_symbol(self.project.hooked_by(state.addr).display_name) is not None
            and self.project.loader.find_symbol(self.project.hooked_by(state.addr).display_name).subtype.value[0] == 10
        ):  # STT_GNU_IFUNC #pylint:disable=line-too-long
            if not self._sync_return(state, idx):
                raise AngrTracerError("Could not synchronize at ifunc return address")
        elif self._analyze_misfollow(state, idx):
            # misfollow analysis will set a sync point somewhere if it succeeds
            pass
        else:
            raise TracerDesyncError(
                "Oops! angr did not follow the trace", deviating_addr=state.addr, deviating_trace_idx=idx + 1
            )

        if state.globals["sync_idx"] is not None:
            l.debug(
                "Trace: %s-%s/%s synchronizing %s",
                state.globals["trace_idx"],
                state.globals["sync_idx"],
                len(self._trace),
                state.globals["sync_timer"],
            )
        else:
            l.debug("Trace: %s/%s", state.globals["trace_idx"], len(self._trace))

    def _translate_state_addr(self, state_addr, obj=None):
        if obj is None:
            obj = self.project.loader.find_object_containing(state_addr)
        if obj not in self._aslr_slides:
            raise Exception("Internal error: cannot translate address")
        return state_addr + self._aslr_slides[obj]

    def _translate_trace_addr(self, trace_addr, obj=None):
        if obj is None:
            for obj, slide in self._aslr_slides.items():  # pylint: disable=redefined-argument-from-local
                if obj.contains_addr(trace_addr - slide):
                    break
            else:
                raise Exception("Can't figure out which object this address belongs to")
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
        elif ((trace_addr - state_addr) & 0xFFF) == 0:
            self._aslr_slides[current_bin] = self._current_slide = trace_addr - state_addr
            return True
        # error handling
        elif current_bin:
            raise AngrTracerError(
                "Trace desynced on jumping into %s. "
                "Did you load the right version of this library?" % current_bin.provides
            )
        else:
            raise AngrTracerError("Trace desynced on jumping into %#x, where no library is mapped!" % state_addr)

    def _check_qemu_block_in_unicorn_block(self, state: "SimState", trace_curr_idx, state_desync_block_idx):
        """
        Check if desync occurred because unicorn block was split into multiple blocks in qemu tracer. If yes, find the
        correct increment for trace index
        """

        # We first find the block address where the trace and state's history match
        for trace_match_idx in range(trace_curr_idx - 1, -1, -1):
            if self._trace[trace_match_idx] == state.history.recent_bbl_addrs[state_desync_block_idx - 1]:
                break
        else:
            # Failed to find matching block address. qemu block is probably not contained in a previous block.
            return (False, -1)

        control_flow_insn_types = [CS_GRP_CALL, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET]
        big_block_start = self._trace[trace_match_idx]
        big_block_end = None
        curr_block_addr = big_block_start
        while True:
            curr_block = state.project.factory.block(self._translate_trace_addr(curr_block_addr))
            curr_block_last_insn = curr_block.capstone.insns[-1]
            if any(curr_block_last_insn.group(insn_type) for insn_type in control_flow_insn_types):
                # Found last block
                big_block_end = curr_block.addr + curr_block.size - 1
                break

            curr_block_addr = curr_block.addr + curr_block.size

        for last_contain_index in range(trace_match_idx + 1, trace_curr_idx + 1):
            if self._trace[last_contain_index] <= big_block_start or self._trace[last_contain_index] > big_block_end:
                # This qemu block is not contained in the bigger block
                return (False, -1)

        # Check for future blocks in trace contained in big block
        for next_contain_index in range(trace_curr_idx + 1, len(self._trace)):
            if self._trace[next_contain_index] < big_block_start or self._trace[next_contain_index] > big_block_end:
                # This qemu block is not contained in bigger block
                break

        return (True, next_contain_index - trace_curr_idx)

    def _check_qemu_unicorn_large_block_split(self, state: "SimState", trace_curr_idx, state_desync_block_idx):
        """
        Check if desync occurred because large blocks are split up at different instructions by qemu and unicorn. This
        is done by reconstructing part of block executed so far from the trace and state history and checking if they
        the same
        """

        control_flow_insn_types = [CS_GRP_CALL, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET]

        prev_trace_block = state.project.factory.block(self._translate_trace_addr(self._trace[trace_curr_idx - 1]))
        for insn_type in control_flow_insn_types:
            if prev_trace_block.capstone.insns[-1].group(insn_type):
                # Previous block ends in a control flow instruction. It is not large block different split.
                return False

        # The previous block did not end in a control flow instruction. Let's find the start of this big block from
        # trace: it'll be the first block executed after a control flow instruction.
        big_block_start_addr = None
        for trace_block_idx in range(trace_curr_idx - 2, -1, -1):
            trace_block = state.project.factory.block(self._translate_trace_addr(self._trace[trace_block_idx]))
            trace_block_last_insn = trace_block.capstone.insns[-1]
            for insn_type in control_flow_insn_types:
                if trace_block_last_insn.group(insn_type):
                    big_block_start_addr = self._translate_trace_addr(self._trace[trace_block_idx + 1])
                    break

            if big_block_start_addr is not None:
                break
        else:
            # Failed to find end of the big basic block in trace. Treat as trace desync.
            return False

        # Now we check the part of the state history corresponding to this big basic block to ensure there are no
        # control flow instructions at end of any blocks in the part. This check moves backwards starting from the
        # desyncing block to the start of the big block we found earlier
        for state_history_block_addr in reversed(state.history.recent_bbl_addrs[:state_desync_block_idx]):
            state_history_block = state.project.factory.block(state_history_block_addr)
            state_history_block_last_insn = state_history_block.capstone.insns[-1]
            for insn_type in control_flow_insn_types:
                if state_history_block_last_insn.group(insn_type):
                    # We haven't found the start of big block according to the trace but found a block ending with a
                    # control flow instruction. It is a trace desync then.
                    return False

            if state_history_block_addr == big_block_start_addr:
                # We found start of the big block and no control flow statements in between that and the block where
                # desync happend.
                break

        # Let's find the address of the last byte of the big basic block using VEX lifter
        angr_big_block_end_addr = None
        curr_block_addr = big_block_start_addr
        while True:
            curr_block = state.project.factory.block(self._translate_trace_addr(curr_block_addr))
            curr_block_last_insn = curr_block.capstone.insns[-1]
            if any(curr_block_last_insn.group(insn_type) for insn_type in control_flow_insn_types):
                # Found last block
                angr_big_block_end_addr = curr_block.addr + curr_block.size - 1
                break

            curr_block_addr = curr_block.addr + curr_block.size

        # Let's find the address of the last bytes of the big basic block from the trace
        big_block_end_addr = None
        for trace_block_idx in range(trace_curr_idx, len(self._trace)):
            trace_block = state.project.factory.block(self._translate_trace_addr(self._trace[trace_block_idx]))
            trace_block_last_insn = trace_block.capstone.insns[-1]
            for insn_type in control_flow_insn_types:
                if trace_block_last_insn.group(insn_type):
                    # Found first block in trace ending in a control flow instruction. Verify it matches the end of big
                    # block according to VEX lifter
                    big_block_end_addr = trace_block.addr + trace_block.size - 1
                    if angr_big_block_end_addr != big_block_end_addr:
                        # End does not match. Treat as trace desync.
                        return False
                    else:
                        break

            if big_block_end_addr is not None:
                break
        else:
            # Failed to find end of the big basic block in trace. Treat as trace desync.
            return False

        # At this point, we know the following:
        # - There is no control flow instruction between big_block_start_addr and big_block_end_addr
        # - There is no control flow instruction between big_block_start_addr and state_desync_block_addr
        # - state_desync_block_addr is definitely executed after big_block_start_addr
        # So it's enough to check if desyncing block's address is less than big_block_end_addr to ensure that it
        # is part of the big block
        return state.history.recent_bbl_addrs[state_desync_block_idx] < big_block_end_addr

    def _analyze_misfollow(self, state, idx):
        angr_addr = state.addr
        obj = self.project.loader.find_object_containing(angr_addr)
        if obj not in self._aslr_slides:  # this SHOULD be an invariant given the way _compare_addrs works
            raise Exception("BUG: misfollow analysis initiated when jumping into a new object")

        slide = self._aslr_slides[obj]
        trace_addr = self._trace[idx + 1] - slide
        l.info("Misfollow: angr says %#x, trace says %#x", angr_addr, trace_addr)
        if not obj.contains_addr(trace_addr):
            l.error("Translated trace address lives in a different object from the angr trace")
            return False

        # TODO: add rep handling

        if "IRSB" in state.history.recent_description:
            VEXMaxInsnsPerBlock = 99
            last_block = state.block(state.history.bbl_addrs[-1])

            # Case 1: angr block contains more instructions than trace block
            if self._trace[idx + 1] - slide in last_block.instruction_addrs:
                # we have disparate block sizes!
                # specifically, the angr block size is larger than the trace's.
                # allow the trace to catch up.

                while self._trace[idx + 1] - slide in last_block.instruction_addrs:
                    idx += 1

                l.info("...resolved: disparate block sizes")

                if self._trace[idx + 1] - slide == state.addr:
                    state.globals["trace_idx"] = idx + 1
                    return True
                else:
                    state.globals["trace_idx"] = idx
                    # state.globals['trace_desync'] = True
                    return True

            # Case 2: trace block contains more instructions than angr
            # block.  Caused by VEX's maximum instruction limit of 99
            # instructions
            elif (
                state.project.factory.block(state.history.addr).instructions == VEXMaxInsnsPerBlock
                and state.history.jumpkind == "Ijk_Boring"
            ):
                l.info("...resolved: vex block limit")
                return True

        prev_addr = state.history.bbl_addrs[-1]
        prev_obj = self.project.loader.find_object_containing(prev_addr)

        if state.block(prev_addr).vex.jumpkind == "Ijk_Call":
            l.info("...syncing at callsite")
            return self._sync_callsite(state, idx, prev_addr)

        if prev_addr in getattr(prev_obj, "reverse_plt", ()):
            prev_name = prev_obj.reverse_plt[prev_addr]
            l.info("...syncing at PLT callsite for %s", prev_name)
            # TODO: this method is newer than sync_callsite. should it be used always?
            return self._sync_return(state, idx, assert_obj=prev_obj)

        if prev_obj is not None:
            prev_section = prev_obj.find_section_containing(prev_addr)
            if prev_section is not None:
                if prev_section.name in (".plt",):
                    l.info("...syncing at PLT callsite (type 2)")
                    return self._sync_return(state, idx, assert_obj=prev_obj)

        l.info("...all analyses failed.")
        return False

    def _sync_callsite(self, state, idx, callsite_addr):
        retsite_addr = state.block(callsite_addr).size + callsite_addr
        return self._sync(state, idx, retsite_addr)

    def _sync_return(self, state, idx, assert_obj=None):
        ret_addr_bv = self.project.factory.cc().return_addr.get_value(state)
        if state.solver.symbolic(ret_addr_bv):
            l.info("...symbolic return address. I refuse to deal with this.")
            return False

        ret_addr = state.solver.eval(ret_addr_bv)
        if assert_obj is not None and not assert_obj.contains_addr(ret_addr):
            l.info("...address is not in the correct object, aborting analysis")
            return False
        return self._sync(state, idx, ret_addr)

    def _sync(self, state, idx, addr):
        addr_translated = self._translate_state_addr(addr)
        try:
            sync_idx = self._trace.index(addr_translated, idx)
        except ValueError:
            l.error("Trying to synchronize at %#x (%#x) but it does not appear in the trace?", addr_translated, addr)
            return False

        state.globals["sync_idx"] = sync_idx
        state.globals["trace_idx"] = idx
        state.globals["sync_timer"] = 10000  # TODO: ???
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
            target_idx = self._trace.index(target_addr, state.globals["trace_idx"])
        except ValueError as e:
            # if the user wants to catch desync caused by sim_procedure,
            # mark this state as a desync state and then end the tracing prematurely
            if self._mode == TracingMode.CatchDesync:
                state.globals["is_desync"] = True
                return
            raise AngrTracerError(
                "Trace failed to synchronize during fast forward? You might want to unhook %s."
                % (self.project.hooked_by(state.history.addr).display_name)
            ) from e
        else:
            state.globals["trace_idx"] = target_idx

    @classmethod
    def crash_windup(cls, state, crash_addr):
        # first check: are we just executing user-controlled code?
        if not state.ip.symbolic and state.mem[state.ip].char.resolved.symbolic:
            l.debug("executing input-related code")
            return state, state
        # second check: is this code mapped and executable?
        section = state.project.loader.find_section_containing(state.addr)
        if not section or not (section.flags & 0x4):  # pylint:disable=superfluous-parens
            return state, state
        # in case we can't unwind, we return the state itself
        if state.addr == crash_addr:
            return state, state

        state = state.copy()
        state.options.add(sim_options.COPY_STATES)
        state.options.discard(sim_options.STRICT_PAGE_ACCESS)

        # before we step through and collect the actions we have to set
        # up a special case for address concretization in the case of a
        # controlled read or write vulnerability.
        bp1 = state.inspect.b("address_concretization", BP_BEFORE, action=cls._check_add_constraints)

        bp2 = state.inspect.b("address_concretization", BP_AFTER, action=cls._grab_concretization_results)

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
            insts = inst_addrs.index(crash_addr)
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

        l.debug("final step...")
        try:
            succs = state.step(num_inst=1)
        except SimIRSBNoDecodeError:
            # See https://github.com/angr/angr/issues/71
            # Basically, we probably tried to single step over a delay slot.
            succs = state.step(num_inst=2)

        successors = succs.flat_successors + succs.unconstrained_successors
        crash_state = successors[0]

        # now remove our breakpoints since other people might not want them
        for s in [last_state, crash_state]:
            if s is None:
                continue
            s.inspect.remove_breakpoint("address_concretization", bp1)
            s.inspect.remove_breakpoint("address_concretization", bp2)

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
            if descr[0] == "file" and descr[1] == state.posix.stdin.ident:
                if descr[2] == "packet":
                    indices.append(descr[3])
                elif type(descr[2]) is int:
                    indices.append(descr[2])

        return sorted(indices)
