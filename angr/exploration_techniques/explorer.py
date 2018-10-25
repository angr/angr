from . import ExplorationTechnique
from .common import condition_to_lambda
from .. import sim_options
from ..errors import SimIRSBNoDecodeError, AngrExplorationTechniqueError

import logging
l = logging.getLogger("angr.exploration_techniques.explorer")

class Explorer(ExplorationTechnique):
    """
    Search for up to "num_find" paths that satisfy condition "find", avoiding condition "avoid". Stashes found paths into "find_stash' and avoided paths into "avoid_stash".

    The "find" and "avoid" parameters may be any of:

    - An address to find
    - A set or list of addresses to find
    - A function that takes a path and returns whether or not it matches.

    If an angr CFG is passed in as the "cfg" parameter and "find" is either a number or a list or a set, then
    any paths which cannot possibly reach a success state without going through a failure state will be
    preemptively avoided.

    If either the "find" or "avoid" parameter is a function returning a boolean, and a path triggers both conditions, it will be added to the find stash, unless "avoid_priority" is set to True.
    """
    def __init__(self, find=None, avoid=None, find_stash='found', avoid_stash='avoid', cfg=None, num_find=1, avoid_priority=False):
        super(Explorer, self).__init__()
        self.find, static_find = condition_to_lambda(find)
        self.avoid, static_avoid = condition_to_lambda(avoid)
        self.find_stash = find_stash
        self.avoid_stash = avoid_stash
        self.cfg = cfg
        self.ok_blocks = set()
        self.num_find = num_find
        self.avoid_priority = avoid_priority

        # even if avoid or find addresses are not statically known, stop on those that we do know
        self._extra_stop_points = (static_find or set()) | (static_avoid or set())
        self._unknown_stop_points = static_find is None or static_avoid is None
        self._warned_unicorn = False

        # TODO: This is a hack for while CFGFast doesn't handle procedure continuations
        from .. import analyses
        if isinstance(cfg, analyses.CFGFast):
            l.error("CFGFast is currently inappropriate for use with Explorer.")
            l.error("Usage of the CFG has been disabled for this explorer.")
            self.cfg = None

        if self.cfg is not None:
            avoid = static_avoid or set()

            # we need the find addresses to be determined statically
            if not static_find:
                l.error("You must provide at least one 'find' address as a number, set, list, or tuple if you provide a CFG.")
                l.error("Usage of the CFG has been disabled for this explorer.")
                self.cfg = None
                return

            for a in avoid:
                if cfg.get_any_node(a) is None:
                    l.warning("'Avoid' address %#x not present in CFG...", a)

            # not a queue but a stack... it's just a worklist!
            queue = []
            for f in static_find:
                nodes = cfg.get_all_nodes(f)
                if len(nodes) == 0:
                    l.warning("'Find' address %#x not present in CFG...", f)
                else:
                    queue.extend(nodes)

            seen_nodes = set()
            while len(queue) > 0:
                n = queue.pop()
                if id(n) in seen_nodes:
                    continue
                if n.addr in avoid:
                    continue
                self.ok_blocks.add(n.addr)
                seen_nodes.add(id(n))
                queue.extend(n.predecessors)

            if len(self.ok_blocks) == 0:
                l.error("No addresses could be validated by the provided CFG!")
                l.error("Usage of the CFG has been disabled for this explorer.")
                self.cfg = None
                return

            l.warning("Please be sure that the CFG you have passed in is complete.")
            l.warning("Providing an incomplete CFG can cause viable paths to be discarded!")

    def setup(self, simgr):
        if not self.find_stash in simgr.stashes: simgr.stashes[self.find_stash] = []
        if not self.avoid_stash in simgr.stashes: simgr.stashes[self.avoid_stash] = []

    def step(self, simgr, stash='active', **kwargs):
        base_extra_stop_points = set(kwargs.pop("extra_stop_points", []))
        return simgr.step(stash=stash, extra_stop_points=base_extra_stop_points | self._extra_stop_points, **kwargs)

    def _classify(self, addr, findable, avoidable):
        if self.avoid_priority:
            if addr in avoidable:
                return self.avoid_stash
            elif addr in findable:
                return self.find_stash
        else:
            if addr in findable:
                return self.find_stash
            elif addr in avoidable:
                return self.avoid_stash
        return None

    def _classify_all(self, addrs, findable, avoidable):
        if self.avoid_priority:
            for i, addr in enumerate(addrs):
                if addr in avoidable:
                    return i, self.avoid_stash
            for i, addr in enumerate(addrs):
                if addr in findable:
                    return i, self.find_stash
        else:
            for i, addr in enumerate(addrs):
                if addr in findable:
                    return i, self.find_stash
            for i, addr in enumerate(addrs):
                if addr in avoidable:
                    return i, self.avoid_stash
        return None, None

    # make it more natural to deal with the intended dataflow
    def filter(self, simgr, state, **kwargs):
        stash = self._filter_inner(state)
        if stash is None:
            return simgr.filter(state, **kwargs)
        return stash

    def _filter_inner(self, state):
        if self._unknown_stop_points and sim_options.UNICORN in state.options and not self._warned_unicorn:
            l.warning("Using unicorn with find/avoid conditions that are a lambda (not a number, set, tuple or list)")
            l.warning("Unicorn may step over states that match the condition (find or avoid) without stopping.")
            self._warned_unicorn = True

        findable = self.find(state)
        avoidable = self.avoid(state)

        if findable is True:
            return self.find_stash
        if avoidable is True:
            return self.avoid_stash

        if not findable and not avoidable:
            if self.cfg is not None and self.cfg.get_any_node(state.addr) is not None:
                if state.addr not in self.ok_blocks:
                    return self.avoid_stash
            return None

        if type(findable) is not set:
            findable = set()
        if type(avoidable) is not set:
            avoidable = set()

        stash = self._classify(state.addr, findable, avoidable)
        if stash is not None:
            return stash

        # at this point the state is definitely either findable or avoidable... but not at the current address.
        # SOME people are apparently just too good to always specify basic block addresses and deal with the fact
        # that angr's understanding of basic blocks isn't the one that most program analysts use. </sarcasm>

        # refuse to try to work with unsatisfiable states
        if not state.history.reachable:
            return 'unsat'

        current_block = state.block()
        target_addr = min(findable | avoidable)
        target_instruction_idx = current_block.instruction_addrs.index(target_addr)
        if target_instruction_idx <= 0:
            raise AngrExplorationTechniqueError("Something went very wrong during explorer windup: idx <= 0")

        try:
            useful_block = state.block(num_inst=target_instruction_idx)
        except SimIRSBNoDecodeError as ex:
            if state.arch.name.startswith("MIPS") and target_instruction_idx == current_block.instructions - 1:
                l.warning("You specified a MIPS delay slot as a find-avoid target. We can't deal with that.")
                l.warning("Returning the state at the associated jump instruction.")
                if target_instruction_idx == 1:
                    stash = self._classify(current_block.instruction_addrs[1], findable, avoidable)
                    if stash is None:
                        raise AngrExplorationTechniqueError(
                            "Something went very wrong during explorer windup: stash is None (mips edge case)")
                    return stash

                useful_block = state.block(num_inst=target_instruction_idx - 1)
            else:
                raise ex

        succ = state.step(irsb=useful_block.vex)
        if not succ.flat_successors:
            l.warning("Something weird happened during explorer windup: windup step produced no successors")
            return None
        if len(succ.flat_successors) > 1:
            idx, stash = self._classify_all([s.addr for s in succ.flat_successors], findable, avoidable)
            if stash is not None:
                # FIXME this is a nasty limitation in the exploration technique architecture
                # should we make it so that filter can return multiple states?
                l.warning("State split during explorer windup, but one of the split states was found/avoided.")
                l.warning("This may lead to a loss of coverage.")
                l.warning("Set project.engines.vex.default_strict_block_end = True if you believe this is an issue.")
                return stash, succ.flat_successors[idx]
            return None

        stash = self._classify(succ.flat_successors[0].addr, findable, avoidable)
        if stash is None:
            l.warning("Explorer entered windup but did not produce a found/avoided state")
        return stash, succ.flat_successors[0]

    def complete(self, simgr):
        return len(simgr.stashes[self.find_stash]) >= self.num_find
