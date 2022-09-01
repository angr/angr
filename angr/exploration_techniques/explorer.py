import logging
import claripy

from . import ExplorationTechnique
from .common import condition_to_lambda
from .. import sim_options
from ..state_plugins.sim_event import resource_event

l = logging.getLogger(name=__name__)

class Explorer(ExplorationTechnique):
    """
    Search for up to "num_find" paths that satisfy condition "find", avoiding condition "avoid". Stashes found paths
    into "find_stash' and avoided paths into "avoid_stash".

    The "find" and "avoid" parameters may be any of:

    - An address to find
    - A set or list of addresses to find
    - A function that takes a path and returns whether or not it matches.

    If an angr CFG is passed in as the "cfg" parameter and "find" is either a number or a list or a set, then
    any paths which cannot possibly reach a success state without going through a failure state will be
    preemptively avoided.

    If either the "find" or "avoid" parameter is a function returning a boolean, and a path triggers both conditions,
    it will be added to the find stash, unless "avoid_priority" is set to True.
    """
    def __init__(
            self,
            find=None,
            avoid=None,
            find_stash='found',
            avoid_stash='avoid',
            cfg=None,
            num_find=1,
            avoid_priority=False
    ):
        super().__init__()
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
        from .. import analyses  # pylint: disable=import-outside-toplevel
        if isinstance(cfg, analyses.CFGFast):
            l.error("CFGFast is currently inappropriate for use with Explorer.")
            l.error("Usage of the CFG has been disabled for this explorer.")
            self.cfg = None

        if self.cfg is not None:
            avoid = static_avoid or set()

            # we need the find addresses to be determined statically
            if not static_find:
                l.error("You must provide at least one numeric 'find' address if you provide a CFG.")
                l.error("Usage of the CFG has been disabled for this explorer.")
                self.cfg = None
                return

            for a in avoid:
                if cfg.model.get_any_node(a) is None:
                    l.warning("'Avoid' address %#x not present in CFG...", a)

            # not a queue but a stack... it's just a worklist!
            queue = []
            for f in static_find:
                nodes = cfg.model.get_all_nodes(f)
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
        if not self.find_stash in simgr.stashes:
            simgr.stashes[self.find_stash] = []
        if not self.avoid_stash in simgr.stashes:
            simgr.stashes[self.avoid_stash] = []

    def step(self, simgr, stash='active', **kwargs):
        base_extra_stop_points = set(kwargs.pop("extra_stop_points", []))
        return simgr.step(stash=stash, extra_stop_points=base_extra_stop_points | self._extra_stop_points, **kwargs)

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

        try:
            if self.avoid_priority:
                avoidable = self.avoid(state)
                if avoidable and (avoidable is True or state.addr in avoidable):
                    return self.avoid_stash
            findable = self.find(state)
            if findable and (findable is True or state.addr in findable):
                return self.find_stash
            if not self.avoid_priority:
                avoidable = self.avoid(state)
                if avoidable and (avoidable is True or state.addr in avoidable):
                    return self.avoid_stash
        except claripy.errors.ClaripySolverInterruptError as e:
            resource_event(state, e)
            return 'interrupted'

        if self.cfg is not None and self.cfg.model.get_any_node(state.addr) is not None:
            if state.addr not in self.ok_blocks:
                return self.avoid_stash

        return None

    def complete(self, simgr):
        return len(simgr.stashes[self.find_stash]) >= self.num_find
