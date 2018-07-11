from . import ExplorationTechnique
from .. import sim_options
from ..errors import SimIRSBNoDecodeError

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
        self.find = self._condition_to_lambda(find)
        self.avoid = self._condition_to_lambda(avoid)
        self.find_stash = find_stash
        self.avoid_stash = avoid_stash
        self.cfg = cfg
        self.ok_blocks = set()
        self.num_find = num_find
        self.avoid_priority = avoid_priority

        find_addrs = getattr(self.find, "addrs", None)
        avoid_addrs = getattr(self.avoid, "addrs", None)

        # it is safe to use unicorn only if all addresses at which we should stop are statically known
        self._warn_unicorn = (find_addrs is None) or (avoid_addrs is None)

        # even if avoid or find addresses are not statically known, stop on those that we do know
        self._extra_stop_points = (find_addrs or set()) | (avoid_addrs or set())


        # TODO: This is a hack for while CFGFast doesn't handle procedure continuations
        from .. import analyses
        if isinstance(cfg, analyses.CFGFast):
            l.error("CFGFast is currently inappropriate for use with Explorer.")
            l.error("Usage of the CFG has been disabled for this explorer.")
            self.cfg = None

        if self.cfg is not None:
            avoid = avoid_addrs or set()

            # we need the find addresses to be determined statically
            if not find_addrs:
                l.error("You must provide at least one 'find' address as a number, set, list, or tuple if you provide a CFG.")
                l.error("Usage of the CFG has been disabled for this explorer.")
                self.cfg = None
                return

            for a in avoid:
                if cfg.get_any_node(a) is None:
                    l.warning("'Avoid' address %#x not present in CFG...", a)

            # not a queue but a stack... it's just a worklist!
            queue = []
            for f in find_addrs:
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
        base_extra_stop_points = set(kwargs.get("extra_stop_points") or {})
        return simgr.step(stash=stash, extra_stop_points=base_extra_stop_points | self._extra_stop_points, **kwargs)

    def filter(self, simgr, state, filter_func=None):
        if sim_options.UNICORN in state.options and self._warn_unicorn:
            self._warn_unicorn = False # show warning only once
            l.warning("Using unicorn with find or avoid conditions that are a lambda (not a number, set, tuple or list).")
            l.warning("Unicorn may step over states that match the condition (find or avoid) without stopping.")
        rFind = self.find(state)
        if rFind:
            if not state.history.reachable:
                return 'unsat'
            rAvoid = self.avoid(state)
            if rAvoid:
                # if there is a conflict
                if self.avoid_priority & ((type(rFind) is not set) | (type(rAvoid) is not set)):
                    # with avoid_priority and one of the conditions is not a set
                    return self.avoid_stash
            if type(rAvoid) is not set:
                # rAvoid is False or self.avoid_priority is False
                # Setting rAvoid to {} simplifies the rest of the code
                rAvoid = {}
            if type(rFind) is set:
                while state.addr not in rFind:
                    if state.addr in rAvoid:
                        return self.avoid_stash
                    try:
                        state = self.project.factory.successors(state, num_inst=1).successors[0]
                    except SimIRSBNoDecodeError as ex:
                        if state.arch.name.startswith('MIPS'):
                            l.warning('Due to MIPS delay slots, the find address must be executed with other instructions and therefore may not be able to be found' + \
                                ' - Trying to find state that includes find address')
                            if len(rFind.intersection(set(state.block().instruction_addrs))) > 0:
                                #there is an address that is both in the block AND in the rFind stat
                                l.warning('Found state that includes find instruction, this one will be returned')
                                rFind = rFind.union(set(state.block().instruction_addrs))
                        else:
                                raise ex
                if self.avoid_priority & (state.addr in rAvoid):
                    # Only occurs if the intersection of rAvoid and rFind is not empty
                    # Why would anyone want that?
                    return self.avoid_stash
            return (self.find_stash, state)
        if self.avoid(state): return self.avoid_stash
        if self.cfg is not None and self.cfg.get_any_node(state.addr) is not None:
            if state.addr not in self.ok_blocks: return self.avoid_stash
        return None

    def complete(self, simgr):
        return len(simgr.stashes[self.find_stash]) >= self.num_find
