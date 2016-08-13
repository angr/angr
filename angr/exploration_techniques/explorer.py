from . import ExplorationTechnique

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

        if cfg is not None:
            if isinstance(avoid, (int, long)):
                avoid = (avoid,)
            if not isinstance(avoid, (list, tuple)):
                avoid = ()

            if isinstance(find, (int, long)):
                find = (find,)
            if not isinstance(find, (list, tuple)):
                self.cfg = None
                return

            # not a queue but a stack... it's just a worklist!
            queue = sum((cfg.get_all_nodes(f) for f in find), [])
            while len(queue) > 0:
                n = queue.pop()
                if n.addr in self.ok_blocks:
                    continue
                if n.addr in avoid:
                    continue
                self.ok_blocks.add(n.addr)
                queue.extend(n.predecessors)

    def setup(self, pg):
        if not self.find_stash in pg.stashes: pg.stashes[self.find_stash] = []
        if not self.avoid_stash in pg.stashes: pg.stashes[self.avoid_stash] = []

    def filter(self, path):
        rFind = self.find(path)
        if rFind:
            if not path.reachable:
                return 'unsat'
            rAvoid = self.avoid(path)
            if rAvoid:
                # if there is a conflict
                if self.avoid_priority & ((type(rFind) is not set) | (type(rAvoid) is not set)):
                    # with avoid_priority and one of the conditions is not a set
                    return self.avoid_stash
            if (type(rAvoid) is not set):
                # rAvoid is False or self.avoid_priority is False
                # Setting rAvoid to {} simplifies the rest of the code
                rAvoid = {}
            if type(rFind) is set:
                while path.addr not in rFind:
                    if path.addr in rAvoid:
                        return self.avoid_stash
                    path = path.step(num_inst=1)[0]
                if self.avoid_priority & (path.addr in rAvoid):
                    # Only occurs if the intersection of rAvoid and rFind is not empty
                    # Why would anyone want that?
                    return self.avoid_stash
            return (self.find_stash, path)
        if self.avoid(path): return self.avoid_stash
        if self.cfg is not None and self.cfg.get_any_node(path.addr) is not None:
            if path.addr not in self.ok_blocks: return self.avoid_stash
        return None

    def complete(self, pg):
        return len(pg.stashes[self.find_stash]) >= self.num_find

