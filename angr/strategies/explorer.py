from . import Strategy

class Explorer(Strategy):
    def __init__(self, find=None, avoid=None, find_stash='found', avoid_stash='avoid', cfg=None, pruned_stash='pruned'):
        super(Explorer, self).__init__()
        self.find = self._condition_to_lambda(find)
        self.avoid = self._condition_to_lambda(avoid)
        self.find_stash = find_stash
        self.avoid_stash = avoid_stash
        self.pruned_stash = pruned_stash
        self.cfg = cfg
        self.ok_blocks = set()

        if cfg is not None:
            if isinstance(avoid, (int, long)):
                avoid = (avoid,)
            if not isinstance(avoid, (list, tuple)):
                self.cfg = None
                return

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

    def filter(self, path):
        r = self.find(path)
        if r:
            if not path.reachable:
                return 'unsat'
            if type(r) is set:
                while path.addr not in r:
                    path = path.step(num_inst=1)[0]
            return (self.find_stash, path)
        if self.avoid(path): return self.avoid_stash
        if self.cfg is not None and self.cfg.get_any_node(path.addr) is not None:
            if path.addr not in self.ok_nodes: return self.pruned_stash
        return None

