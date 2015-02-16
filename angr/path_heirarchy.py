import logging
l = logging.getLogger('angr.path_heirarchy')

class PathHeirarchy(object):
    def __init__(self):
        self._parents = { }
        self._successors = { }

    def _lineage(self, p):
        lineage = [ ]

        cur = p
        while cur in self._parents:
            cur = self._parents[cur]
            lineage.append(cur)

        lineage.reverse()
        return lineage

    def _all_successors(self, p):
        todo = [ p ]

        while len(todo) != 0:
            cur = todo.pop()
            if cur in self._successors:
                todo.extend(self._successors[cur])
            yield cur

    def _find_root_unreachable(self, p):
        lineage = self._lineage(p)
        if len(lineage) == 0 or lineage[-1].reachable:
            return p

        good = max([0] + [ i for i,p in enumerate(lineage) if p._reachable == True ])
        bad = len(lineage) - 1

        while True:
            l.debug("... looking between %d and %d in %d paths", good, bad, len(lineage))
            cur = (bad+good)/2

            if cur == good or cur == bad:
                if lineage[bad].reachable:
                    bad += 1

                root = lineage[bad]
                l.debug("... returning %d (%s)", bad, root)
                return root
            elif lineage[cur].reachable:
                l.debug("... %d is reachable", cur)
                good = cur
            else:
                l.debug("... %d is unreachable", bad)
                bad = cur

    def unreachable(self, p):
        l.debug("Pruning tree given unreachable %s", p)
        root = self._find_root_unreachable(p)
        l.debug("... root is %s", root)
        self._prune(root)

    def _prune(self, p):
        for c in self._all_successors(p):
            if not c._error:
                l.debug("... pruning %s", c)
                c.error = PathUnreachableError('ancestral path %s is unreachable' % p)
                self.remove_path(c)
        self.remove_path(p)

    def remove_path(self, p):
        if p in self._parents:
            del self._parents[p]
        if p in self._successors:
            del self._successors[p]

    def add_successors(self, p, successors):
        if p not in self._successors:
            self._successors[p] = [ ]

        self._successors[p].extend(successors)
        for s in successors:
            self._parents[s] = p

from .errors import PathUnreachableError
