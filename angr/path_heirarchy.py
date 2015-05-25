import logging
l = logging.getLogger('angr.path_heirarchy')

import weakref

class PathHeirarchy(object):
    def __init__(self):
        self._parents = { }
        self._successors = { }
        self._good = set()
        self._path_mapping = weakref.WeakValueDictionary()

    def _lineage(self, se):
        lineage = [ ]

        cur = se
        while cur in self._parents:
            cur = self._parents[cur]
            lineage.append(cur)

        lineage.reverse()
        return lineage

    def _all_successors(self, se):
        todo = [ se ]

        while len(todo) != 0:
            cur = todo.pop()
            if cur in self._successors:
                todo.extend(self._successors[cur])
            yield cur

    def _find_root_unreachable(self, se):
        lineage = self._lineage(se)
        if len(lineage) == 0 or lineage[-1].reachable:
            return se

        good = max([0] + [ i for i,s in enumerate(lineage) if s in self._good ])
        bad = len(lineage) - 1

        while True:
            l.debug("... looking between %d and %d in %d paths", good, bad, len(lineage))
            cur = (bad+good)/2

            if cur == good or cur == bad:
                if lineage[bad].satisfiable():
                    self._good.add(lineage[bad])
                    bad += 1

                root = lineage[bad]
                l.debug("... returning %d (%s)", bad, root)
                return root
            elif lineage[cur].satisfiable():
                l.debug("... %d is reachable", cur)
                self._good.add(lineage[cur])
                good = cur
            else:
                l.debug("... %d is unreachable", bad)
                bad = cur

    def _prune(self, se):
        for c in self._all_successors(se):
            l.debug("... pruning %s", c)

            try:
                p = self._path_mapping[c]
                if not p._error:
                    p.error = PathUnreachableError('ancestral path %s is unreachable' % p)
                    p._reachable = False
            except KeyError:
                pass

            self._remove(c)
        self._remove(se)

    def _remove(self, se):
        if se in self._parents:
            del self._parents[se]
        if se in self._successors:
            del self._successors[se]

    def unreachable(self, p):
        se = p.state.se

        l.debug("Pruning tree given unreachable %s", se)
        root = self._find_root_unreachable(se)
        l.debug("... root is %s", root)
        self._prune(root)

    def add_successors(self, p, successors):
        l.debug("Adding %d successors for %s", len(successors), p)
        if p.state.se not in self._successors:
            self._successors[p.state.se] = [ ]

        self._successors[p.state.se].extend(successors)
        for s in successors:
            self._parents[s] = p.state.se

from .errors import PathUnreachableError
