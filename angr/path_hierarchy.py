import logging
l = logging.getLogger('angr.path_hierarchy')

import weakref

class PathHierarchy(object):
    def __init__(self, strong_path_mapping=None):
        self._parents = { }
        self._successors = { }
        self._good = set()
        self._path_mapping = {} if strong_path_mapping else weakref.WeakValueDictionary()

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
        successors = [ ]

        while len(todo) != 0:
            cur = todo.pop()
            if cur in self._successors:
                todo += self._successors[cur]
            successors.append(cur)

        return successors

    def _is_reachable(self, se):
        if se in self._good:
            return True
        else:
            s = se._solver.satisfiable()
            if s:
                self._good.add(se)
            return s

    def _find_root_unreachable(self, se):
        lineage = self._lineage(se)
        if len(lineage) == 0 or self._is_reachable(lineage[-1]):
            return se

        good = max([0] + [ i for i,s in enumerate(lineage) if s in self._good ])
        bad = len(lineage) - 1

        while True:
            l.debug("... looking between %d and %d in %d paths", good, bad, len(lineage))
            cur = (bad+good)/2

            if cur == good or cur == bad:
                if self._is_reachable(lineage[bad]):
                    bad += 1

                root = lineage[bad]
                l.debug("... returning %d (%s)", bad, root)
                return root
            elif self._is_reachable(lineage[cur]):
                l.debug("... %d is reachable", cur)
                good = cur
            else:
                l.debug("... %d is unreachable", bad)
                bad = cur

    def _prune(self, se):
        to_prune = self._all_successors(se)
        to_prune.append(se)

        for c in to_prune:
            l.debug("... pruning %s", c)

            try:
                p = self._path_mapping[c]
                l.debug("... still there: %s", p)
                if not p.errored:
                    # This is a hack! This entire operation is a hack!
                    p.error = PathUnreachableError('ancestral path %s is unreachable' % p)
                    p._run_error = p.error
                    p._reachable = False
                    p.errored = True
            except KeyError:
                l.debug("... gc'ed: path of %s", c)

        for c in to_prune:
            self._remove(c)

        return to_prune

    def _remove(self, se):
        if se in self._parents:
            del self._parents[se]
        if se in self._successors:
            del self._successors[se]
        self._good.discard(se)

    def unreachable(self, p):
        se = p.state.se

        l.debug("Pruning tree given unreachable %s", se)
        root = self._find_root_unreachable(se)
        l.debug("... root is %s", root)
        self._prune(root)

        #paths = [ ]
        #for se in pruned:
        #   try:
        #       paths.append(self._path_mapping[se])
        #   except KeyError:
        #       pass
        #return paths

    def add_successors(self, p, successors):
        l.debug("Adding %d successors for %s", len(successors), p)

        if p.state.se not in self._successors:
            self._successors[p.state.se] = [ ]
        self._successors[p.state.se] += [ s.state.se for s in successors ]
        self._path_mapping[p.state.se] = p

        for s in successors:
            self._parents[s.state.se] = p.state.se
            self._path_mapping[s.state.se] = s

from .errors import PathUnreachableError
