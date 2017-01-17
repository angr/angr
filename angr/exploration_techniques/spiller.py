import logging

l = logging.getLogger("angr.exploration_techniques.spiller")

import ana
from . import ExplorationTechnique

class SpilledPath(ana.Storable):
    def __init__(self, path):
        self.path = path

    def _ana_getstate(self):
        return (self.path,)

    def _ana_setstate(self, s):
        self.path = s[0]

class Spiller(ExplorationTechnique):
    """
    Automatically spill paths out. It can spill out paths to a different stash, spill
    them out to ANA, or first do the former and then (after enough paths) the latter.
    """

    def __init__(
        self,
        src_stash="active", min=5, max=10, #pylint:disable=redefined-builtin
        staging_stash="spill_stage", staging_min=10, staging_max=20,
        pickle_callback=None, unpickle_callback=None, priority_key=None
    ):
        """
        Initializes the spiller.

        @param max: the number of paths that are *not* spilled
        @param src_stash: the stash from which to spill paths (default: active)
        @param staging_stash: the stash *to* which to spill paths (default: "spill_stage")
        @param staging_max: the number of paths that can be in the staging stash before things get spilled to ANA (default: None. If staging_stash is set, then this means unlimited, and ANA will not be used).
        @param priority_key: a function that takes a path and returns its numberical priority (MAX_INT is lowest priority). By default, self.path_priority will be used, which prioritizes by object ID.
        """
        super(Spiller, self).__init__()
        self.max = max
        self.min = min
        self.src_stash = src_stash
        self.staging_stash = staging_stash
        self.staging_max = staging_max
        self.staging_min = staging_min

        # various callbacks
        self.priority_key = priority_key
        self.unpickle_callback = unpickle_callback
        self.pickle_callback = pickle_callback

        # tracking of pickled stuff
        self._pickled_paths = [ ]
        self._ever_pickled = 0
        self._ever_unpickled = 0

    def _unpickle(self, n):
        self._pickled_paths.sort()
        unpickled = [ SpilledPath.ana_load(pid).path for _,pid in self._pickled_paths[:n] ]
        self._pickled_paths[:n] = [ ]
        self._ever_unpickled += len(unpickled)
        if self.unpickle_callback:
            map(self.unpickle_callback, unpickled)
        return unpickled

    def _get_priority(self, path):
        return (self.priority_key or self.path_priority)(path)

    def _pickle(self, paths):
        if self.pickle_callback:
            map(self.pickle_callback, paths)
        wrappers = [ SpilledPath(path) for path in paths ]
        self._ever_pickled += len(paths)
        for w in wrappers:
            w.make_uuid()
        self._pickled_paths += [ (self._get_priority(w.path), w.ana_store()) for w in wrappers ]

    def step(self, pg, stash, **kwargs):
        pg = pg.step(stash=stash, **kwargs)

        paths = pg.stashes[self.src_stash]
        staged_paths = pg.stashes.setdefault(self.staging_stash, [ ]) if self.staging_stash else [ ]

        if len(paths) < self.min:
            missing = (self.max + self.min) / 2 - len(paths)
            l.debug("Too few paths in stash %s.", self.src_stash)
            if self.staging_stash:
                l.debug("... retrieving paths from staging stash (%s)", self.staging_stash)
                staged_paths.sort(key=self.priority_key or self.path_priority)
                paths += staged_paths[:missing]
                staged_paths[:missing] = [ ]
            else:
                l.debug("... staging stash disabled; unpickling paths")
                paths += self._unpickle(missing)

        if len(paths) > self.max:
            l.debug("Too many paths in stash %s", self.src_stash)
            paths.sort(key=self.priority_key or self.path_priority)
            staged_paths += paths[self.max:]
            paths[self.max:] = [ ]

        # if we have too few staged paths, unpickle up to halfway between max and min
        if len(staged_paths) < self.staging_min:
            l.debug("Too few paths in staging stash (%s)", self.staging_stash)
            staged_paths += self._unpickle((self.staging_min + self.staging_max) / 2 - len(staged_paths))

        if len(staged_paths) > self.staging_max:
            l.debug("Too many paths in staging stash (%s)", self.staging_stash)
            self._pickle(staged_paths[self.staging_max:])
            staged_paths[self.staging_max:] = [ ]

        pg.stashes[self.src_stash] = paths
        pg.stashes[self.staging_stash] = staged_paths
        return pg

    @staticmethod
    def path_priority(path):
        return id(path)
