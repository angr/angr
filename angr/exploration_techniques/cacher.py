import os
import hashlib
import logging
import pickle

from . import ExplorationTechnique

l = logging.getLogger("angr.exploration_techniques.cacher")

class Cacher(ExplorationTechnique):
    """
    An exploration technique that caches states during symbolic execution.
    """

    def __init__(self, when=None, dump_cache=True, cache_file=None, dump_func=None, load_func=None):
        """
        :param dump_cache: Whether to dump data to cache.
        :param cache_file: File to cache data.
        :param when      : If provided, should be a function that takes a SimulationManager and returns
                           a Boolean, or the address of the state to be cached.
        :param dump_func : If provided, should be a function that defines how Cacher should cache the
                           SimulationManager. Default to caching the active stash.
        :param load_func : If provided, should be a function that defines how Cacher should uncache the
                           SimulationManager. Default to uncaching the stash to be stepped.
        """

        super(Cacher, self).__init__()
        self._dump_cond = self._condition_to_lambda(when)
        self._dump_cache = dump_cache
        self._cache_file = cache_file
        self._dump_func = self._dump_stash if dump_func is None else dump_func
        self._load_func = self._load_stash if load_func is None else load_func
        self._cached = False

    def setup(self, simgr):
        self.project = simgr._project

        if self._cache_file is None:
            binary = self.project.filename
            binhash = hashlib.md5(open(binary).read()).hexdigest()
            self._cache_file = os.path.join("/tmp", "%s-%s.tcache" % (os.path.basename(binary), binhash))

        if os.path.exists(self._cache_file):
            l.warning("Loading state from cache file %s", self._cache_file)

            with open(self._cache_file) as f:
                self._load_func(simgr)

    def step(self, simgr, stash, **kwargs):
        simgr.step(stash=stash, **kwargs)
        for s in simgr[stash]:
            if self._dump_cond(s):
                self._dump_func(simgr, stash)
                self._cached = True
                break
        return simgr
        
    def complete(self, simgr):
        return self._cached

    def _load_stash(simgr):
        with open(self._cache_file) as f:
            stash = pickle.load(f)
        simgr.active = stash

    def _dump_stash(simgr, stash):
        if self._dump_cache:
            l.warning("Caching state to %s...", self._cache_file)
            f = open(self._cache_file, 'wb')

            try:
                # Do not pickle project
                for s in simgr[stash]:
                    s.project = None
                    s.history.trim()
                try:
                    pickle.dump(simgr[stash], f, pickle.HIGHEST_PROTOCOL)
                except RuntimeError as e: # maximum recursion depth can be reached here
                    l.error("Unable to cache state, '%s' during pickling", e.message)
                finally:
                    for s in simgr[stash]:
                        s.project = self.project
            finally:
                if f:
                    f.close()
