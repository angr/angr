import os
import hashlib
import logging

from . import ExplorationTechnique


l = logging.getLogger("angr.exploration_techniques.cacher")


class Cacher(ExplorationTechnique):
    """
    An exploration technique that caches states during symbolic execution.
    """

    def __init__(self, when=None, dump_cache=True, load_cache=True, container=None, dump_func=None, load_func=None):
        """
        :param dump_cache: Whether to dump data to cache.
        :param load_cache: Whether to load data from cache.
        :param container : Data container.
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
        self._load_cache = load_cache
        self._container = container
        self._dump_func = self._dump_stash if dump_func is None else dump_func
        self._load_func = self._load_stash if load_func is None else load_func

        self._container_picklable = None
        try:
            import pickle
            pickle.loads(container)
            self._container_picklable = True
        except:
            self._container_picklable = False

    def setup(self, simgr):
        binary = simgr._project.filename
        binhash = hashlib.md5(open(binary).read()).hexdigest()

        # By default, we dump data to a file in under /tmp/.
        if self._container is None:
            self._container = os.path.join("/tmp", "%s-%s.cache" % (os.path.basename(binary), binhash))

        # Container is the file name.
        elif isinstance(self._container, str) and not self._container_picklable:
            try:
                self._container = self._container % {'name': os.path.basename(binary), 'binhash': binhash, 'addr': '%(addr)s'}
            except KeyError:
                l.error("Only the following cache keys are accepted: 'name', 'binhash' and 'addr'.")
                raise

        if (self._load_cache
           and isinstance(self._container, str)
           and not self._container_picklable
           and os.path.exists(self._container)):
            l.warning("Uncaching from %s...", self._container)
            self._load_func(self._container, simgr)

        self.project = simgr._project

    def step(self, simgr, stash, **kwargs):
        # We cache if any of the states in 'stash' satisfies the condition.
        for s in simgr.stashes[stash]:
            if self._dump_cache and self._dump_cond(s):
                if isinstance(self._container, str):
                    self._container = self._container % {'addr': hex(s.addr)[:-1]}

                if not self._container_picklable and os.path.exists(self._container):
                    continue

                l.warning("Caching to %s...", self._container)

                self._dump_func(self._container, simgr, stash)

        return simgr.step(stash=stash, **kwargs)

    @staticmethod
    def _load_stash(container, simgr):
        project = simgr._project
        cached_project = project.load_function(container)
        cached_project.analyses = project.analyses
        cached_project.surveyors = project.surveyors
        cached_project.store_function = project.store_function
        cached_project.load_function = project.load_function
        cached_project.storage = None

        stash = cached_project.storage['cached_states']
        for s in stash:
            s.project = cached_project

        simgr.stashes['active'] = stash
        simgr._project = cached_project

    @staticmethod
    def _dump_stash(container, simgr, stash):
        for s in simgr.stashes[stash]:
            s.project = None
            s.history.trim()

        project = simgr._project
        project.storage['cached_states'] = simgr.stashes[stash]
        project.store_function(container)

        for s in simgr.stashes[stash]:
            s.project = project
