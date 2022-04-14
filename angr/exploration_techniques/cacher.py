import os
import string
import hashlib
import tempfile
import logging

from . import ExplorationTechnique
from .common import condition_to_lambda


l = logging.getLogger(name=__name__)


class Cacher(ExplorationTechnique):
    """
    An exploration technique that caches states during symbolic execution.

    DO NOT USE THIS - THIS IS FOR ARCHIVAL PURPOSES ONLY
    """

    def __init__(self, when=None, dump_cache=True, load_cache=True, container=None,
                 lookup=None, dump_func=None, load_func=None):
        """
        :param dump_cache: Whether to dump data to cache.
        :param load_cache: Whether to load data from cache.
        :param container:  Data container.
        :param when:       If provided, should be a function that takes a SimulationManager and returns
                           a Boolean, or the address of the state to be cached.
        :param lookup:     A function that returns True if cache hit and False otherwise.
        :param dump_func:  If provided, should be a function that defines how Cacher should cache the
                           SimulationManager. Default to caching the active stash.
        :param load_func:  If provided, should be a function that defines how Cacher should uncache the
                           SimulationManager. Default to uncaching the stash to be stepped.
        """
        super(Cacher, self).__init__()
        self._dump_cond, _ = condition_to_lambda(when)
        self._dump_cache = dump_cache
        self._load_cache = load_cache
        self._cache_lookup = self._lookup if lookup is None else lookup
        self._dump_func = self._dump_stash if dump_func is None else dump_func
        self._load_func = self._load_stash if load_func is None else load_func

        self.container = container
        self.container_pickle_str = isinstance(container, str) and not all(c in string.printable for c in container)

    def setup(self, simgr):
        binary = simgr._project.filename
        binhash = hashlib.md5(open(binary).read()).hexdigest()

        if self.container is None:
            # Create a temporary directory to hold the cache files
            tmp_directory = tempfile.mkdtemp(prefix="angr_cacher_container")
            self.container = os.path.join(tmp_directory, "%s-%s.cache" % (os.path.basename(binary), binhash))

        # Container is the file name.
        elif isinstance(self.container, str) and not self.container_pickle_str:
            try:
                self.container = self.container % {'name': os.path.basename(binary), 'binhash': binhash, 'addr': '%(addr)s'}
            except KeyError:
                l.error("Only the following cache keys are accepted: 'name', 'binhash' and 'addr'.")
                raise

        if self._load_cache and self._cache_lookup():
            l.warning("Uncaching from %s...", self.container)
            self._load_func(self.container, simgr)

        self.project = simgr._project

    def step(self, simgr, stash='active', **kwargs):
        # We cache if any of the states in 'stash' satisfies the condition.
        for s in simgr.stashes[stash]:
            if self._dump_cache and self._dump_cond(s):
                if isinstance(self.container, str):
                    self.container = self.container % {'addr': hex(s.addr)[:-1]}

                if self._cache_lookup():
                    continue

                l.warning("Caching to %s...", self.container)

                self._dump_func(self.container, simgr, stash)

        return simgr.step(stash=stash, **kwargs)

    def _lookup(self):
        if isinstance(self.container, str):
            if self.container_pickle_str:
                return True

            elif os.path.exists(self.container):
                return True

            else:
                return False

        elif isinstance(self.container, file):
            return True

        else:
            l.warning("Default Cacher cannot recognize containers of type other than 'str' and 'file'.")
            return False

    @staticmethod
    def _load_stash(container, simgr):
        project = simgr._project
        cached_project = project.load_function(container)

        if cached_project is not None:
            cached_project.analyses = project.analyses
            cached_project.store_function = project.store_function
            cached_project.load_function = project.load_function

            stash = cached_project.storage['cached_states']
            for s in stash:
                s.project = cached_project

            simgr.stashes['active'] = stash
            cached_project.storage = None

            simgr._project = cached_project

        else:
            l.error("Something went wrong during Project unpickling...")

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
