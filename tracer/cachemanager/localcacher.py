import os
import hashlib
import logging
import pickle
from .cachemanager import CacheManager

l = logging.getLogger("tracer.cachemanager.LocalCacheManager")

class LocalCacheManager(CacheManager):

    def __init__(self, dump_cache=True):
        super(LocalCacheManager, self).__init__()
        self._cache_file = None
        self._dump_cache = dump_cache

    def set_tracer(self, tracer):
        super(LocalCacheManager, self).set_tracer(tracer)

        binhash = hashlib.md5(open(self.tracer.binary).read()).hexdigest()
        self._cache_file = os.path.join("/tmp", \
                "%s-%s.tcache" % (os.path.basename(self.tracer.binary), binhash))

    def cache_lookup(self):

        if os.path.exists(self._cache_file):
            l.warning("loading state from cache file %s", self._cache_file)

            # just for the testcase
            self.tracer._loaded_from_cache = True

            with open(self._cache_file) as f:
                return pickle.load(f)

    def cacher(self, simstate):
        if self._dump_cache:
            l.warning("caching state to %s...", self._cache_file)
            f = open(self._cache_file, 'wb')
        else:
            f = None

        try:
            self._dump_cache_data(simstate, dump_fp=f)
        finally:
            if f:
                f.close()
