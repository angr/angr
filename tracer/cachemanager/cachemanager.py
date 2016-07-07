import pickle
import logging

l = logging.getLogger("tracer.cachemanager.CacheManager")

class CacheManager(object):

    def __init__(self, tracer):
        self.tracer = tracer

    def cacher(self):
        raise NotImplementedError("subclasses must implement this method")

    def cache_lookup(self):
        raise NotImplementedError("subclasses must implement this method")

    def _prepare_cache_data(self):

        cache_path = self.tracer.previous.copy()
        self.tracer.remove_preconstraints(cache_path, to_composite_solver=False)

        state = cache_path.state

        ds = None
        try:
            ds = pickle.dumps((self.tracer.bb_cnt - 1, self.tracer.cgc_flag_data, state))
        except RuntimeError as e: # maximum recursion depth can be reached here
            l.error("unable to cache state, '%s' during pickling", e.message)

        return ds
