import pickle
import logging

l = logging.getLogger("tracer.cachemanager.CacheManager")

class CacheManager(object):

    def __init__(self):
        self.tracer = None

    def set_tracer(self, tracer):
        self.tracer = tracer

    def cacher(self, simstate):
        raise NotImplementedError("subclasses must implement this method")

    def cache_lookup(self):
        raise NotImplementedError("subclasses must implement this method")

    def _prepare_cache_data(self, simstate):

        state = self.tracer.previous.state

        ds = None
        try:
            ds = pickle.dumps((self.tracer.bb_cnt - 1, self.tracer.cgc_flag_data, state))
        except RuntimeError as e: # maximum recursion depth can be reached here
            l.error("unable to cache state, '%s' during pickling", e.message)

        # add preconstraints to tracer
        self.tracer._preconstrain_state(simstate)

        return ds
