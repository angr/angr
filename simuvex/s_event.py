import itertools
event_id_count = itertools.count()

class SimEvent(object):
    #def __init__(self, address=None, stmt_idx=None, message=None, exception=None, traceback=None):
    def __init__(self, state, event_type, **kwargs):
        self.id = event_id_count.next()
        self.type = event_type
        self.bbl_addr = state.log.bbl_addr
        self.stmt_idx = state.log.stmt_idx
        self.sim_procedure = state.log.sim_procedure
        self.objects = dict(kwargs)

    def __repr__(self):
        return "<SimEvent %s %d, with fields %s>" % (self.type, self.id, self.objects.keys())

