import itertools
event_id_count = itertools.count()

class SimEvent(object):
    #def __init__(self, address=None, stmt_idx=None, message=None, exception=None, traceback=None):
    def __init__(self, state, event_type, **kwargs):
        self.id = next(event_id_count)
        self.type = event_type
        self.ins_addr = state.scratch.ins_addr
        self.bbl_addr = state.scratch.bbl_addr
        self.stmt_idx = state.scratch.stmt_idx
        self.sim_procedure = None if state.scratch.sim_procedure is None else state.scratch.sim_procedure.canonical
        self.objects = dict(kwargs)

    def __repr__(self):
        return "<SimEvent %s %d, with fields %s>" % (self.type, self.id, self.objects.keys())

    def _copy_event(self):
        c = self.__class__.__new__(self.__class__)
        c.id = self.id
        c.type = self.type
        c.bbl_addr = self.bbl_addr
        c.stmt_idx = self.stmt_idx
        c.sim_procedure = self.sim_procedure
        c.objects = dict(self.objects)

        return c
