import simuvex

class PathEvent(object):
    pass

class PathEventExitTaken(PathEvent):
    def __init__(self, e):
        self.target = e.target
        self.guard = e.guard
        self.jumpkind = e.jumpkind
        self.source = e.source

class PathEventSimRun(PathEvent):
    def __init__(self, r):
        self.addr = r.addr
        self.type = "SimIRSB" if isinstance(r, simuvex.SimIRSB) else "SimProcedure" if isinstance(r, simuvex.SimProcedure) else "SimRunUnknown"
        self.procedure = r.__class__.__name__ if isinstance(r, simuvex.SimProcedure) else "-"
        self.refs = r.refs()
        self.exits = [ PathEventExitTaken(e) for e in r.exits() ]

class PathEventError(PathEvent):
    def __init__(self, m, exc=None):
        self.message = m
        self.exception = exc

class PathEventMessage(PathEvent):
    def __init__(self, c, m):
        self.category = c
        self.message = m
