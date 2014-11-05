import simuvex
#import pyvex

class PathEvent(object):
    pass
    #def ida_log(self, ida):
    #   pass

class PathEventExitTaken(PathEvent):
    def __init__(self, e):
        self.target = e.target
        self.guard = e.guard
        self.jumpkind = e.jumpkind
        self.source = e.source

    def __repr__(self):
        return '<PathEventExitTaken from {} to {}>'.format(self.source, self.target)

    #def ida_log(self, ida, path_name):
    #   if self.source is None or self._path.last_run is None:
    #       ida.idc.MakeComm(self.target.eval().value if hasattr(self.target.eval(), 'value') else self.target, "Path %s started here" % self._path.name)
    #   else:
    #       s = self.source
    #       t = self._path.last_initial_state.se.any_int(self.target)
    #       ida.idc.MakeComm(s, "Path %s jumped out to 0x%x" % (self._path.name, t))
    #       ida.idc.MakeComm(t, "Path %s jumped in from 0x%x" % (self._path.name, s))

class PathEventSimRun(PathEvent):
    def __init__(self, r):
        self.addr = r.addr
        self.type = "SimIRSB" if isinstance(r, simuvex.SimIRSB) else "SimProcedure" if isinstance(r, simuvex.SimProcedure) else "SimRunUnknown"
        self.procedure = r.__class__.__name__ if isinstance(r, simuvex.SimProcedure) else "-"
        self.refs = r.refs()
        self.exits = [ PathEventExitTaken(e) for e in r.exits() ]

    def __repr__(self):
        return '<PathEventSimRun ({}) at {}>'.format(self.type, self.addr)

    #def ida_log(self, ida, path_name):
    #   if self.type != "SimIRSB":
    #       return

    #   irsb = self._path._project.block(self.addr)
    #   for b in [ s for s in irsb.statements() if isinstance(s, pyvex.IRStmt.IMark) ]:
    #       print "coloring",hex(b.addr)
    #       ida.idaapi.set_item_color(b.addr, int(("%x" % (hash(id(self._path))))[:6], 16))

class PathEventError(PathEvent):
    def __init__(self, m, exc=None):
        self.message = m
        self.exception = exc

    def __repr__(self):
        return '<PathEventError>'

    #def ida_log(self, ida, path_name):
    #   r = "Path %s got error '%s'" % (self._path.name, self.message)
    #   if self.exception is not None:
    #       r += ", with exception '%s'" % self.exception
    #   ida.idc.MakeComm(self._path.last_run.addr, r)

class PathEventMessage(PathEvent):
    def __init__(self, c, m):
        self.category = c
        self.message = m

    def __repr__(self):
        return '<PathEventMessage>'
