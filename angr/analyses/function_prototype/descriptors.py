
class BaseDescriptor:
    pass


class SimpleLoopVariable(BaseDescriptor):
    def __init__(self, bits:int, lbound:int, ubound:int, interval:int):
        self.bits = bits
        self.lbound = lbound
        self.ubound = ubound
        self.interval = interval

    def __repr__(self):
        return "[LoopVar %s-%s, step %s]" % (
            self.lbound if self.lbound is not None else "unknown",
            self.ubound if self.ubound is not None else "unknown",
            self.interval if self.interval is not None else "unknown",
        )
