
class Block(object):
    """
    Describes an AIL block.
    """
    def __init__(self, addr, statements=None):
        self.addr = addr
        self.statements = [ ] if statements is None else statements

    def __repr__(self):
        return "<AILBlock of %d statements>" % len(self.statements)

    def __str__(self):
        return "\n".join([ str(stmt) for stmt in self.statements])
