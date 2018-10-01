
class Block(object):
    """
    Describes an AIL block.
    """
    def __init__(self, addr, statements=None):
        self.addr = addr
        self.statements = [ ] if statements is None else statements

    def copy(self):
        return Block(
            addr=self.addr,
            statements=self.statements[::],
        )

    def __repr__(self):
        return "<AILBlock %#x of %d statements>" % (self.addr, len(self.statements))

    def __str__(self):
        stmts_str = "\n".join([ ("%02d | %x | " % (i, stmt.ins_addr)) + str(stmt) for i, stmt in enumerate(self.statements)])
        block_str = "## Block %x\n" % self.addr + stmts_str
        return block_str

    def __eq__(self, other):
        return type(other) is Block and \
            self.addr == other.addr and \
            self.statements == other.statements

    def __hash__(self):
        return hash(self.addr)
