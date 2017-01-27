
from ..java import JavaSimProcedure


class Read(JavaSimProcedure):
    # TODO consider the fd

    __provides__ = (
        ("java.io.InputStream", "read()"),
    )

    def run(self, this, *args):
        v = self.state.posix.read_from(0, 1)
        return v.zero_extend(32-8)
