from ..java import JavaSimProcedure


class Read(JavaSimProcedure):
    # TODO consider the fd

    __provides__ = (("java.io.InputStream", "read()"),)

    def run(self, this, *args):  # pylint: disable=arguments-differ,unused-argument
        data, _, _ = self.state.posix.stdin.read(None, 1)
        return data.zero_extend(32 - 8)
