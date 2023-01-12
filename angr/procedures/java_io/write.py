from ..java import JavaSimProcedure


class Write(JavaSimProcedure):
    # TODO consider the fd

    __provides__ = (("java.io.PrintStream", "write(int)"),)

    def run(self, this, b, *args):  # pylint: disable=arguments-differ,unused-argument
        # we do % 256 since this is what Java implementation does.
        # formally what happens is %0x100 and then remove the 3 0-bytes
        # this is outputted as 1 byte only
        # I tested with: echo "a" | java -jar simple3.jar  > /tmp/o1.bin; xxd /tmp/o1.bin; 00000000: 62

        v = (b % 256).get_byte(3)
        self.state.posix.stdout.write(None, v)
