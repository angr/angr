import simuvex
from simuvex.s_type import SimTypeFd, SimTypeInt
from claripy import BVV
######################################
# getc
######################################


class _IO_getc(simuvex.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, fd):
        self.argument_types = {0: SimTypeFd()}
        self.return_type = SimTypeInt(32, True)

        # let's get the memory back for the file we're interested in and find
        # the newline
        # fd should be a FILE* but for now It is a int file descriptor
        fp = self.state.posix.get_file(fd)
        pos = fp.pos

        max_str_len = self.state.libc.max_str_len

        # if there exists a limit on the file size, let's respect that, the
        # limit cannot be symbolic
        limit = max_str_len if fp.size is None else self.state.se.max_int(
            fp.size - pos)

        # limit will always be concrete, if it's zero we EOF'd
        if limit != 0:
            data = fp.read_from(1)
            data = data.zero_extend(32 - data.size())
        else:
            data = -1 #EOF
            data = BVV(data, 32)
        return data
