import simuvex
from simuvex.s_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

######################################
# fgets
######################################

class fgets(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, fd):
        self.argument_types = {2: SimTypeFd(),
                               0: self.ty_ptr(SimTypeArray(SimTypeChar(), size)),
                               1: SimTypeLength(self.state.arch)}
        self.return_type = self.argument_types[0]

        # some sensible limits for the new line search
        max_symbolic_bytes = self.state.libc.buf_symbolic_bytes
        max_str_len = self.state.libc.max_str_len

        # let's get the memory back for the file we're interested in and find the newline
        fp = self.state.posix.get_file(fd)
        pos = fp.pos
        mem = fp.content
        # if there exists a limit on the file size, let's respect that, the limit cannot be symbolic
        limit = max_str_len if fp.size is None else self.state.se.max_int(fp.size - pos)

        # limit will always be concrete, if it's zero we EOF'd
        if limit != 0:
            # XXX max_str_len is small, might not be suitable for tracing!
            # measure up to the newline of size - 1
            r, c, i = mem.find(pos, self.state.BVV('\n'), limit, max_symbolic_bytes=max_symbolic_bytes)
        else:
            r = 0
            c = [ ]

        # XXX: this is a HACK to determine if r is 0 because there is a newline at the first index or
        # if r is 0 because there cannot be any newline
        errored = False
        if not self.state.se.satisfiable(extra_constraints=(r > 0,)):
            errored = True
            if self.state.se.solution(mem.load(0, 1), self.state.BVV('\n')):
                errored = False

        # make sure we only read up to size - 1
        read_size = self.state.se.If(size == 0, 0, size - 1)
        # if file can EOF (ie not completely symbolic)
        if fp.size is not None:
            read_size = self.state.se.If(limit < read_size, limit, read_size)

        # now if find errored then there cannot exist a newline in the file, otherwise this logic checks out
        if not errored:
            newline_d = self.state.se.If(r == 0, r, r - pos + 1)
            distance = self.state.se.If(read_size < newline_d, read_size, newline_d)
        else:
            distance = read_size

        # read in up to the newline
        ret = self.inline_call(simuvex.SimProcedures['libc.so.6']['read'], fd, dst, distance).ret_expr

        # in case there's no newline
        c = self.state.se.Or(ret == read_size, *c)
        self.state.add_constraints(c)

        # otherwise we take care of the newline case
        # now write the terminating null byte, should be placed after the newline which is also stored
        self.state.memory.store(dst + distance, self.state.BVV(0, 8))

        inner_case = self.state.se.If(self.state.se.And(fp.pos == 0, ret == 0), 0, dst)
        return self.state.se.If(size == 0, 0, inner_case)
