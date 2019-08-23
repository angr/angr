from angr.procedures.stubs.format_parser import FormatParser

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

class fscanf(FormatParser):
    #pylint:disable=arguments-differ

    def run(self, file_ptr):
        # TODO handle errors

        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        fmt_str = self._parse(1)
        items = fmt_str.interpret(2, self.arg, simfd=simfd)
        return items
