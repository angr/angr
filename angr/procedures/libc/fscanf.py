from angr.procedures.stubs.format_parser import ScanfFormatParser

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

class fscanf(ScanfFormatParser):
    #pylint:disable=arguments-differ

    def run(self, file_ptr, fmt):  # pylint:disable=unused-argument
        # TODO handle errors

        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        fmt_str = self._parse(fmt)
        items = fmt_str.interpret(self.va_arg, simfd=simfd)
        return items
