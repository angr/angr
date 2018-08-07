import angr

from ..stubs.format_parser import FormatParser

#pylint:disable=arguments-differ,unused-argument

#
# Here, we define a specific structure (part of it at least) for the FILE structure.
# These offsets are copied from glibc for maximum compatibility, but we are effectively
# implementing SOME libc with these procedures, so we need SOME implementation of FILE.
#
# with the exception of ungetc. we're just making this stuff up now.
#
_IO_FILE = {
    'MIPS32': {
        'fd': 0x38,
        'ungetc': 0x40,
        'size': 0x94,
    },
    'X86': {
        'fd': 0x38,
        'ungetc': 0x40,
        'size': 0x94,
    },
    'AMD64': {
        'fd': 0x70,
        'ungetc': 0x78,
        'size': 0xd8,
    },
    # Bionic libc does not use __IO_FILE
    # Refer to http://androidxref.com/5.1.1_r6/xref/bionic/libc/include/stdio.h
    # __sFILE replaces __IO_FILE
    # _file replaces _fileno
    'ARM': {
        'fd': 0x0e,
        'ungetc': 0x20,
        'size': 0x54,
    },
    'AARCH64': {
        'fd': 0x14,
        'ungetc': 0x20,
        'size': 0x98,
    },
}

_IO_FILE['ARMEL'] = _IO_FILE['ARM']
_IO_FILE['ARMHF'] = _IO_FILE['ARM']


def io_file_data_for_arch(arch):
    """
    A wrapper to get the _IO_FILE data for an architecture
    """
    if arch.name not in _IO_FILE:
        raise angr.errors.SimProcedureError("missing _IO_FILE offsets for arch: %s" % arch.name)
    return _IO_FILE[arch.name]


def mode_to_flag(mode):
    # TODO improve this: handle mode = strings
    if mode[-1] == 'b': # lol who uses windows
        mode = mode[:-1]
    all_modes = {
        "r"  : angr.storage.file.Flags.O_RDONLY,
        "r+" : angr.storage.file.Flags.O_RDWR,
        "w"  : angr.storage.file.Flags.O_WRONLY | angr.storage.file.Flags.O_CREAT,
        "w+" : angr.storage.file.Flags.O_RDWR | angr.storage.file.Flags.O_CREAT,
        "a"  : angr.storage.file.Flags.O_WRONLY | angr.storage.file.Flags.O_CREAT | angr.storage.file.Flags.O_APPEND,
        "a+" : angr.storage.file.Flags.O_RDWR | angr.storage.file.Flags.O_CREAT | angr.storage.file.Flags.O_APPEND
    }
    if mode not in all_modes:
        raise angr.SimProcedureError('unsupported file open mode %s' % mode)

    return all_modes[mode]


class FILE(object):
    def __init__(self, state, ptr):
        self.state = state
        self.ptr = ptr
        self.offsets = io_file_data_for_arch(state.arch.name)

    @staticmethod
    def max_size(arch):
        offsets = io_file_data_for_arch(arch)
        return offsets['size']

    @property
    def fd(self):
        return self.state.mem[self.offsets['fd']].int.resolved
    @fd.setter
    def fd(self, val):
        self.state.mem[self.offsets['fd']].int = val

    @property
    def ungetc(self):
        if self.state.solver.is_true(self.state.mem[self.offsets['ungetc'] + 1].char.resolved == 0):
            return None
        return self.state.mem[self.offsets['ungetc']].char.resolved
    @ungetc.setter
    def ungetc(self, val):
        if val is None:
            self.state.mem[self.offsets['ungetc'] + 1].char = 0
        else:
            self.state.mem[self.offsets['ungetc'] + 1].char = 1
            self.state.mem[self.offsets['ungetc']].char = val


class FileProcedure(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super(FileProcedure, self).__init__(*args, **kwargs)

        self._stdin_addr = self._get_addr('stdin')
        self._stdout_addr = self._get_addr('stdin')
        self._stderr_addr = self._get_addr('stdin')

    def get_file(self, ptr):
        return FILE(self.state, ptr)

    def _get_addr(self, name):
        if self.project is None:
            return None
        symbol = self.project.loader.find_symbol(name)
        if symbol is None:
            size = FILE.max_size(self.project.arch)
            symbol = self.project.loader.extern_object.make_extern(name, size=size)
        return symbol.rebased_addr

    @property
    def stdin_addr(self):
        if self._stdin_addr is None:
            self._stdin_addr = self._get_addr('stdin')
        return self.get_file(self._stdin_addr)

    @property
    def stdout_addr(self):
        if self._stdout_addr is None:
            self._stdout_addr = self._get_addr('stdout')
        return self.get_file(self._stdout_addr)

    @property
    def stderr_addr(self):
        if self._stderr_addr is None:
            self._stderr_addr = self._get_addr('stderr')
        return self._stderr_addr


#####
# Management procedures
#####

class fopen(FileProcedure):
    def run(self, p_addr, m_addr):
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        p_strlen = self.inline_call(strlen, p_addr)
        m_strlen = self.inline_call(strlen, m_addr)
        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness='Iend_BE')
        m_expr = self.state.memory.load(m_addr, m_strlen.max_null_index, endness='Iend_BE')
        path = self.state.se.eval(p_expr, cast_to=str)
        mode = self.state.se.eval(m_expr, cast_to=str)

        # TODO: handle append
        fd = self.state.posix.open(path, mode_to_flag(mode))

        if fd is None:
            # if open failed return NULL
            return 0
        else:
            # Allocate a FILE struct in heap
            malloc = angr.SIM_PROCEDURES['libc']['malloc']
            ptr = self.inline_call(malloc, FILE.max_size(self.state.arch)).ret_expr
            fp = self.get_file(ptr)
            fp.fd = fd
            fp.ungetc = None
            return ptr


class fclose(FileProcedure):
    def run(self, ptr):
        fp = self.get_file(ptr)
        if self.state.posix.close(fp.fd):
            return 0
        else:
            return -1


class feof(FileProcedure):
    def run(self, ptr):
        fp = self.get_file(ptr)
        simfd = self.state.posix.get_fd(fp.fd)
        if simfd is None:
            return -1
        return self.state.solver.If(simfd.eof(), self.state.solver.BVV(1, self.state.arch.bits), 0)


class fseek(FileProcedure):
    def run(self, file_ptr, offset, whence):
        # Make sure whence can only be one of the three values: SEEK_SET(0), SEEK_CUR(1), and SEEK_END(2)
        try:
            whence = self.state.solver.eval_one(whence)
        except angr.errors.SimSolverError:
            raise angr.SimProcedureError('multi-valued "whence" is not supported in fseek.')

        try:
            whence = {0: 'start', 1: 'current', 2: 'end'}[whence]
        except KeyError:
            return -1 # EINVAL

        fp = self.get_file(file_ptr)
        simfd = self.state.posix.get_fd(fp.fd)
        if simfd is None:
            return -1
        return self.state.solver.If(simfd.seek(offset, whence), self.state.solver.BVV(0, self.state.arch.bits), -1)


class rewind(fseek):
    def run(self, file_ptr):
        return super(rewind, self).run(file_ptr, 0, 0)


class ftell(FileProcedure):
    def run(self, file_ptr):
        fp = self.get_file(file_ptr)
        simfd = self.state.posix.get_fd(fp.fd)
        if simfd is None:
            return -1
        pos = simfd.tell()
        if pos is None:
            return -1
        return pos


######
# Reading procedures
######

class fgets(FileProcedure):
    def run(self, dst, size, file_ptr):
        if self.state.solver.is_true(size == 0):
            return 0
        elif self.state.solver.is_true(size == 1):
            self.state.memory.store(dst, b'\0')
            return 1

        fp = self.get_file(file_ptr)
        simfd = self.state.posix.get_fd(fp.fd)
        if simfd is None:
            return -1

        ungetc = fp.ungetc
        if ungetc is not None:
            fp.ungetc = None
            size -= 1

        # let's get the memory back for the file we're interested in and find the newline
        data, real_size = simfd.read_data(size-1)

        if ungetc is not None:
            data = self.state.solver.Concat(ungetc, data)
            real_size += 1
            size += 1

        for i, byte in enumerate(data.chop(8)):
            self.state.solver.add(self.state.solver.If(
                i+1 != real_size, byte != '\n', # if not last byte returned, not newline
                self.state.solver.Or( # otherwise one of the following must be true
                    i+2 == size, # we ran out of space, or
                    byte == '\n' # it is a newline
                )))

        self.state.memory.store(dst, data, size=real_size)
        self.state.memory.store(dst+real_size, '\0')

        return real_size


class fgetc(FileProcedure):
    def run(self, ptr):
        fp = self.get_file(ptr)
        simfd = self.state.posix.get_fd(fp.fd)
        if simfd is None:
            return -1

        ungetc = fp.ungetc
        if ungetc is not None:
            fp.ungetc = None
            result = ungetc
            real_length = 1
        else:
            result, real_length, = simfd.read_data(1)
        return self.state.solver.If(real_length == 0, -1, result.zero_extend(self.state.arch.bits - 8))

getc = fgetc


class getchar(fgetc):
    def run(self):
        return super(getchar, self).run(self.stdin_addr)


class fread(FileProcedure):
    def run(self, dst, size, nm, file_ptr):
        fp = self.get_file(file_ptr)
        simfd = self.state.posix.get_fd(fp.fd)

        if simfd is None:
            return -1

        ungetc = fp.ungetc
        if ungetc is None:
            ret = simfd.read(dst, size * nm)
        else:
            ret = self.state.solver.Concat(ungetc, simfd.read(dst, size * nm - 1))

        return self.state.se.If(self.state.se.Or(size == 0, nm == 0), 0, ret // size)


class ungetc(FileProcedure):
    def run(self, c, ptr):
        char = c & 0xff
        fp = self.get_file(ptr)
        fp.ungetc = char
        return char


######
# Writing procedures
######

class fflush(angr.SimProcedure):
    def run(self, fd):
        return 0


class fprintf(FileProcedure, FormatParser):
    def run(self, file_ptr):
        fp = self.get_file(file_ptr)
        simfd = self.state.posix.get_fd(fp.fd)
        if simfd is None:
            return -1

        # The format str is at index 1
        fmt_str = self._parse(1)
        out_str = fmt_str.replace(2, self.arg)

        simfd.write_data(out_str, out_str.size() // 8)

        return out_str.size() // 8


class fputc(FileProcedure):
    def run(self, c, ptr):
        fp = self.get_file(ptr)
        simfd = self.state.posix.get_fd(fp.fd)
        if simfd is None:
            return -1

        simfd.write_data(c[7:0])
        return c & 0xff

putc = fputc


class putchar(fputc):
    def run(self, c):
        return super(putchar, self).run(c, self.stdout_addr)


class fputs(FileProcedure):
    def run(self, str_addr, file_ptr):
        fp = self.get_file(file_ptr)
        simfd = self.state.posix.get_fd(fp.fd)
        if simfd is None:
            return -1

        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        p_strlen = self.inline_call(strlen, str_addr)
        simfd.write(str_addr, p_strlen.max_null_index)
        return 1


class puts(FileProcedure):
    def run(self, str_addr):
        return super(puts, self).run(str_addr, self.stdout_addr)


class fwrite(FileProcedure):
    def run(self, src, size, nmemb, file_ptr):
        fp = self.get_file(file_ptr)
        simfd = self.state.posix.get_fd(fp.fd)
        if simfd is None:
            return -1
        return simfd.write(src, size*nmemb)
