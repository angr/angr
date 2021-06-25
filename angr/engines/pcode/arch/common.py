from archinfo.arch import Arch
from archinfo.tls import TLSArchInfo


class ArchPcode(Arch):
    """
    A generic architecture for architectures supported by pypcode, but not yet
    explicitly defined in archinfo. Provides minimal architectural info like
    register file map, endianness, bit width, etc.
    """
    initial_sp = 0x7fff # FIXME
    sizeof = {'short': 16, 'int': 32, 'long': 32, 'long long': 64}
    elf_tls = TLSArchInfo(1, 8, [], [0], [], 0, 0)
