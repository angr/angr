"""
These procedures implement functions described in the C standard library specification
"""

from angr.errors import SimProcedureError

#
# Here, we define a specific structure (part of it at least) for the FILE structure.
# These offsets are copied from glibc for maximum compatibility, but we are effectively
# implementing SOME libc with these procedures, so we need SOME implementation of FILE.
#
_IO_FILE = {
    'MIPS32': {
        'size': 148,
        'fd': 0x38,
    },
    'X86': {
        'size': 148,
        'fd': 0x38,
    },
    'AMD64': {
        'size': 216,
        'fd': 0x70,
    },
# Bionic libc does not use __IO_FILE
# Refer to http://androidxref.com/5.1.1_r6/xref/bionic/libc/include/stdio.h
# __sFILE replaces __IO_FILE
# _file replaces _fileno
    'ARM': {
        'size': 84,
        'fd': 0x0e,
    },
    'AARCH64': {
        'size': 152,
        'fd': 0x14,
    },
}

_IO_FILE['ARMEL'] = _IO_FILE['ARM']
_IO_FILE['ARMHF'] = _IO_FILE['ARM']


def io_file_data_for_arch(arch):
    """
    A wrapper to get the _IO_FILE data for an architecture
    """
    if arch.name not in _IO_FILE:
        raise SimProcedureError("missing _IO_FILE offsets for arch: %s" % arch.name)
    return _IO_FILE[arch.name]
