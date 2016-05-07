
#
# offsets in struct _IO_FILE
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
