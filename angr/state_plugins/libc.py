from .plugin import SimStatePlugin


class SimStateLibc(SimStatePlugin):
    """
    This state plugin keeps track of various libc stuff:
    """

    # __slots__ = [ 'heap_location', 'max_str_symbolic_bytes' ]

    LOCALE_ARRAY = [
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0x80
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0x86
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0x8c
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0x92
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0x98
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0x9e
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xa4
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xaa
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xb0
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xb6
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xbc
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xc2
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xc8
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xce
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xd4
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xda
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xe0
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xe6
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xec
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xf2
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xf8
        b"\000\000",
        b"\000\000",
        b"\002\000",
        b"\002\000",
        b"\002\000",
        b"\002\000",  # 0xfe
        b"\002\000",
        b"\002\000",
        b"\002\000",
        b"\002\000",
        b"\002\000",
        b"\003\040",  # 0x04
        b"\002\040",
        b"\002\040",
        b"\002\040",
        b"\002\040",
        b"\002\000",
        b"\002\000",  # 0x0a
        b"\002\000",
        b"\002\000",
        b"\002\000",
        b"\002\000",
        b"\002\000",
        b"\002\000",  # 0x10
        b"\002\000",
        b"\002\000",
        b"\002\000",
        b"\002\000",
        b"\002\000",
        b"\002\000",  # 0x16
        b"\002\000",
        b"\002\000",
        b"\002\000",
        b"\002\000",
        b"\001\140",
        b"\004\300",  # 0x1c
        b"\004\300",
        b"\004\300",
        b"\004\300",
        b"\004\300",
        b"\004\300",
        b"\004\300",  # 0x22
        b"\004\300",
        b"\004\300",
        b"\004\300",
        b"\004\300",
        b"\004\300",
        b"\004\300",  # 0x28
        b"\004\300",
        b"\004\300",
        b"\010\330",
        b"\010\330",
        b"\010\330",
        b"\010\330",  # 0x2e
        b"\010\330",
        b"\010\330",
        b"\010\330",
        b"\010\330",
        b"\010\330",
        b"\010\330",  # 0x34
        b"\004\300",
        b"\004\300",
        b"\004\300",
        b"\004\300",
        b"\004\300",
        b"\004\300",  # 0x3a
        b"\004\300",
        b"\010\325",
        b"\010\325",
        b"\010\325",
        b"\010\325",
        b"\010\325",  # 0x40
        b"\010\325",
        b"\010\305",
        b"\010\305",
        b"\010\305",
        b"\010\305",
        b"\010\305",  # 0x46
        b"\010\305",
        b"\010\305",
        b"\010\305",
        b"\010\305",
        b"\010\305",
        b"\010\305",  # 0x4c
        b"\010\305",
        b"\010\305",
        b"\010\305",
        b"\010\305",
        b"\010\305",
        b"\010\305",  # 0x52
        b"\010\305",
        b"\010\305",
        b"\010\305",
        b"\004\300",
        b"\004\300",
        b"\004\300",  # 0x58
        b"\004\300",
        b"\004\300",
        b"\004\300",
        b"\010\326",
        b"\010\326",
        b"\010\326",  # 0x5e
        b"\010\326",
        b"\010\326",
        b"\010\326",
        b"\010\306",
        b"\010\306",
        b"\010\306",  # 0x64
        b"\010\306",
        b"\010\306",
        b"\010\306",
        b"\010\306",
        b"\010\306",
        b"\010\306",  # 0x6a
        b"\010\306",
        b"\010\306",
        b"\010\306",
        b"\010\306",
        b"\010\306",
        b"\010\306",  # 0x70
        b"\010\306",
        b"\010\306",
        b"\010\306",
        b"\010\306",
        b"\010\306",
        b"\004\300",  # 0x76
        b"\004\300",
        b"\004\300",
        b"\004\300",
        b"\002\000",
        b"\000\000",
        b"\000\000",  # 0x7c
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0x82
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0x88
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0x8e
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0x94
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0x9a
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xa0
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xa6
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xac
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xb2
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xb8
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xbe
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xc4
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xca
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xd0
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xd6
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xdc
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xe2
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xe8
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xee
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xf4
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",
        b"\000\000",  # 0xfa
    ]

    TOLOWER_LOC_ARRAY = [
        0x80,
        0x81,
        0x82,
        0x83,
        0x84,
        0x85,
        0x86,
        0x87,  # 0x80
        0x88,
        0x89,
        0x8A,
        0x8B,
        0x8C,
        0x8D,
        0x8E,
        0x8F,  # 0x88
        0x90,
        0x91,
        0x92,
        0x93,
        0x94,
        0x95,
        0x96,
        0x97,  # 0x90
        0x98,
        0x99,
        0x9A,
        0x9B,
        0x9C,
        0x9D,
        0x9E,
        0x9F,  # 0x98
        0xA0,
        0xA1,
        0xA2,
        0xA3,
        0xA4,
        0xA5,
        0xA6,
        0xA7,  # 0xa0
        0xA8,
        0xA9,
        0xAA,
        0xAB,
        0xAC,
        0xAD,
        0xAE,
        0xAF,  # 0xa8
        0xB0,
        0xB1,
        0xB2,
        0xB3,
        0xB4,
        0xB5,
        0xB6,
        0xB7,  # 0xb0
        0xB8,
        0xB9,
        0xBA,
        0xBB,
        0xBC,
        0xBD,
        0xBE,
        0xBF,  # 0xb8
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC4,
        0xC5,
        0xC6,
        0xC7,  # 0xc0
        0xC8,
        0xC9,
        0xCA,
        0xCB,
        0xCC,
        0xCD,
        0xCE,
        0xCF,  # 0xc8
        0xD0,
        0xD1,
        0xD2,
        0xD3,
        0xD4,
        0xD5,
        0xD6,
        0xD7,  # 0xd0
        0xD8,
        0xD9,
        0xDA,
        0xDB,
        0xDC,
        0xDD,
        0xDE,
        0xDF,  # 0xd8
        0xE0,
        0xE1,
        0xE2,
        0xE3,
        0xE4,
        0xE5,
        0xE6,
        0xE7,  # 0xe0
        0xE8,
        0xE9,
        0xEA,
        0xEB,
        0xEC,
        0xED,
        0xEE,
        0xEF,  # 0xe8
        0xF0,
        0xF1,
        0xF2,
        0xF3,
        0xF4,
        0xF5,
        0xF6,
        0xF7,  # 0xf0
        0xF8,
        0xF9,
        0xFA,
        0xFB,
        0xFC,
        0xFD,
        0xFE,
        0xFFFFFFFF,  # 0xf8
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,  # 0x00
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,  # 0x08
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,  # 0x10
        0x18,
        0x19,
        0x1A,
        0x1B,
        0x1C,
        0x1D,
        0x1E,
        0x1F,  # 0x18
        0x20,
        0x21,
        0x22,
        0x23,
        0x24,
        0x25,
        0x26,
        0x27,  # 0x20
        0x28,
        0x29,
        0x2A,
        0x2B,
        0x2C,
        0x2D,
        0x2E,
        0x2F,  # 0x28
        0x30,
        0x31,
        0x32,
        0x33,
        0x34,
        0x35,
        0x36,
        0x37,  # 0x30
        0x38,
        0x39,
        0x3A,
        0x3B,
        0x3C,
        0x3D,
        0x3E,
        0x3F,  # 0x38
        0x40,
        0x61,
        0x62,
        0x63,
        0x64,
        0x65,
        0x66,
        0x67,  # 0x40
        0x68,
        0x69,
        0x6A,
        0x6B,
        0x6C,
        0x6D,
        0x6E,
        0x6F,  # 0x48
        0x70,
        0x71,
        0x72,
        0x73,
        0x74,
        0x75,
        0x76,
        0x77,  # 0x50
        0x78,
        0x79,
        0x7A,
        0x5B,
        0x5C,
        0x5D,
        0x5E,
        0x5F,  # 0x58
        0x60,
        0x61,
        0x62,
        0x63,
        0x64,
        0x65,
        0x66,
        0x67,  # 0x60
        0x68,
        0x69,
        0x6A,
        0x6B,
        0x6C,
        0x6D,
        0x6E,
        0x6F,  # 0x68
        0x70,
        0x71,
        0x72,
        0x73,
        0x74,
        0x75,
        0x76,
        0x77,  # 0x70
        0x78,
        0x79,
        0x7A,
        0x7B,
        0x7C,
        0x7D,
        0x7E,
        0x7F,  # 0x78
        0x80,
        0x81,
        0x82,
        0x83,
        0x84,
        0x85,
        0x86,
        0x87,  # 0x80
        0x88,
        0x89,
        0x8A,
        0x8B,
        0x8C,
        0x8D,
        0x8E,
        0x8F,  # 0x88
        0x90,
        0x91,
        0x92,
        0x93,
        0x94,
        0x95,
        0x96,
        0x97,  # 0x90
        0x98,
        0x99,
        0x9A,
        0x9B,
        0x9C,
        0x9D,
        0x9E,
        0x9F,  # 0x98
        0xA0,
        0xA1,
        0xA2,
        0xA3,
        0xA4,
        0xA5,
        0xA6,
        0xA7,  # 0xa0
        0xA8,
        0xA9,
        0xAA,
        0xAB,
        0xAC,
        0xAD,
        0xAE,
        0xAF,  # 0xa8
        0xB0,
        0xB1,
        0xB2,
        0xB3,
        0xB4,
        0xB5,
        0xB6,
        0xB7,  # 0xb0
        0xB8,
        0xB9,
        0xBA,
        0xBB,
        0xBC,
        0xBD,
        0xBE,
        0xBF,  # 0xb8
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC4,
        0xC5,
        0xC6,
        0xC7,  # 0xc0
        0xC8,
        0xC9,
        0xCA,
        0xCB,
        0xCC,
        0xCD,
        0xCE,
        0xCF,  # 0xc8
        0xD0,
        0xD1,
        0xD2,
        0xD3,
        0xD4,
        0xD5,
        0xD6,
        0xD7,  # 0xd0
        0xD8,
        0xD9,
        0xDA,
        0xDB,
        0xDC,
        0xDD,
        0xDE,
        0xDF,  # 0xd8
        0xE0,
        0xE1,
        0xE2,
        0xE3,
        0xE4,
        0xE5,
        0xE6,
        0xE7,  # 0xe0
        0xE8,
        0xE9,
        0xEA,
        0xEB,
        0xEC,
        0xED,
        0xEE,
        0xEF,  # 0xe8
        0xF0,
        0xF1,
        0xF2,
        0xF3,
        0xF4,
        0xF5,
        0xF6,
        0xF7,  # 0xf0
        0xF8,
        0xF9,
        0xFA,
        0xFB,
        0xFC,
        0xFD,
        0xFE,
        0xFF,  # 0xf8
    ]

    TOUPPER_LOC_ARRAY = [
        0x80,
        0x81,
        0x82,
        0x83,
        0x84,
        0x85,
        0x86,
        0x87,  # 0x80
        0x88,
        0x89,
        0x8A,
        0x8B,
        0x8C,
        0x8D,
        0x8E,
        0x8F,  # 0x88
        0x90,
        0x91,
        0x92,
        0x93,
        0x94,
        0x95,
        0x96,
        0x97,  # 0x90
        0x98,
        0x99,
        0x9A,
        0x9B,
        0x9C,
        0x9D,
        0x9E,
        0x9F,  # 0x98
        0xA0,
        0xA1,
        0xA2,
        0xA3,
        0xA4,
        0xA5,
        0xA6,
        0xA7,  # 0xa0
        0xA8,
        0xA9,
        0xAA,
        0xAB,
        0xAC,
        0xAD,
        0xAE,
        0xAF,  # 0xa8
        0xB0,
        0xB1,
        0xB2,
        0xB3,
        0xB4,
        0xB5,
        0xB6,
        0xB7,  # 0xb0
        0xB8,
        0xB9,
        0xBA,
        0xBB,
        0xBC,
        0xBD,
        0xBE,
        0xBF,  # 0xb8
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC4,
        0xC5,
        0xC6,
        0xC7,  # 0xc0
        0xC8,
        0xC9,
        0xCA,
        0xCB,
        0xCC,
        0xCD,
        0xCE,
        0xCF,  # 0xc8
        0xD0,
        0xD1,
        0xD2,
        0xD3,
        0xD4,
        0xD5,
        0xD6,
        0xD7,  # 0xd0
        0xD8,
        0xD9,
        0xDA,
        0xDB,
        0xDC,
        0xDD,
        0xDE,
        0xDF,  # 0xd8
        0xE0,
        0xE1,
        0xE2,
        0xE3,
        0xE4,
        0xE5,
        0xE6,
        0xE7,  # 0xe0
        0xE8,
        0xE9,
        0xEA,
        0xEB,
        0xEC,
        0xED,
        0xEE,
        0xEF,  # 0xe8
        0xF0,
        0xF1,
        0xF2,
        0xF3,
        0xF4,
        0xF5,
        0xF6,
        0xF7,  # 0xf0
        0xF8,
        0xF9,
        0xFA,
        0xFB,
        0xFC,
        0xFD,
        0xFE,
        0xFFFFFFFF,  # 0xf8
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,  # 0x00
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,  # 0x08
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,  # 0x10
        0x18,
        0x19,
        0x1A,
        0x1B,
        0x1C,
        0x1D,
        0x1E,
        0x1F,  # 0x18
        0x20,
        0x21,
        0x22,
        0x23,
        0x24,
        0x25,
        0x26,
        0x27,  # 0x20
        0x28,
        0x29,
        0x2A,
        0x2B,
        0x2C,
        0x2D,
        0x2E,
        0x2F,  # 0x28
        0x30,
        0x31,
        0x32,
        0x33,
        0x34,
        0x35,
        0x36,
        0x37,  # 0x30
        0x38,
        0x39,
        0x3A,
        0x3B,
        0x3C,
        0x3D,
        0x3E,
        0x3F,  # 0x38
        0x40,
        0x41,
        0x42,
        0x43,
        0x44,
        0x45,
        0x46,
        0x47,  # 0x40
        0x48,
        0x49,
        0x4A,
        0x4B,
        0x4C,
        0x4D,
        0x4E,
        0x4F,  # 0x48
        0x50,
        0x51,
        0x52,
        0x53,
        0x54,
        0x55,
        0x56,
        0x57,  # 0x50
        0x58,
        0x59,
        0x5A,
        0x5B,
        0x5C,
        0x5D,
        0x5E,
        0x5F,  # 0x58
        0x60,
        0x41,
        0x42,
        0x43,
        0x44,
        0x45,
        0x46,
        0x47,  # 0x60
        0x48,
        0x49,
        0x4A,
        0x4B,
        0x4C,
        0x4D,
        0x4E,
        0x4F,  # 0x68
        0x50,
        0x51,
        0x52,
        0x53,
        0x54,
        0x55,
        0x56,
        0x57,  # 0x70
        0x58,
        0x59,
        0x5A,
        0x7B,
        0x7C,
        0x7D,
        0x7E,
        0x7F,  # 0x78
        0x80,
        0x81,
        0x82,
        0x83,
        0x84,
        0x85,
        0x86,
        0x87,  # 0x80
        0x88,
        0x89,
        0x8A,
        0x8B,
        0x8C,
        0x8D,
        0x8E,
        0x8F,  # 0x88
        0x90,
        0x91,
        0x92,
        0x93,
        0x94,
        0x95,
        0x96,
        0x97,  # 0x90
        0x98,
        0x99,
        0x9A,
        0x9B,
        0x9C,
        0x9D,
        0x9E,
        0x9F,  # 0x98
        0xA0,
        0xA1,
        0xA2,
        0xA3,
        0xA4,
        0xA5,
        0xA6,
        0xA7,  # 0xa0
        0xA8,
        0xA9,
        0xAA,
        0xAB,
        0xAC,
        0xAD,
        0xAE,
        0xAF,  # 0xa8
        0xB0,
        0xB1,
        0xB2,
        0xB3,
        0xB4,
        0xB5,
        0xB6,
        0xB7,  # 0xb0
        0xB8,
        0xB9,
        0xBA,
        0xBB,
        0xBC,
        0xBD,
        0xBE,
        0xBF,  # 0xb8
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC4,
        0xC5,
        0xC6,
        0xC7,  # 0xc0
        0xC8,
        0xC9,
        0xCA,
        0xCB,
        0xCC,
        0xCD,
        0xCE,
        0xCF,  # 0xc8
        0xD0,
        0xD1,
        0xD2,
        0xD3,
        0xD4,
        0xD5,
        0xD6,
        0xD7,  # 0xd0
        0xD8,
        0xD9,
        0xDA,
        0xDB,
        0xDC,
        0xDD,
        0xDE,
        0xDF,  # 0xd8
        0xE0,
        0xE1,
        0xE2,
        0xE3,
        0xE4,
        0xE5,
        0xE6,
        0xE7,  # 0xe0
        0xE8,
        0xE9,
        0xEA,
        0xEB,
        0xEC,
        0xED,
        0xEE,
        0xEF,  # 0xe8
        0xF0,
        0xF1,
        0xF2,
        0xF3,
        0xF4,
        0xF5,
        0xF6,
        0xF7,  # 0xf0
        0xF8,
        0xF9,
        0xFA,
        0xFB,
        0xFC,
        0xFD,
        0xFE,
        0xFF,  # 0xf8
    ]

    def __init__(self):
        SimStatePlugin.__init__(self)

        # various thresholds
        self.buf_symbolic_bytes = 60
        self.max_symbolic_strstr = 1
        self.max_symbolic_strchr = 16
        self.max_variable_size = 128
        self.max_str_len = 128
        self.max_buffer_size = 48
        self.max_strtol_len = 11  # len(str(2**31)) + 1
        self.max_memcpy_size = 4096
        self.max_packet_size = 256
        self.max_gets_size = 256

        # strtok
        self.strtok_heap = []
        self.simple_strtok = True
        self.strtok_token_size = 1024

        # helpful stuff
        self.strdup_stack = []

        # as per Audrey:
        # the idea is that there's two abi versions, and for one of them, the
        # address passed to libc_start_main isn't actually the address of the
        # function, but the address of a pointer to a struct containing the
        # actual function address and the table of contents address
        self.ppc64_abiv = None

        # It will be initialized in __libc_start_main SimProcedure
        self.ctype_b_loc_table_ptr = None
        self.ctype_tolower_loc_table_ptr = None
        self.ctype_toupper_loc_table_ptr = None

        self.errno_location = None

    @SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        o = super().copy(memo)
        o.buf_symbolic_bytes = self.buf_symbolic_bytes
        o.max_symbolic_strstr = self.max_symbolic_strstr
        o.max_symbolic_strchr = self.max_symbolic_strchr
        o.max_variable_size = self.max_variable_size
        o.max_str_len = self.max_str_len
        o.max_buffer_size = self.max_buffer_size
        o.max_strtol_len = self.max_strtol_len
        o.max_memcpy_size = self.max_memcpy_size
        o.max_packet_size = self.max_packet_size
        o.max_gets_size = self.max_gets_size
        o.strtok_heap = self.strtok_heap[:]
        o.simple_strtok = self.simple_strtok
        o.strtok_token_size = self.strtok_token_size
        o.strdup_stack = self.strdup_stack[:]
        o.ppc64_abiv = self.ppc64_abiv
        o.ctype_b_loc_table_ptr = self.ctype_b_loc_table_ptr
        o.ctype_tolower_loc_table_ptr = self.ctype_tolower_loc_table_ptr
        o.ctype_toupper_loc_table_ptr = self.ctype_toupper_loc_table_ptr
        o.errno_location = self.errno_location

        return o

    def merge(self, others, merge_conditions, common_ancestor=None):  # pylint: disable=unused-argument
        return False

    def widen(self, others):
        return False

    @property
    def errno(self):
        return self.state.mem[self.errno_location].int.resolved

    @errno.setter
    def errno(self, val):
        self.state.mem[self.errno_location].int = val

    def ret_errno(self, val):
        try:
            ival = getattr(self.state.posix, val)
        except AttributeError as e:
            raise ValueError("Invalid errno constant %s" % val) from e

        if self.state.scratch.sim_procedure.is_syscall:
            return -ival
        else:
            self.errno = ival
            return -1


from angr.sim_state import SimState

SimState.register_default("libc", SimStateLibc)
