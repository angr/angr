# pylint:disable=missing-class-docstring
from __future__ import annotations
from enum import Enum


class FlirtArch(int, Enum):
    ARCH_386 = 0  # Intel 80x86
    ARCH_Z80 = 1  # 8085, Z80
    ARCH_I860 = 2  # Intel 860
    ARCH_8051 = 3  # 8051
    ARCH_TMS = 4  # Texas Instruments TMS320C5x
    ARCH_6502 = 5  # 6502
    ARCH_PDP = 6  # PDP11
    ARCH_68K = 7  # Motorola 680x0
    ARCH_JAVA = 8  # Java
    ARCH_6800 = 9  # Motorola 68xx
    ARCH_ST7 = 10  # SGS-Thomson ST7
    ARCH_MC6812 = 11  # Motorola 68HC12
    ARCH_MIPS = 12  # MIPS
    ARCH_ARM = 13  # Advanced RISC Machines
    ARCH_TMSC6 = 14  # Texas Instruments TMS320C6x
    ARCH_PPC = 15  # PowerPC
    ARCH_80196 = 16  # Intel 80196
    ARCH_Z8 = 17  # Z8
    ARCH_SH = 18  # Renesas (formerly Hitachi) SuperH
    ARCH_NET = 19  # Microsoft Visual Studio.Net
    ARCH_AVR = 20  # Atmel 8-bit RISC processor(s)
    ARCH_H8 = 21  # Hitachi H8/300, H8/2000
    ARCH_PIC = 22  # Microchip's PIC
    ARCH_SPARC = 23  # SPARC
    ARCH_ALPHA = 24  # DEC Alpha
    ARCH_HPPA = 25  # Hewlett-Packard PA-RISC
    ARCH_H8500 = 26  # Hitachi H8/500
    ARCH_TRICORE = 27  # Tasking Tricore
    ARCH_DSP56K = 28  # Motorola DSP5600x
    ARCH_C166 = 29  # Siemens C166 family
    ARCH_ST20 = 30  # SGS-Thomson ST20
    ARCH_IA64 = 31  # Intel Itanium IA64
    ARCH_I960 = 32  # Intel 960
    ARCH_F2MC = 33  # Fujitsu F2MC-16
    ARCH_TMS320C54 = 34  # Texas Instruments TMS320C54xx
    ARCH_TMS320C55 = 35  # Texas Instruments TMS320C55xx
    ARCH_TRIMEDIA = 36  # Trimedia
    ARCH_M32R = 37  # Mitsubishi 32bit RISC
    ARCH_NEC_78K0 = 38  # NEC 78K0
    ARCH_NEC_78K0S = 39  # NEC 78K0S
    ARCH_M740 = 40  # Mitsubishi 8bit
    ARCH_M7700 = 41  # Mitsubishi 16bit
    ARCH_ST9 = 42  # ST9+
    ARCH_FR = 43  # Fujitsu FR Family
    ARCH_MC6816 = 44  # Motorola 68HC16
    ARCH_M7900 = 45  # Mitsubishi 7900
    ARCH_TMS320C3 = 46  # Texas Instruments TMS320C3
    ARCH_KR1878 = 47  # Angstrem KR1878
    ARCH_AD218X = 48  # Analog Devices ADSP 218X
    ARCH_OAKDSP = 49  # Atmel OAK DSP
    ARCH_TLCS900 = 50  # Toshiba TLCS-900
    ARCH_C39 = 51  # Rockwell C39
    ARCH_CR16 = 52  # NSC CR16
    ARCH_MN102L00 = 53  # Panasonic MN10200
    ARCH_TMS320C1X = 54  # Texas Instruments TMS320C1x
    ARCH_NEC_V850X = 55  # NEC V850 and V850ES/E1/E2
    ARCH_SCR_ADPT = 56  # Processor module adapter for processor modules written in scripting languages
    ARCH_EBC = 57  # EFI Bytecode
    ARCH_MSP430 = 58  # Texas Instruments MSP430
    ARCH_SPU = 59  # Cell Broadband Engine Synergistic Processor Unit
    ARCH_DALVIK = 60  # Android Dalvik Virtual Machine


FLIRT_ARCH_TO_ARCHNAME: dict[int, dict[int, str]] = {
    FlirtArch.ARCH_386: {32: "X86", 64: "AMD64"},
    FlirtArch.ARCH_MIPS: {32: "MIPS32", 64: "MIPS64"},
    FlirtArch.ARCH_ARM: {32: "ARM", 64: "AARCH64"},
    FlirtArch.ARCH_PPC: {32: "PPC32", 64: "PPC64"},
    FlirtArch.ARCH_SPARC: {32: "SPARC32", 64: "SPARC64"},
}


class FlirtFileType(int, Enum):
    FILE_DOS_EXE_OLD = 0x00000001
    FILE_DOS_COM_OLD = 0x00000002
    FILE_BIN = 0x00000004
    FILE_DOSDRV = 0x00000008
    FILE_NE = 0x00000010
    FILE_INTELHEX = 0x00000020
    FILE_MOSHEX = 0x00000040
    FILE_LX = 0x00000080
    FILE_LE = 0x00000100
    FILE_NLM = 0x00000200
    FILE_COFF = 0x00000400
    FILE_PE = 0x00000800
    FILE_OMF = 0x00001000
    FILE_SREC = 0x00002000
    FILE_ZIP = 0x00004000
    FILE_OMFLIB = 0x00008000
    FILE_AR = 0x00010000
    FILE_LOADER = 0x00020000
    FILE_ELF = 0x00040000
    FILE_W32RUN = 0x00080000
    FILE_AOUT = 0x00100000
    FILE_PILOT = 0x00200000
    FILE_DOS_EXE = 0x00400000
    FILE_DOS_COM = 0x00800000
    FILE_AIXAR = 0x01000000


class FlirtOSType(int, Enum):
    """
    Actually no longer used in IDA.
    """

    OS_MSDOS = 0x01
    OS_WIN = 0x02
    OS_OS2 = 0x04
    OS_NETWARE = 0x08
    OS_UNIX = 0x10
    OS_OTHER = 0x20


FLIRT_OS_TO_OSNAME = {
    FlirtOSType.OS_MSDOS: "MSDOS",
    FlirtOSType.OS_WIN: "Win32",
    FlirtOSType.OS_OS2: "OS/2",
    FlirtOSType.OS_UNIX: "Linux",
    FlirtOSType.OS_OTHER: "Other",
}


class FlirtAppType(int, Enum):
    APP_CONSOLE = 0x0001
    APP_GRAPHICS = 0x0002
    APP_EXE = 0x0004
    APP_DLL = 0x0008
    APP_DRV = 0x0010
    APP_SINGLE_THREADED = 0x0020
    APP_MULTI_THREADED = 0x0040
    APP_16_BIT = 0x0080
    APP_32_BIT = 0x0100
    APP_64_BIT = 0x0200


class FlirtFeatureFlag(int, Enum):
    FEATURE_STARTUP = 0x1
    FEATURE_CTYPE_CRC = 0x2
    FEATURE_2BYTE_CTYPE = 0x4
    FEATURE_ALT_CTYPE_CRC = 0x8
    FEATURE_COMPRESSED = 0x10


class FlirtParseFlag(int, Enum):
    PARSE_MORE_PUBLIC_NAMES = 0x1
    PARSE_READ_TAIL_BYTES = 0x2
    PARSE_READ_REFERENCED_FUNCTIONS = 0x4
    PARSE_MORE_MODULES_WITH_SAME_CRC = 0x8
    PARSE_MORE_MODULES = 0x10


class FlirtFunctionFlag(int, Enum):
    FUNCTION_LOCAL = 0x2
    FUNCTION_UNRESOLVED_COLLISION = 0x8
