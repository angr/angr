# pylint:disable=line-too-long
import logging
from collections import OrderedDict

from ...sim_type import (SimTypeFunction,
    SimTypeShort,
    SimTypeInt,
    SimTypeLong,
    SimTypeLongLong,
    SimTypeDouble,
    SimTypeFloat,
    SimTypePointer,
    SimTypeChar,
    SimStruct,
    SimTypeArray,
    SimTypeBottom,
    SimUnion,
    SimTypeBool,
    SimTypeRef,
)
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.type_collection_names = ["win32"]
lib.set_default_cc("X86", SimCCStdcall)
lib.set_default_cc("AMD64", SimCCMicrosoftAMD64)
lib.set_library_names("version.dll")
prototypes = \
    {
        #
        'VerFindFileA': SimTypeFunction([SimTypeInt(signed=False, label="VER_FIND_FILE_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="VER_FIND_FILE_STATUS"), arg_names=["uFlags", "szFileName", "szWinDir", "szAppDir", "szCurDir", "puCurDirLen", "szDestDir", "puDestDirLen"]),
        #
        'VerFindFileW': SimTypeFunction([SimTypeInt(signed=False, label="VER_FIND_FILE_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="VER_FIND_FILE_STATUS"), arg_names=["uFlags", "szFileName", "szWinDir", "szAppDir", "szCurDir", "puCurDirLen", "szDestDir", "puDestDirLen"]),
        #
        'VerInstallFileA': SimTypeFunction([SimTypeInt(signed=False, label="VER_INSTALL_FILE_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="VER_INSTALL_FILE_STATUS"), arg_names=["uFlags", "szSrcFileName", "szDestFileName", "szSrcDir", "szDestDir", "szCurDir", "szTmpFile", "puTmpFileLen"]),
        #
        'VerInstallFileW': SimTypeFunction([SimTypeInt(signed=False, label="VER_INSTALL_FILE_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="VER_INSTALL_FILE_STATUS"), arg_names=["uFlags", "szSrcFileName", "szDestFileName", "szSrcDir", "szDestDir", "szCurDir", "szTmpFile", "puTmpFileLen"]),
        #
        'GetFileVersionInfoSizeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lptstrFilename", "lpdwHandle"]),
        #
        'GetFileVersionInfoSizeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lptstrFilename", "lpdwHandle"]),
        #
        'GetFileVersionInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lptstrFilename", "dwHandle", "dwLen", "lpData"]),
        #
        'GetFileVersionInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lptstrFilename", "dwHandle", "dwLen", "lpData"]),
        #
        'GetFileVersionInfoSizeExA': SimTypeFunction([SimTypeInt(signed=False, label="GET_FILE_VERSION_INFO_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwFlags", "lpwstrFilename", "lpdwHandle"]),
        #
        'GetFileVersionInfoSizeExW': SimTypeFunction([SimTypeInt(signed=False, label="GET_FILE_VERSION_INFO_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwFlags", "lpwstrFilename", "lpdwHandle"]),
        #
        'GetFileVersionInfoExA': SimTypeFunction([SimTypeInt(signed=False, label="GET_FILE_VERSION_INFO_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "lpwstrFilename", "dwHandle", "dwLen", "lpData"]),
        #
        'GetFileVersionInfoExW': SimTypeFunction([SimTypeInt(signed=False, label="GET_FILE_VERSION_INFO_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "lpwstrFilename", "dwHandle", "dwLen", "lpData"]),
        #
        'VerQueryValueA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBlock", "lpSubBlock", "lplpBuffer", "puLen"]),
        #
        'VerQueryValueW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBlock", "lpSubBlock", "lplpBuffer", "puLen"]),
    }

lib.set_prototypes(prototypes)
