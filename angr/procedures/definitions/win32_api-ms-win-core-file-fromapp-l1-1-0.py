# pylint:disable=line-too-long
import logging

from ...sim_type import SimTypeFunction,     SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat,     SimTypePointer,     SimTypeChar,     SimStruct,     SimTypeFixedSizeArray,     SimTypeBottom,     SimUnion,     SimTypeBool
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
lib.set_library_names("api-ms-win-core-file-fromapp-l1-1-0.dll")
prototypes = \
    {
        #
        'CopyFileFromAppW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName", "bFailIfExists"]),
        #
        'CreateDirectoryFromAppW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"nLength": SimTypeInt(signed=False, label="UInt32"), "lpSecurityDescriptor": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "bInheritHandle": SimTypeInt(signed=True, label="Int32")}, name="SECURITY_ATTRIBUTES", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName", "lpSecurityAttributes"]),
        #
        'CreateFileFromAppW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"nLength": SimTypeInt(signed=False, label="UInt32"), "lpSecurityDescriptor": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "bInheritHandle": SimTypeInt(signed=True, label="Int32")}, name="SECURITY_ATTRIBUTES", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile"]),
        #
        'CreateFile2FromAppW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwFileAttributes": SimTypeInt(signed=False, label="UInt32"), "dwFileFlags": SimTypeInt(signed=False, label="UInt32"), "dwSecurityQosFlags": SimTypeInt(signed=False, label="UInt32"), "lpSecurityAttributes": SimTypePointer(SimStruct({"nLength": SimTypeInt(signed=False, label="UInt32"), "lpSecurityDescriptor": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "bInheritHandle": SimTypeInt(signed=True, label="Int32")}, name="SECURITY_ATTRIBUTES", pack=False, align=None), offset=0), "hTemplateFile": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="CREATEFILE2_EXTENDED_PARAMETERS", pack=False, align=None), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "dwDesiredAccess", "dwShareMode", "dwCreationDisposition", "pCreateExParams"]),
        #
        'DeleteFileFromAppW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName"]),
        #
        'FindFirstFileExFromAppW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="FINDEX_INFO_LEVELS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="FINDEX_SEARCH_OPS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "fInfoLevelId", "lpFindFileData", "fSearchOp", "lpSearchFilter", "dwAdditionalFlags"]),
        #
        'GetFileAttributesExFromAppW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="GET_FILEEX_INFO_LEVELS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "fInfoLevelId", "lpFileInformation"]),
        #
        'MoveFileFromAppW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName"]),
        #
        'RemoveDirectoryFromAppW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName"]),
        #
        'ReplaceFileFromAppW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpReplacedFileName", "lpReplacementFileName", "lpBackupFileName", "dwReplaceFlags", "lpExclude", "lpReserved"]),
        #
        'SetFileAttributesFromAppW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "dwFileAttributes"]),
    }

lib.set_prototypes(prototypes)
