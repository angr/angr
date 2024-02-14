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
lib.set_library_names("imagehlp.dll")
prototypes = \
    {
        #
        'CheckSumMappedFile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeRef("IMAGE_NT_HEADERS64", SimStruct), offset=0), arg_names=["BaseAddress", "FileLength", "HeaderSum", "CheckSum"]),
        #
        'GetImageConfigInformation': SimTypeFunction([SimTypePointer(SimTypeRef("LOADED_IMAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("IMAGE_LOAD_CONFIG_DIRECTORY64", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LoadedImage", "ImageConfigInformation"]),
        #
        'SetImageConfigInformation': SimTypeFunction([SimTypePointer(SimTypeRef("LOADED_IMAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("IMAGE_LOAD_CONFIG_DIRECTORY64", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LoadedImage", "ImageConfigInformation"]),
        #
        'BindImage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ImageName", "DllPath", "SymbolPath"]),
        #
        'BindImageEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="IMAGEHLP_STATUS_REASON"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Reason", "ImageName", "DllName", "Va", "Parameter"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "ImageName", "DllPath", "SymbolPath", "StatusRoutine"]),
        #
        'ReBaseImage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CurrentImageName", "SymbolPath", "fReBase", "fRebaseSysfileOk", "fGoingDown", "CheckImageSize", "OldImageSize", "OldImageBase", "NewImageSize", "NewImageBase", "TimeStamp"]),
        #
        'ReBaseImage64': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CurrentImageName", "SymbolPath", "fReBase", "fRebaseSysfileOk", "fGoingDown", "CheckImageSize", "OldImageSize", "OldImageBase", "NewImageSize", "NewImageBase", "TimeStamp"]),
        #
        'CheckSumMappedFile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeRef("IMAGE_NT_HEADERS32", SimStruct), offset=0), arg_names=["BaseAddress", "FileLength", "HeaderSum", "CheckSum"]),
        #
        'MapFileAndCheckSumA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Filename", "HeaderSum", "CheckSum"]),
        #
        'MapFileAndCheckSumW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Filename", "HeaderSum", "CheckSum"]),
        #
        'GetImageConfigInformation': SimTypeFunction([SimTypePointer(SimTypeRef("LOADED_IMAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("IMAGE_LOAD_CONFIG_DIRECTORY32", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LoadedImage", "ImageConfigInformation"]),
        #
        'GetImageUnusedHeaderBytes': SimTypeFunction([SimTypePointer(SimTypeRef("LOADED_IMAGE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["LoadedImage", "SizeUnusedHeaderBytes"]),
        #
        'SetImageConfigInformation': SimTypeFunction([SimTypePointer(SimTypeRef("LOADED_IMAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("IMAGE_LOAD_CONFIG_DIRECTORY32", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LoadedImage", "ImageConfigInformation"]),
        #
        'ImageGetDigestStream': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["refdata", "pData", "dwLength"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "DigestLevel", "DigestFunction", "DigestHandle"]),
        #
        'ImageAddCertificate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("WIN_CERTIFICATE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Certificate", "Index"]),
        #
        'ImageRemoveCertificate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Index"]),
        #
        'ImageEnumerateCertificates': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "TypeFilter", "CertificateCount", "Indices", "IndexCount"]),
        #
        'ImageGetCertificateData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WIN_CERTIFICATE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "CertificateIndex", "Certificate", "RequiredLength"]),
        #
        'ImageGetCertificateHeader': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WIN_CERTIFICATE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "CertificateIndex", "Certificateheader"]),
        #
        'ImageLoad': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeRef("LOADED_IMAGE", SimStruct), offset=0), arg_names=["DllName", "DllPath"]),
        #
        'ImageUnload': SimTypeFunction([SimTypePointer(SimTypeRef("LOADED_IMAGE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LoadedImage"]),
        #
        'MapAndLoad': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("LOADED_IMAGE", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ImageName", "DllPath", "LoadedImage", "DotDll", "ReadOnly"]),
        #
        'UnMapAndLoad': SimTypeFunction([SimTypePointer(SimTypeRef("LOADED_IMAGE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LoadedImage"]),
        #
        'TouchFileTimes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "pSystemTime"]),
        #
        'UpdateDebugInfoFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("IMAGE_NT_HEADERS32", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ImageFileName", "SymbolPath", "DebugFilePath", "NtHeaders"]),
        #
        'UpdateDebugInfoFileEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("IMAGE_NT_HEADERS32", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ImageFileName", "SymbolPath", "DebugFilePath", "NtHeaders", "OldCheckSum"]),
    }

lib.set_prototypes(prototypes)
