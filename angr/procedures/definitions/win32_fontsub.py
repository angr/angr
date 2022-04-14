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
lib.set_library_names("fontsub.dll")
prototypes = \
    {
        # 
        'CreateFontPackage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="CREATE_FONT_PACKAGE_SUBSET_PLATFORM"), SimTypeInt(signed=False, label="CREATE_FONT_PACKAGE_SUBSET_ENCODING"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["param0"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["puchSrcBuffer", "ulSrcBufferSize", "ppuchFontPackageBuffer", "pulFontPackageBufferSize", "pulBytesWritten", "usFlag", "usTTCIndex", "usSubsetFormat", "usSubsetLanguage", "usSubsetPlatform", "usSubsetEncoding", "pusSubsetKeepList", "usSubsetListCount", "lpfnAllocate", "lpfnReAllocate", "lpfnFree", "lpvReserved"]),
        # 
        'MergeFontPackage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["param0"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["puchMergeFontBuffer", "ulMergeFontBufferSize", "puchFontPackageBuffer", "ulFontPackageBufferSize", "ppuchDestBuffer", "pulDestBufferSize", "pulBytesWritten", "usMode", "lpfnAllocate", "lpfnReAllocate", "lpfnFree", "lpvReserved"]),
    }

lib.set_prototypes(prototypes)
