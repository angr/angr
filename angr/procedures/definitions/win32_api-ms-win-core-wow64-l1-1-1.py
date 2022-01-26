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
lib.set_library_names("api-ms-win-core-wow64-l1-1-1.dll")
prototypes = \
    {
        # 
        'GetSystemWow64Directory2A': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer", "uSize", "ImageFileMachineType"]),
        # 
        'GetSystemWow64Directory2W': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer", "uSize", "ImageFileMachineType"]),
        # 
        'Wow64SetThreadDefaultGuestMachine': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=False, label="UInt16"), arg_names=["Machine"]),
    }

lib.set_prototypes(prototypes)
