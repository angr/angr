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
lib.set_library_names("api-ms-win-core-wow64-l1-1-1.dll")
prototypes = \
    {
        #
        'GetSystemWow64Directory2A': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="IMAGE_FILE_MACHINE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer", "uSize", "ImageFileMachineType"]),
        #
        'GetSystemWow64Directory2W': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="IMAGE_FILE_MACHINE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer", "uSize", "ImageFileMachineType"]),
        #
        'Wow64SetThreadDefaultGuestMachine': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=False, label="UInt16"), arg_names=["Machine"]),
    }

lib.set_prototypes(prototypes)
