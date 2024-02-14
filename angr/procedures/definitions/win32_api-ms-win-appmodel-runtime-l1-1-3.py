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
lib.set_library_names("api-ms-win-appmodel-runtime-l1-1-3.dll")
prototypes = \
    {
        #
        'GetPackagePathByFullName2': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="PackagePathType"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFullName", "packagePathType", "pathLength", "path"]),
        #
        'GetStagedPackagePathByFullName2': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="PackagePathType"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFullName", "packagePathType", "pathLength", "path"]),
        #
        'GetCurrentPackageInfo2': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="PackagePathType"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["flags", "packagePathType", "bufferLength", "buffer", "count"]),
        #
        'GetCurrentPackagePath2': SimTypeFunction([SimTypeInt(signed=False, label="PackagePathType"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packagePathType", "pathLength", "path"]),
        #
        'GetPackageInfo2': SimTypeFunction([SimTypePointer(SimTypeRef("_PACKAGE_INFO_REFERENCE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="PackagePathType"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageInfoReference", "flags", "packagePathType", "bufferLength", "buffer", "count"]),
    }

lib.set_prototypes(prototypes)
