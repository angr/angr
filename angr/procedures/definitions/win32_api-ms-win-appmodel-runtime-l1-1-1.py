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
lib.set_library_names("api-ms-win-appmodel-runtime-l1-1-1.dll")
prototypes = \
    {
        #
        'GetPackageFullNameFromToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["token", "packageFullNameLength", "packageFullName"]),
        #
        'GetPackageFamilyNameFromToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["token", "packageFamilyNameLength", "packageFamilyName"]),
        #
        'GetApplicationUserModelIdFromToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["token", "applicationUserModelIdLength", "applicationUserModelId"]),
        #
        'VerifyPackageFullName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFullName"]),
        #
        'VerifyPackageFamilyName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFamilyName"]),
        #
        'VerifyPackageId': SimTypeFunction([SimTypePointer(SimTypeRef("PACKAGE_ID", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageId"]),
        #
        'VerifyApplicationUserModelId': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["applicationUserModelId"]),
        #
        'VerifyPackageRelativeApplicationId': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageRelativeApplicationId"]),
        #
        'GetStagedPackageOrigin': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="PackageOrigin"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFullName", "origin"]),
        #
        'OpenPackageInfoByFullNameForUser': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("_PACKAGE_INFO_REFERENCE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["userSid", "packageFullName", "reserved", "packageInfoReference"]),
    }

lib.set_prototypes(prototypes)
