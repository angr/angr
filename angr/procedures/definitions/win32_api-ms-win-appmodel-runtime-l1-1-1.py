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
lib.set_library_names("api-ms-win-appmodel-runtime-l1-1-1.dll")
prototypes = \
    {
        # 
        'GetPackageFullNameFromToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["token", "packageFullNameLength", "packageFullName"]),
        # 
        'GetPackageFamilyNameFromToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["token", "packageFamilyNameLength", "packageFamilyName"]),
        # 
        'GetApplicationUserModelIdFromToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["token", "applicationUserModelIdLength", "applicationUserModelId"]),
        # 
        'VerifyPackageFullName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageFullName"]),
        # 
        'VerifyPackageFamilyName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageFamilyName"]),
        # 
        'VerifyPackageId': SimTypeFunction([SimTypePointer(SimStruct({"reserved": SimTypeInt(signed=False, label="UInt32"), "processorArchitecture": SimTypeInt(signed=False, label="UInt32"), "version": SimStruct({"Anonymous": SimUnion({"Version": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct({"Revision": SimTypeShort(signed=False, label="UInt16"), "Build": SimTypeShort(signed=False, label="UInt16"), "Minor": SimTypeShort(signed=False, label="UInt16"), "Major": SimTypeShort(signed=False, label="UInt16")}, name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None")}, name="PACKAGE_VERSION", pack=False, align=None), "name": SimTypePointer(SimTypeChar(label="Char"), offset=0), "publisher": SimTypePointer(SimTypeChar(label="Char"), offset=0), "resourceId": SimTypePointer(SimTypeChar(label="Char"), offset=0), "publisherId": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="PACKAGE_ID", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageId"]),
        # 
        'VerifyApplicationUserModelId': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["applicationUserModelId"]),
        # 
        'VerifyPackageRelativeApplicationId': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageRelativeApplicationId"]),
        # 
        'GetStagedPackageOrigin': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="PackageOrigin"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageFullName", "origin"]),
        # 
        'OpenPackageInfoByFullNameForUser': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimStruct({"reserved": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="_PACKAGE_INFO_REFERENCE", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["userSid", "packageFullName", "reserved", "packageInfoReference"]),
    }

lib.set_prototypes(prototypes)
