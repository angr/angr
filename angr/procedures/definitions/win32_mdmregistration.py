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
lib.set_library_names("mdmregistration.dll")
prototypes = \
    {
        #
        'GetDeviceRegistrationInfo': SimTypeFunction([SimTypeInt(signed=False, label="REGISTRATION_INFORMATION_CLASS"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceInformationClass", "ppDeviceRegistrationInfo"]),
        #
        'IsDeviceRegisteredWithManagement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfIsDeviceRegisteredWithManagement", "cchUPN", "pszUPN"]),
        #
        'IsManagementRegistrationAllowed': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfIsManagementRegistrationAllowed"]),
        #
        'IsMdmUxWithoutAadAllowed': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["isEnrollmentAllowed"]),
        #
        'SetManagedExternally': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["IsManagedExternally"]),
        #
        'DiscoverManagementService': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("MANAGEMENT_SERVICE_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUPN", "ppMgmtInfo"]),
        #
        'RegisterDeviceWithManagementUsingAADCredentials': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["UserToken"]),
        #
        'RegisterDeviceWithManagementUsingAADDeviceCredentials': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'RegisterDeviceWithManagementUsingAADDeviceCredentials2': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MDMApplicationID"]),
        #
        'RegisterDeviceWithManagement': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUPN", "ppszMDMServiceUri", "ppzsAccessToken"]),
        #
        'UnregisterDeviceWithManagement': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["enrollmentID"]),
        #
        'GetDeviceManagementConfigInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["providerID", "configStringBufferLength", "configString"]),
        #
        'SetDeviceManagementConfigInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["providerID", "configString"]),
        #
        'GetManagementAppHyperlink': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cchHyperlink", "pszHyperlink"]),
        #
        'DiscoverManagementServiceEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("MANAGEMENT_SERVICE_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUPN", "pszDiscoveryServiceCandidate", "ppMgmtInfo"]),
    }

lib.set_prototypes(prototypes)
