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
lib.set_library_names("userenv.dll")
prototypes = \
    {
        #
        'CreateAppContainerProfile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SID_AND_ATTRIBUTES", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszAppContainerName", "pszDisplayName", "pszDescription", "pCapabilities", "dwCapabilityCount", "ppSidAppContainerSid"]),
        #
        'DeleteAppContainerProfile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszAppContainerName"]),
        #
        'GetAppContainerRegistryLocation': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["desiredAccess", "phAppContainerKey"]),
        #
        'GetAppContainerFolderPath': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszAppContainerSid", "ppszPath"]),
        #
        'DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psidAppContainerSid", "pszRestrictedAppContainerName", "ppsidRestrictedAppContainerSid"]),
        #
        'DeriveAppContainerSidFromAppContainerName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszAppContainerName", "ppsidAppContainerSid"]),
        #
        'CreateEnvironmentBlock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpEnvironment", "hToken", "bInherit"]),
        #
        'DestroyEnvironmentBlock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpEnvironment"]),
        #
        'ExpandEnvironmentStringsForUserA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken", "lpSrc", "lpDest", "dwSize"]),
        #
        'ExpandEnvironmentStringsForUserW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken", "lpSrc", "lpDest", "dwSize"]),
        #
        'RefreshPolicy': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["bMachine"]),
        #
        'RefreshPolicyEx': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["bMachine", "dwOptions"]),
        #
        'EnterCriticalPolicySection': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bMachine"]),
        #
        'LeaveCriticalPolicySection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSection"]),
        #
        'RegisterGPNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent", "bMachine"]),
        #
        'UnregisterGPNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent"]),
        #
        'GetGPOListA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("GROUP_POLICY_OBJECTA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken", "lpName", "lpHostName", "lpComputerName", "dwFlags", "pGPOList"]),
        #
        'GetGPOListW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("GROUP_POLICY_OBJECTW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken", "lpName", "lpHostName", "lpComputerName", "dwFlags", "pGPOList"]),
        #
        'FreeGPOListA': SimTypeFunction([SimTypePointer(SimTypeRef("GROUP_POLICY_OBJECTA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pGPOList"]),
        #
        'FreeGPOListW': SimTypeFunction([SimTypePointer(SimTypeRef("GROUP_POLICY_OBJECTW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pGPOList"]),
        #
        'GetAppliedGPOListA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("GROUP_POLICY_OBJECTA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwFlags", "pMachineName", "pSidUser", "pGuidExtension", "ppGPOList"]),
        #
        'GetAppliedGPOListW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("GROUP_POLICY_OBJECTW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwFlags", "pMachineName", "pSidUser", "pGuidExtension", "ppGPOList"]),
        #
        'ProcessGroupPolicyCompleted': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["extensionId", "pAsyncHandle", "dwStatus"]),
        #
        'ProcessGroupPolicyCompletedEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["extensionId", "pAsyncHandle", "dwStatus", "RsopStatus"]),
        #
        'RsopAccessCheckByType': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_TYPE_LIST", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "pPrincipalSelfSid", "pRsopToken", "dwDesiredAccessMask", "pObjectTypeList", "ObjectTypeListLength", "pGenericMapping", "pPrivilegeSet", "pdwPrivilegeSetLength", "pdwGrantedAccessMask", "pbAccessStatus"]),
        #
        'RsopFileAccessCheck': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFileName", "pRsopToken", "dwDesiredAccessMask", "pdwGrantedAccessMask", "pbAccessStatus"]),
        #
        'RsopSetPolicySettingStatus': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IWbemServices"), SimTypeBottom(label="IWbemClassObject"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POLICYSETTINGSTATUSINFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pServices", "pSettingInstance", "nInfo", "pStatus"]),
        #
        'RsopResetPolicySettingStatus': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IWbemServices"), SimTypeBottom(label="IWbemClassObject")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pServices", "pSettingInstance"]),
        #
        'GenerateGPNotification': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["bMachine", "lpwszMgmtProduct", "dwMgmtProductOptions"]),
        #
        'LoadUserProfileA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PROFILEINFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken", "lpProfileInfo"]),
        #
        'LoadUserProfileW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PROFILEINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken", "lpProfileInfo"]),
        #
        'UnloadUserProfile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken", "hProfile"]),
        #
        'GetProfilesDirectoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProfileDir", "lpcchSize"]),
        #
        'GetProfilesDirectoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProfileDir", "lpcchSize"]),
        #
        'GetProfileType': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags"]),
        #
        'DeleteProfileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSidString", "lpProfilePath", "lpComputerName"]),
        #
        'DeleteProfileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSidString", "lpProfilePath", "lpComputerName"]),
        #
        'CreateProfile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUserSid", "pszUserName", "pszProfilePath", "cchProfilePath"]),
        #
        'GetDefaultUserProfileDirectoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProfileDir", "lpcchSize"]),
        #
        'GetDefaultUserProfileDirectoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProfileDir", "lpcchSize"]),
        #
        'GetAllUsersProfileDirectoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProfileDir", "lpcchSize"]),
        #
        'GetAllUsersProfileDirectoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProfileDir", "lpcchSize"]),
        #
        'GetUserProfileDirectoryA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken", "lpProfileDir", "lpcchSize"]),
        #
        'GetUserProfileDirectoryW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken", "lpProfileDir", "lpcchSize"]),
    }

lib.set_prototypes(prototypes)
