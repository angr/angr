# pylint:disable=line-too-long
from __future__ import annotations
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
lib.set_library_names("secur32.dll")
prototypes = \
    {
        #
        'LsaRegisterLogonProcess': SimTypeFunction([SimTypePointer(SimTypeRef("LSA_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogonProcessName", "LsaHandle", "SecurityMode"]),
        #
        'LsaLogonUser': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LSA_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="SECURITY_LOGON_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TOKEN_GROUPS", SimStruct), offset=0), SimTypePointer(SimTypeRef("TOKEN_SOURCE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("QUOTA_LIMITS", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LsaHandle", "OriginName", "LogonType", "AuthenticationPackage", "AuthenticationInformation", "AuthenticationInformationLength", "LocalGroups", "SourceContext", "ProfileBuffer", "ProfileBufferLength", "LogonId", "Token", "Quotas", "SubStatus"]),
        #
        'LsaLookupAuthenticationPackage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LSA_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LsaHandle", "PackageName", "AuthenticationPackage"]),
        #
        'LsaFreeReturnBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Buffer"]),
        #
        'LsaCallAuthenticationPackage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LsaHandle", "AuthenticationPackage", "ProtocolSubmitBuffer", "SubmitBufferLength", "ProtocolReturnBuffer", "ReturnBufferLength", "ProtocolStatus"]),
        #
        'LsaDeregisterLogonProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LsaHandle"]),
        #
        'LsaConnectUntrusted': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LsaHandle"]),
        #
        'LsaEnumerateLogonSessions': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogonSessionCount", "LogonSessionList"]),
        #
        'LsaGetLogonSessionData': SimTypeFunction([SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SECURITY_LOGON_SESSION_DATA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogonId", "ppLogonSessionData"]),
        #
        'LsaRegisterPolicyChangeNotification': SimTypeFunction([SimTypeInt(signed=False, label="POLICY_NOTIFICATION_INFORMATION_CLASS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InformationClass", "NotificationEventHandle"]),
        #
        'LsaUnregisterPolicyChangeNotification': SimTypeFunction([SimTypeInt(signed=False, label="POLICY_NOTIFICATION_INFORMATION_CLASS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InformationClass", "NotificationEventHandle"]),
        #
        'AcquireCredentialsHandleW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="SECPKG_CRED"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Arg", "Principal", "KeyVer", "Key", "Status"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPrincipal", "pszPackage", "fCredentialUse", "pvLogonId", "pAuthData", "pGetKeyFn", "pvGetKeyArgument", "phCredential", "ptsExpiry"]),
        #
        'AcquireCredentialsHandleA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="SECPKG_CRED"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Arg", "Principal", "KeyVer", "Key", "Status"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPrincipal", "pszPackage", "fCredentialUse", "pvLogonId", "pAuthData", "pGetKeyFn", "pvGetKeyArgument", "phCredential", "ptsExpiry"]),
        #
        'FreeCredentialsHandle': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phCredential"]),
        #
        'AddCredentialsW': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Arg", "Principal", "KeyVer", "Key", "Status"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCredentials", "pszPrincipal", "pszPackage", "fCredentialUse", "pAuthData", "pGetKeyFn", "pvGetKeyArgument", "ptsExpiry"]),
        #
        'AddCredentialsA': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Arg", "Principal", "KeyVer", "Key", "Status"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCredentials", "pszPrincipal", "pszPackage", "fCredentialUse", "pAuthData", "pGetKeyFn", "pvGetKeyArgument", "ptsExpiry"]),
        #
        'ChangeAccountPasswordW': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPackageName", "pszDomainName", "pszAccountName", "pszOldPassword", "pszNewPassword", "bImpersonating", "dwReserved", "pOutput"]),
        #
        'ChangeAccountPasswordA': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPackageName", "pszDomainName", "pszAccountName", "pszOldPassword", "pszNewPassword", "bImpersonating", "dwReserved", "pOutput"]),
        #
        'InitializeSecurityContextW': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="ISC_REQ_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phCredential", "phContext", "pszTargetName", "fContextReq", "Reserved1", "TargetDataRep", "pInput", "Reserved2", "phNewContext", "pOutput", "pfContextAttr", "ptsExpiry"]),
        #
        'InitializeSecurityContextA': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypeInt(signed=False, label="ISC_REQ_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phCredential", "phContext", "pszTargetName", "fContextReq", "Reserved1", "TargetDataRep", "pInput", "Reserved2", "phNewContext", "pOutput", "pfContextAttr", "ptsExpiry"]),
        #
        'AcceptSecurityContext': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypeInt(signed=False, label="ASC_REQ_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phCredential", "phContext", "pInput", "fContextReq", "TargetDataRep", "phNewContext", "pOutput", "pfContextAttr", "ptsExpiry"]),
        #
        'CompleteAuthToken': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "pToken"]),
        #
        'ImpersonateSecurityContext': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext"]),
        #
        'RevertSecurityContext': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext"]),
        #
        'QuerySecurityContextToken': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "Token"]),
        #
        'DeleteSecurityContext': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext"]),
        #
        'ApplyControlToken': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "pInput"]),
        #
        'QueryContextAttributesW': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="SECPKG_ATTR"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "ulAttribute", "pBuffer"]),
        #
        'QueryContextAttributesA': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="SECPKG_ATTR"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "ulAttribute", "pBuffer"]),
        #
        'SetContextAttributesW': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="SECPKG_ATTR"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "ulAttribute", "pBuffer", "cbBuffer"]),
        #
        'SetContextAttributesA': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="SECPKG_ATTR"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "ulAttribute", "pBuffer", "cbBuffer"]),
        #
        'QueryCredentialsAttributesW': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phCredential", "ulAttribute", "pBuffer"]),
        #
        'QueryCredentialsAttributesA': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phCredential", "ulAttribute", "pBuffer"]),
        #
        'SetCredentialsAttributesW': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phCredential", "ulAttribute", "pBuffer", "cbBuffer"]),
        #
        'SetCredentialsAttributesA': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phCredential", "ulAttribute", "pBuffer", "cbBuffer"]),
        #
        'FreeContextBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvContextBuffer"]),
        #
        'MakeSignature': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "fQOP", "pMessage", "MessageSeqNo"]),
        #
        'VerifySignature': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "pMessage", "MessageSeqNo", "pfQOP"]),
        #
        'EncryptMessage': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "fQOP", "pMessage", "MessageSeqNo"]),
        #
        'DecryptMessage': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "pMessage", "MessageSeqNo", "pfQOP"]),
        #
        'EnumerateSecurityPackagesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SecPkgInfoW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcPackages", "ppPackageInfo"]),
        #
        'EnumerateSecurityPackagesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SecPkgInfoA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcPackages", "ppPackageInfo"]),
        #
        'QuerySecurityPackageInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SecPkgInfoW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPackageName", "ppPackageInfo"]),
        #
        'QuerySecurityPackageInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SecPkgInfoA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPackageName", "ppPackageInfo"]),
        #
        'ExportSecurityContext': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="EXPORT_SECURITY_CONTEXT_FLAGS"), SimTypePointer(SimTypeRef("SecBuffer", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "fFlags", "pPackedContext", "pToken"]),
        #
        'ImportSecurityContextW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SecBuffer", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPackage", "pPackedContext", "Token", "phContext"]),
        #
        'ImportSecurityContextA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SecBuffer", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPackage", "pPackedContext", "Token", "phContext"]),
        #
        'InitSecurityInterfaceA': SimTypeFunction([], SimTypePointer(SimTypeRef("SecurityFunctionTableA", SimStruct), offset=0)),
        #
        'InitSecurityInterfaceW': SimTypeFunction([], SimTypePointer(SimTypeRef("SecurityFunctionTableW", SimStruct), offset=0)),
        #
        'SaslEnumerateProfilesA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProfileList", "ProfileCount"]),
        #
        'SaslEnumerateProfilesW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProfileList", "ProfileCount"]),
        #
        'SaslGetProfilePackageA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SecPkgInfoA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProfileName", "PackageInfo"]),
        #
        'SaslGetProfilePackageW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SecPkgInfoW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProfileName", "PackageInfo"]),
        #
        'SaslIdentifyPackageA': SimTypeFunction([SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SecPkgInfoA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pInput", "PackageInfo"]),
        #
        'SaslIdentifyPackageW': SimTypeFunction([SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SecPkgInfoW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pInput", "PackageInfo"]),
        #
        'SaslInitializeSecurityContextW': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="ISC_REQ_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phCredential", "phContext", "pszTargetName", "fContextReq", "Reserved1", "TargetDataRep", "pInput", "Reserved2", "phNewContext", "pOutput", "pfContextAttr", "ptsExpiry"]),
        #
        'SaslInitializeSecurityContextA': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="ISC_REQ_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phCredential", "phContext", "pszTargetName", "fContextReq", "Reserved1", "TargetDataRep", "pInput", "Reserved2", "phNewContext", "pOutput", "pfContextAttr", "ptsExpiry"]),
        #
        'SaslAcceptSecurityContext': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypeInt(signed=False, label="ASC_REQ_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phCredential", "phContext", "pInput", "fContextReq", "TargetDataRep", "phNewContext", "pOutput", "pfContextAttr", "ptsExpiry"]),
        #
        'SaslSetContextOption': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ContextHandle", "Option", "Value", "Size"]),
        #
        'SaslGetContextOption': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ContextHandle", "Option", "Value", "Size", "Needed"]),
        #
        'SspiPrepareForCredRead': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AuthIdentity", "pszTargetName", "pCredmanCredentialType", "ppszCredmanTargetName"]),
        #
        'SspiPrepareForCredWrite': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AuthIdentity", "pszTargetName", "pCredmanCredentialType", "ppszCredmanTargetName", "ppszCredmanUserName", "ppCredentialBlob", "pCredentialBlobSize"]),
        #
        'SspiEncryptAuthIdentity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AuthData"]),
        #
        'SspiDecryptAuthIdentity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EncryptedAuthData"]),
        #
        'SspiIsAuthIdentityEncrypted': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["EncryptedAuthData"]),
        #
        'SspiEncodeAuthIdentityAsStrings': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAuthIdentity", "ppszUserName", "ppszDomainName", "ppszPackedCredentialsString"]),
        #
        'SspiValidateAuthIdentity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AuthData"]),
        #
        'SspiCopyAuthIdentity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AuthData", "AuthDataCopy"]),
        #
        'SspiFreeAuthIdentity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["AuthData"]),
        #
        'SspiZeroAuthIdentity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["AuthData"]),
        #
        'SspiLocalFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["DataBuffer"]),
        #
        'SspiEncodeStringsAsAuthIdentity': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUserName", "pszDomainName", "pszPackedCredentialsString", "ppAuthIdentity"]),
        #
        'SspiCompareAuthIdentities': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AuthIdentity1", "AuthIdentity2", "SameSuppliedUser", "SameSuppliedIdentity"]),
        #
        'SspiMarshalAuthIdentity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AuthIdentity", "AuthIdentityLength", "AuthIdentityByteArray"]),
        #
        'SspiUnmarshalAuthIdentity': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AuthIdentityLength", "AuthIdentityByteArray", "ppAuthIdentity"]),
        #
        'SspiGetTargetHostName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszTargetName", "pszHostName"]),
        #
        'SspiExcludePackage': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AuthIdentity", "pszPackageName", "ppNewAuthIdentity"]),
        #
        'AddSecurityPackageA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SECURITY_PACKAGE_OPTIONS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPackageName", "pOptions"]),
        #
        'AddSecurityPackageW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SECURITY_PACKAGE_OPTIONS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPackageName", "pOptions"]),
        #
        'DeleteSecurityPackageA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPackageName"]),
        #
        'DeleteSecurityPackageW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPackageName"]),
        #
        'CredMarshalTargetInfo': SimTypeFunction([SimTypePointer(SimTypeRef("CREDENTIAL_TARGET_INFORMATIONW", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InTargetInfo", "Buffer", "BufferSize"]),
        #
        'CredUnmarshalTargetInfo': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("CREDENTIAL_TARGET_INFORMATIONW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Buffer", "BufferSize", "RetTargetInfo", "RetActualSize"]),
        #
        'GetUserNameExA': SimTypeFunction([SimTypeInt(signed=False, label="EXTENDED_NAME_FORMAT"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["NameFormat", "lpNameBuffer", "nSize"]),
        #
        'GetUserNameExW': SimTypeFunction([SimTypeInt(signed=False, label="EXTENDED_NAME_FORMAT"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["NameFormat", "lpNameBuffer", "nSize"]),
        #
        'GetComputerObjectNameA': SimTypeFunction([SimTypeInt(signed=False, label="EXTENDED_NAME_FORMAT"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["NameFormat", "lpNameBuffer", "nSize"]),
        #
        'GetComputerObjectNameW': SimTypeFunction([SimTypeInt(signed=False, label="EXTENDED_NAME_FORMAT"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["NameFormat", "lpNameBuffer", "nSize"]),
        #
        'TranslateNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="EXTENDED_NAME_FORMAT"), SimTypeInt(signed=False, label="EXTENDED_NAME_FORMAT"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["lpAccountName", "AccountNameFormat", "DesiredNameFormat", "lpTranslatedName", "nSize"]),
        #
        'TranslateNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="EXTENDED_NAME_FORMAT"), SimTypeInt(signed=False, label="EXTENDED_NAME_FORMAT"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["lpAccountName", "AccountNameFormat", "DesiredNameFormat", "lpTranslatedName", "nSize"]),
    }

lib.set_prototypes(prototypes)
