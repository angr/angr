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
lib.set_library_names("advapi32.dll")
prototypes = \
    {
        #
        'IsTextUnicode': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="IS_TEXT_UNICODE_RESULT"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpv", "iSize", "lpiResult"]),
        #
        'SaferGetPolicyInformation': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="SAFER_POLICY_INFO_CLASS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwScopeId", "SaferPolicyInfoClass", "InfoBufferSize", "InfoBuffer", "InfoBufferRetSize", "lpReserved"]),
        #
        'SaferSetPolicyInformation': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="SAFER_POLICY_INFO_CLASS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwScopeId", "SaferPolicyInfoClass", "InfoBufferSize", "InfoBuffer", "lpReserved"]),
        #
        'SaferCreateLevel': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwScopeId", "dwLevelId", "OpenFlags", "pLevelHandle", "lpReserved"]),
        #
        'SaferCloseLevel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLevelHandle"]),
        #
        'SaferIdentifyLevel': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SAFER_CODE_PROPERTIES_V2", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwNumProperties", "pCodeProperties", "pLevelHandle", "lpReserved"]),
        #
        'SaferComputeTokenFromLevel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="SAFER_COMPUTE_TOKEN_FROM_LEVEL_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LevelHandle", "InAccessToken", "OutAccessToken", "dwFlags", "lpReserved"]),
        #
        'SaferGetLevelInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SAFER_OBJECT_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LevelHandle", "dwInfoType", "lpQueryBuffer", "dwInBufferSize", "lpdwOutBufferSize"]),
        #
        'SaferSetLevelInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SAFER_OBJECT_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["LevelHandle", "dwInfoType", "lpQueryBuffer", "dwInBufferSize"]),
        #
        'SaferRecordEventLogEntry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLevel", "szTargetPath", "lpReserved"]),
        #
        'SaferiIsExecutableFileType': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["szFullPathname", "bFromShellExecute"]),
        #
        'RtlGenRandom': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["RandomBuffer", "RandomBufferLength"]),
        #
        'RtlEncryptMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Memory", "MemorySize", "OptionFlags"]),
        #
        'RtlDecryptMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Memory", "MemorySize", "OptionFlags"]),
        #
        'LsaFreeMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Buffer"]),
        #
        'LsaClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectHandle"]),
        #
        'LsaOpenPolicy': SimTypeFunction([SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("LSA_OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SystemName", "ObjectAttributes", "DesiredAccess", "PolicyHandle"]),
        #
        'LsaSetCAPs': SimTypeFunction([SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CAPDNs", "CAPDNCount", "Flags"]),
        #
        'LsaGetAppliedCAPIDs': SimTypeFunction([SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SystemName", "CAPIDs", "CAPIDCount"]),
        #
        'LsaQueryCAPs': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("CENTRAL_ACCESS_POLICY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CAPIDs", "CAPIDCount", "CAPs", "CAPCount"]),
        #
        'LsaQueryInformationPolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POLICY_INFORMATION_CLASS"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "InformationClass", "Buffer"]),
        #
        'LsaSetInformationPolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POLICY_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "InformationClass", "Buffer"]),
        #
        'LsaQueryDomainInformationPolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POLICY_DOMAIN_INFORMATION_CLASS"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "InformationClass", "Buffer"]),
        #
        'LsaSetDomainInformationPolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POLICY_DOMAIN_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "InformationClass", "Buffer"]),
        #
        'LsaEnumerateTrustedDomains': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "EnumerationContext", "Buffer", "PreferedMaximumLength", "CountReturned"]),
        #
        'LsaLookupNames': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LSA_REFERENCED_DOMAIN_LIST", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LSA_TRANSLATED_SID", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "Count", "Names", "ReferencedDomains", "Sids"]),
        #
        'LsaLookupNames2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LSA_REFERENCED_DOMAIN_LIST", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LSA_TRANSLATED_SID2", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "Flags", "Count", "Names", "ReferencedDomains", "Sids"]),
        #
        'LsaLookupSids': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LSA_REFERENCED_DOMAIN_LIST", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LSA_TRANSLATED_NAME", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "Count", "Sids", "ReferencedDomains", "Names"]),
        #
        'LsaLookupSids2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LSA_REFERENCED_DOMAIN_LIST", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LSA_TRANSLATED_NAME", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "LookupOptions", "Count", "Sids", "ReferencedDomains", "Names"]),
        #
        'LsaEnumerateAccountsWithUserRight': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "UserRight", "Buffer", "CountReturned"]),
        #
        'LsaEnumerateAccountRights': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "AccountSid", "UserRights", "CountOfRights"]),
        #
        'LsaAddAccountRights': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "AccountSid", "UserRights", "CountOfRights"]),
        #
        'LsaRemoveAccountRights': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "AccountSid", "AllRights", "UserRights", "CountOfRights"]),
        #
        'LsaOpenTrustedDomainByName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "TrustedDomainName", "DesiredAccess", "TrustedDomainHandle"]),
        #
        'LsaQueryTrustedDomainInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="TRUSTED_INFORMATION_CLASS"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "TrustedDomainSid", "InformationClass", "Buffer"]),
        #
        'LsaSetTrustedDomainInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="TRUSTED_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "TrustedDomainSid", "InformationClass", "Buffer"]),
        #
        'LsaDeleteTrustedDomain': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "TrustedDomainSid"]),
        #
        'LsaQueryTrustedDomainInfoByName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="TRUSTED_INFORMATION_CLASS"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "TrustedDomainName", "InformationClass", "Buffer"]),
        #
        'LsaSetTrustedDomainInfoByName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="TRUSTED_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "TrustedDomainName", "InformationClass", "Buffer"]),
        #
        'LsaEnumerateTrustedDomainsEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "EnumerationContext", "Buffer", "PreferedMaximumLength", "CountReturned"]),
        #
        'LsaCreateTrustedDomainEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TRUSTED_DOMAIN_INFORMATION_EX", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRUSTED_DOMAIN_AUTH_INFORMATION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "TrustedDomainInformation", "AuthenticationInformation", "DesiredAccess", "TrustedDomainHandle"]),
        #
        'LsaQueryForestTrustInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LSA_FOREST_TRUST_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "TrustedDomainName", "ForestTrustInfo"]),
        #
        'LsaSetForestTrustInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("LSA_FOREST_TRUST_INFORMATION", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeRef("LSA_FOREST_TRUST_COLLISION_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "TrustedDomainName", "ForestTrustInfo", "CheckOnly", "CollisionInfo"]),
        #
        'LsaStorePrivateData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "KeyName", "PrivateData"]),
        #
        'LsaRetrievePrivateData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "KeyName", "PrivateData"]),
        #
        'LsaNtStatusToWinError': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Status"]),
        #
        'LsaQueryForestTrustInformation2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="LSA_FOREST_TRUST_RECORD_TYPE"), SimTypePointer(SimTypePointer(SimTypeRef("LSA_FOREST_TRUST_INFORMATION2", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "TrustedDomainName", "HighestRecordType", "ForestTrustInfo"]),
        #
        'LsaSetForestTrustInformation2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LSA_UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="LSA_FOREST_TRUST_RECORD_TYPE"), SimTypePointer(SimTypeRef("LSA_FOREST_TRUST_INFORMATION2", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeRef("LSA_FOREST_TRUST_COLLISION_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyHandle", "TrustedDomainName", "HighestRecordType", "ForestTrustInfo", "CheckOnly", "CollisionInfo"]),
        #
        'AuditSetSystemPolicy': SimTypeFunction([SimTypePointer(SimTypeRef("AUDIT_POLICY_INFORMATION", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["pAuditPolicy", "dwPolicyCount"]),
        #
        'AuditSetPerUserPolicy': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("AUDIT_POLICY_INFORMATION", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["pSid", "pAuditPolicy", "dwPolicyCount"]),
        #
        'AuditQuerySystemPolicy': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("AUDIT_POLICY_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["pSubCategoryGuids", "dwPolicyCount", "ppAuditPolicy"]),
        #
        'AuditQueryPerUserPolicy': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("AUDIT_POLICY_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["pSid", "pSubCategoryGuids", "dwPolicyCount", "ppAuditPolicy"]),
        #
        'AuditEnumeratePerUserPolicy': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("POLICY_AUDIT_SID_ARRAY", SimStruct), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["ppAuditSidArray"]),
        #
        'AuditComputeEffectivePolicyBySid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("AUDIT_POLICY_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["pSid", "pSubCategoryGuids", "dwPolicyCount", "ppAuditPolicy"]),
        #
        'AuditComputeEffectivePolicyByToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("AUDIT_POLICY_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["hTokenHandle", "pSubCategoryGuids", "dwPolicyCount", "ppAuditPolicy"]),
        #
        'AuditEnumerateCategories': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Guid"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["ppAuditCategoriesArray", "pdwCountReturned"]),
        #
        'AuditEnumerateSubCategories': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Guid"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["pAuditCategoryGuid", "bRetrieveAllSubCategories", "ppAuditSubCategoriesArray", "pdwCountReturned"]),
        #
        'AuditLookupCategoryNameW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["pAuditCategoryGuid", "ppszCategoryName"]),
        #
        'AuditLookupCategoryNameA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["pAuditCategoryGuid", "ppszCategoryName"]),
        #
        'AuditLookupSubCategoryNameW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["pAuditSubCategoryGuid", "ppszSubCategoryName"]),
        #
        'AuditLookupSubCategoryNameA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["pAuditSubCategoryGuid", "ppszSubCategoryName"]),
        #
        'AuditLookupCategoryIdFromCategoryGuid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="POLICY_AUDIT_EVENT_TYPE"), offset=0)], SimTypeChar(label="Byte"), arg_names=["pAuditCategoryGuid", "pAuditCategoryId"]),
        #
        'AuditLookupCategoryGuidFromCategoryId': SimTypeFunction([SimTypeInt(signed=False, label="POLICY_AUDIT_EVENT_TYPE"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeChar(label="Byte"), arg_names=["AuditCategoryId", "pAuditCategoryGuid"]),
        #
        'AuditSetSecurity': SimTypeFunction([SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["SecurityInformation", "pSecurityDescriptor"]),
        #
        'AuditQuerySecurity': SimTypeFunction([SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["SecurityInformation", "ppSecurityDescriptor"]),
        #
        'AuditSetGlobalSaclW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["ObjectTypeName", "Acl"]),
        #
        'AuditSetGlobalSaclA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["ObjectTypeName", "Acl"]),
        #
        'AuditQueryGlobalSaclW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["ObjectTypeName", "Acl"]),
        #
        'AuditQueryGlobalSaclA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["ObjectTypeName", "Acl"]),
        #
        'AuditFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Buffer"]),
        #
        'SetEntriesInAclA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_A", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["cCountOfExplicitEntries", "pListOfExplicitEntries", "OldAcl", "NewAcl"]),
        #
        'SetEntriesInAclW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_W", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["cCountOfExplicitEntries", "pListOfExplicitEntries", "OldAcl", "NewAcl"]),
        #
        'GetExplicitEntriesFromAclA': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_A", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pacl", "pcCountOfExplicitEntries", "pListOfExplicitEntries"]),
        #
        'GetExplicitEntriesFromAclW': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_W", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pacl", "pcCountOfExplicitEntries", "pListOfExplicitEntries"]),
        #
        'GetEffectiveRightsFromAclA': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pacl", "pTrustee", "pAccessRights"]),
        #
        'GetEffectiveRightsFromAclW': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pacl", "pTrustee", "pAccessRights"]),
        #
        'GetAuditedPermissionsFromAclA': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pacl", "pTrustee", "pSuccessfulAuditedRights", "pFailedAuditRights"]),
        #
        'GetAuditedPermissionsFromAclW': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pacl", "pTrustee", "pSuccessfulAuditedRights", "pFailedAuditRights"]),
        #
        'GetNamedSecurityInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pObjectName", "ObjectType", "SecurityInfo", "ppsidOwner", "ppsidGroup", "ppDacl", "ppSacl", "ppSecurityDescriptor"]),
        #
        'GetNamedSecurityInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pObjectName", "ObjectType", "SecurityInfo", "ppsidOwner", "ppsidGroup", "ppDacl", "ppSacl", "ppSecurityDescriptor"]),
        #
        'GetSecurityInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["handle", "ObjectType", "SecurityInfo", "ppsidOwner", "ppsidGroup", "ppDacl", "ppSacl", "ppSecurityDescriptor"]),
        #
        'SetNamedSecurityInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pObjectName", "ObjectType", "SecurityInfo", "psidOwner", "psidGroup", "pDacl", "pSacl"]),
        #
        'SetNamedSecurityInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pObjectName", "ObjectType", "SecurityInfo", "psidOwner", "psidGroup", "pDacl", "pSacl"]),
        #
        'SetSecurityInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["handle", "ObjectType", "SecurityInfo", "psidOwner", "psidGroup", "pDacl", "pSacl"]),
        #
        'GetInheritanceSourceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Guid"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("FN_OBJECT_MGR_FUNCTS", SimStruct), offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypePointer(SimTypeRef("INHERITED_FROMA", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pObjectName", "ObjectType", "SecurityInfo", "Container", "pObjectClassGuids", "GuidCount", "pAcl", "pfnArray", "pGenericMapping", "pInheritArray"]),
        #
        'GetInheritanceSourceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Guid"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("FN_OBJECT_MGR_FUNCTS", SimStruct), offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypePointer(SimTypeRef("INHERITED_FROMW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pObjectName", "ObjectType", "SecurityInfo", "Container", "pObjectClassGuids", "GuidCount", "pAcl", "pfnArray", "pGenericMapping", "pInheritArray"]),
        #
        'FreeInheritedFromArray': SimTypeFunction([SimTypePointer(SimTypeRef("INHERITED_FROMW", SimStruct), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("FN_OBJECT_MGR_FUNCTS", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pInheritArray", "AceCnt", "pfnArray"]),
        #
        'TreeResetNamedSecurityInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="PROG_INVOKE_SETTING"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pObjectName", "Status", "pInvokeSetting", "Args", "SecuritySet"]), offset=0), SimTypeInt(signed=False, label="PROG_INVOKE_SETTING"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pObjectName", "ObjectType", "SecurityInfo", "pOwner", "pGroup", "pDacl", "pSacl", "KeepExplicit", "fnProgress", "ProgressInvokeSetting", "Args"]),
        #
        'TreeResetNamedSecurityInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="PROG_INVOKE_SETTING"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pObjectName", "Status", "pInvokeSetting", "Args", "SecuritySet"]), offset=0), SimTypeInt(signed=False, label="PROG_INVOKE_SETTING"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pObjectName", "ObjectType", "SecurityInfo", "pOwner", "pGroup", "pDacl", "pSacl", "KeepExplicit", "fnProgress", "ProgressInvokeSetting", "Args"]),
        #
        'TreeSetNamedSecurityInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="TREE_SEC_INFO"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="PROG_INVOKE_SETTING"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pObjectName", "Status", "pInvokeSetting", "Args", "SecuritySet"]), offset=0), SimTypeInt(signed=False, label="PROG_INVOKE_SETTING"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pObjectName", "ObjectType", "SecurityInfo", "pOwner", "pGroup", "pDacl", "pSacl", "dwAction", "fnProgress", "ProgressInvokeSetting", "Args"]),
        #
        'TreeSetNamedSecurityInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="TREE_SEC_INFO"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="PROG_INVOKE_SETTING"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pObjectName", "Status", "pInvokeSetting", "Args", "SecuritySet"]), offset=0), SimTypeInt(signed=False, label="PROG_INVOKE_SETTING"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pObjectName", "ObjectType", "SecurityInfo", "pOwner", "pGroup", "pDacl", "pSacl", "dwAction", "fnProgress", "ProgressInvokeSetting", "Args"]),
        #
        'BuildSecurityDescriptorA': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_A", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_A", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pOwner", "pGroup", "cCountOfAccessEntries", "pListOfAccessEntries", "cCountOfAuditEntries", "pListOfAuditEntries", "pOldSD", "pSizeNewSD", "pNewSD"]),
        #
        'BuildSecurityDescriptorW': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_W", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_W", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pOwner", "pGroup", "cCountOfAccessEntries", "pListOfAccessEntries", "cCountOfAuditEntries", "pListOfAuditEntries", "pOldSD", "pSizeNewSD", "pNewSD"]),
        #
        'LookupSecurityDescriptorPartsA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_A", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_A", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["ppOwner", "ppGroup", "pcCountOfAccessEntries", "ppListOfAccessEntries", "pcCountOfAuditEntries", "ppListOfAuditEntries", "pSD"]),
        #
        'LookupSecurityDescriptorPartsW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_W", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_W", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["ppOwner", "ppGroup", "pcCountOfAccessEntries", "ppListOfAccessEntries", "pcCountOfAuditEntries", "ppListOfAuditEntries", "pSD"]),
        #
        'BuildExplicitAccessWithNameA': SimTypeFunction([SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_A", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ACCESS_MODE"), SimTypeInt(signed=False, label="ACE_FLAGS")], SimTypeBottom(label="Void"), arg_names=["pExplicitAccess", "pTrusteeName", "AccessPermissions", "AccessMode", "Inheritance"]),
        #
        'BuildExplicitAccessWithNameW': SimTypeFunction([SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_W", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ACCESS_MODE"), SimTypeInt(signed=False, label="ACE_FLAGS")], SimTypeBottom(label="Void"), arg_names=["pExplicitAccess", "pTrusteeName", "AccessPermissions", "AccessMode", "Inheritance"]),
        #
        'BuildImpersonateExplicitAccessWithNameA': SimTypeFunction([SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_A", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ACCESS_MODE"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pExplicitAccess", "pTrusteeName", "pTrustee", "AccessPermissions", "AccessMode", "Inheritance"]),
        #
        'BuildImpersonateExplicitAccessWithNameW': SimTypeFunction([SimTypePointer(SimTypeRef("EXPLICIT_ACCESS_W", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ACCESS_MODE"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pExplicitAccess", "pTrusteeName", "pTrustee", "AccessPermissions", "AccessMode", "Inheritance"]),
        #
        'BuildTrusteeWithNameA': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pTrustee", "pName"]),
        #
        'BuildTrusteeWithNameW': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pTrustee", "pName"]),
        #
        'BuildImpersonateTrusteeA': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pTrustee", "pImpersonateTrustee"]),
        #
        'BuildImpersonateTrusteeW': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pTrustee", "pImpersonateTrustee"]),
        #
        'BuildTrusteeWithSidA': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pTrustee", "pSid"]),
        #
        'BuildTrusteeWithSidW': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pTrustee", "pSid"]),
        #
        'BuildTrusteeWithObjectsAndSidA': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0), SimTypePointer(SimTypeRef("OBJECTS_AND_SID", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pTrustee", "pObjSid", "pObjectGuid", "pInheritedObjectGuid", "pSid"]),
        #
        'BuildTrusteeWithObjectsAndSidW': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0), SimTypePointer(SimTypeRef("OBJECTS_AND_SID", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pTrustee", "pObjSid", "pObjectGuid", "pInheritedObjectGuid", "pSid"]),
        #
        'BuildTrusteeWithObjectsAndNameA': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0), SimTypePointer(SimTypeRef("OBJECTS_AND_NAME_A", SimStruct), offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pTrustee", "pObjName", "ObjectType", "ObjectTypeName", "InheritedObjectTypeName", "Name"]),
        #
        'BuildTrusteeWithObjectsAndNameW': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0), SimTypePointer(SimTypeRef("OBJECTS_AND_NAME_W", SimStruct), offset=0), SimTypeInt(signed=False, label="SE_OBJECT_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pTrustee", "pObjName", "ObjectType", "ObjectTypeName", "InheritedObjectTypeName", "Name"]),
        #
        'GetTrusteeNameA': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pTrustee"]),
        #
        'GetTrusteeNameW': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pTrustee"]),
        #
        'GetTrusteeTypeA': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0)], SimTypeInt(signed=False, label="TRUSTEE_TYPE"), arg_names=["pTrustee"]),
        #
        'GetTrusteeTypeW': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0)], SimTypeInt(signed=False, label="TRUSTEE_TYPE"), arg_names=["pTrustee"]),
        #
        'GetTrusteeFormA': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0)], SimTypeInt(signed=False, label="TRUSTEE_FORM"), arg_names=["pTrustee"]),
        #
        'GetTrusteeFormW': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0)], SimTypeInt(signed=False, label="TRUSTEE_FORM"), arg_names=["pTrustee"]),
        #
        'GetMultipleTrusteeOperationA': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0)], SimTypeInt(signed=False, label="MULTIPLE_TRUSTEE_OPERATION"), arg_names=["pTrustee"]),
        #
        'GetMultipleTrusteeOperationW': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0)], SimTypeInt(signed=False, label="MULTIPLE_TRUSTEE_OPERATION"), arg_names=["pTrustee"]),
        #
        'GetMultipleTrusteeA': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0)], SimTypePointer(SimTypeRef("TRUSTEE_A", SimStruct), offset=0), arg_names=["pTrustee"]),
        #
        'GetMultipleTrusteeW': SimTypeFunction([SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0)], SimTypePointer(SimTypeRef("TRUSTEE_W", SimStruct), offset=0), arg_names=["pTrustee"]),
        #
        'ConvertSidToStringSidA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Sid", "StringSid"]),
        #
        'ConvertSidToStringSidW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Sid", "StringSid"]),
        #
        'ConvertStringSidToSidA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["StringSid", "Sid"]),
        #
        'ConvertStringSidToSidW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["StringSid", "Sid"]),
        #
        'ConvertStringSecurityDescriptorToSecurityDescriptorA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["StringSecurityDescriptor", "StringSDRevision", "SecurityDescriptor", "SecurityDescriptorSize"]),
        #
        'ConvertStringSecurityDescriptorToSecurityDescriptorW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["StringSecurityDescriptor", "StringSDRevision", "SecurityDescriptor", "SecurityDescriptorSize"]),
        #
        'ConvertSecurityDescriptorToStringSecurityDescriptorA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityDescriptor", "RequestedStringSDRevision", "SecurityInformation", "StringSecurityDescriptor", "StringSecurityDescriptorLen"]),
        #
        'ConvertSecurityDescriptorToStringSecurityDescriptorW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityDescriptor", "RequestedStringSDRevision", "SecurityInformation", "StringSecurityDescriptor", "StringSecurityDescriptorLen"]),
        #
        'CredWriteW': SimTypeFunction([SimTypePointer(SimTypeRef("CREDENTIALW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Credential", "Flags"]),
        #
        'CredWriteA': SimTypeFunction([SimTypePointer(SimTypeRef("CREDENTIALA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Credential", "Flags"]),
        #
        'CredReadW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="CRED_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("CREDENTIALW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetName", "Type", "Flags", "Credential"]),
        #
        'CredReadA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="CRED_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("CREDENTIALA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetName", "Type", "Flags", "Credential"]),
        #
        'CredEnumerateW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="CRED_ENUMERATE_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeRef("CREDENTIALW", SimStruct), offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Flags", "Count", "Credential"]),
        #
        'CredEnumerateA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="CRED_ENUMERATE_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeRef("CREDENTIALA", SimStruct), offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Flags", "Count", "Credential"]),
        #
        'CredWriteDomainCredentialsW': SimTypeFunction([SimTypePointer(SimTypeRef("CREDENTIAL_TARGET_INFORMATIONW", SimStruct), offset=0), SimTypePointer(SimTypeRef("CREDENTIALW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetInfo", "Credential", "Flags"]),
        #
        'CredWriteDomainCredentialsA': SimTypeFunction([SimTypePointer(SimTypeRef("CREDENTIAL_TARGET_INFORMATIONA", SimStruct), offset=0), SimTypePointer(SimTypeRef("CREDENTIALA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetInfo", "Credential", "Flags"]),
        #
        'CredReadDomainCredentialsW': SimTypeFunction([SimTypePointer(SimTypeRef("CREDENTIAL_TARGET_INFORMATIONW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeRef("CREDENTIALW", SimStruct), offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetInfo", "Flags", "Count", "Credential"]),
        #
        'CredReadDomainCredentialsA': SimTypeFunction([SimTypePointer(SimTypeRef("CREDENTIAL_TARGET_INFORMATIONA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeRef("CREDENTIALA", SimStruct), offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetInfo", "Flags", "Count", "Credential"]),
        #
        'CredDeleteW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="CRED_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetName", "Type", "Flags"]),
        #
        'CredDeleteA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="CRED_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetName", "Type", "Flags"]),
        #
        'CredRenameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="CRED_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["OldTargetName", "NewTargetName", "Type", "Flags"]),
        #
        'CredRenameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="CRED_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["OldTargetName", "NewTargetName", "Type", "Flags"]),
        #
        'CredGetTargetInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("CREDENTIAL_TARGET_INFORMATIONW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetName", "Flags", "TargetInfo"]),
        #
        'CredGetTargetInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("CREDENTIAL_TARGET_INFORMATIONA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetName", "Flags", "TargetInfo"]),
        #
        'CredMarshalCredentialW': SimTypeFunction([SimTypeInt(signed=False, label="CRED_MARSHAL_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CredType", "Credential", "MarshaledCredential"]),
        #
        'CredMarshalCredentialA': SimTypeFunction([SimTypeInt(signed=False, label="CRED_MARSHAL_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CredType", "Credential", "MarshaledCredential"]),
        #
        'CredUnmarshalCredentialW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="CRED_MARSHAL_TYPE"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MarshaledCredential", "CredType", "Credential"]),
        #
        'CredUnmarshalCredentialA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="CRED_MARSHAL_TYPE"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MarshaledCredential", "CredType", "Credential"]),
        #
        'CredIsMarshaledCredentialW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MarshaledCredential"]),
        #
        'CredIsMarshaledCredentialA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MarshaledCredential"]),
        #
        'CredProtectW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="CRED_PROTECTION_TYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fAsSelf", "pszCredentials", "cchCredentials", "pszProtectedCredentials", "pcchMaxChars", "ProtectionType"]),
        #
        'CredProtectA': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="CRED_PROTECTION_TYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fAsSelf", "pszCredentials", "cchCredentials", "pszProtectedCredentials", "pcchMaxChars", "ProtectionType"]),
        #
        'CredUnprotectW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fAsSelf", "pszProtectedCredentials", "cchProtectedCredentials", "pszCredentials", "pcchMaxChars"]),
        #
        'CredUnprotectA': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fAsSelf", "pszProtectedCredentials", "cchProtectedCredentials", "pszCredentials", "pcchMaxChars"]),
        #
        'CredIsProtectedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="CRED_PROTECTION_TYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszProtectedCredentials", "pProtectionType"]),
        #
        'CredIsProtectedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="CRED_PROTECTION_TYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszProtectedCredentials", "pProtectionType"]),
        #
        'CredFindBestCredentialW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("CREDENTIALW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetName", "Type", "Flags", "Credential"]),
        #
        'CredFindBestCredentialA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("CREDENTIALA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetName", "Type", "Flags", "Credential"]),
        #
        'CredGetSessionTypes': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MaximumPersistCount", "MaximumPersist"]),
        #
        'CredFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Buffer"]),
        #
        'CryptAcquireContextA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phProv", "szContainer", "szProvider", "dwProvType", "dwFlags"]),
        #
        'CryptAcquireContextW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phProv", "szContainer", "szProvider", "dwProvType", "dwFlags"]),
        #
        'CryptReleaseContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProv", "dwFlags"]),
        #
        'CryptGenKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="ALG_ID"), SimTypeInt(signed=False, label="CRYPT_KEY_FLAGS"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProv", "Algid", "dwFlags", "phKey"]),
        #
        'CryptDeriveKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="ALG_ID"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProv", "Algid", "hBaseData", "dwFlags", "phKey"]),
        #
        'CryptDestroyKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey"]),
        #
        'CryptSetKeyParam': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="CRYPT_KEY_PARAM_ID"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "dwParam", "pbData", "dwFlags"]),
        #
        'CryptGetKeyParam': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="CRYPT_KEY_PARAM_ID"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "dwParam", "pbData", "pdwDataLen", "dwFlags"]),
        #
        'CryptSetHashParam': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="CRYPT_SET_HASH_PARAM"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash", "dwParam", "pbData", "dwFlags"]),
        #
        'CryptGetHashParam': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash", "dwParam", "pbData", "pdwDataLen", "dwFlags"]),
        #
        'CryptSetProvParam': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="CRYPT_SET_PROV_PARAM_ID"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProv", "dwParam", "pbData", "dwFlags"]),
        #
        'CryptGetProvParam': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProv", "dwParam", "pbData", "pdwDataLen", "dwFlags"]),
        #
        'CryptGenRandom': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProv", "dwLen", "pbBuffer"]),
        #
        'CryptGetUserKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProv", "dwKeySpec", "phUserKey"]),
        #
        'CryptExportKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="CRYPT_KEY_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "hExpKey", "dwBlobType", "dwFlags", "pbData", "pdwDataLen"]),
        #
        'CryptImportKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="CRYPT_KEY_FLAGS"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProv", "pbData", "dwDataLen", "hPubKey", "dwFlags", "phKey"]),
        #
        'CryptEncrypt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "hHash", "Final", "dwFlags", "pbData", "pdwDataLen", "dwBufLen"]),
        #
        'CryptDecrypt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "hHash", "Final", "dwFlags", "pbData", "pdwDataLen"]),
        #
        'CryptCreateHash': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="ALG_ID"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProv", "Algid", "hKey", "dwFlags", "phHash"]),
        #
        'CryptHashData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash", "pbData", "dwDataLen", "dwFlags"]),
        #
        'CryptHashSessionKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash", "hKey", "dwFlags"]),
        #
        'CryptDestroyHash': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash"]),
        #
        'CryptSignHashA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash", "dwKeySpec", "szDescription", "dwFlags", "pbSignature", "pdwSigLen"]),
        #
        'CryptSignHashW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash", "dwKeySpec", "szDescription", "dwFlags", "pbSignature", "pdwSigLen"]),
        #
        'CryptVerifySignatureA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash", "pbSignature", "dwSigLen", "hPubKey", "szDescription", "dwFlags"]),
        #
        'CryptVerifySignatureW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash", "pbSignature", "dwSigLen", "hPubKey", "szDescription", "dwFlags"]),
        #
        'CryptSetProviderA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszProvName", "dwProvType"]),
        #
        'CryptSetProviderW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszProvName", "dwProvType"]),
        #
        'CryptSetProviderExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszProvName", "dwProvType", "pdwReserved", "dwFlags"]),
        #
        'CryptSetProviderExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszProvName", "dwProvType", "pdwReserved", "dwFlags"]),
        #
        'CryptGetDefaultProviderA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwProvType", "pdwReserved", "dwFlags", "pszProvName", "pcbProvName"]),
        #
        'CryptGetDefaultProviderW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwProvType", "pdwReserved", "dwFlags", "pszProvName", "pcbProvName"]),
        #
        'CryptEnumProviderTypesA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwIndex", "pdwReserved", "dwFlags", "pdwProvType", "szTypeName", "pcbTypeName"]),
        #
        'CryptEnumProviderTypesW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwIndex", "pdwReserved", "dwFlags", "pdwProvType", "szTypeName", "pcbTypeName"]),
        #
        'CryptEnumProvidersA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwIndex", "pdwReserved", "dwFlags", "pdwProvType", "szProvName", "pcbProvName"]),
        #
        'CryptEnumProvidersW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwIndex", "pdwReserved", "dwFlags", "pdwProvType", "szProvName", "pcbProvName"]),
        #
        'CryptContextAddRef': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProv", "pdwReserved", "dwFlags"]),
        #
        'CryptDuplicateKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "pdwReserved", "dwFlags", "phKey"]),
        #
        'CryptDuplicateHash': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash", "pdwReserved", "dwFlags", "phHash"]),
        #
        'AccessCheck': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "ClientToken", "DesiredAccess", "GenericMapping", "PrivilegeSet", "PrivilegeSetLength", "GrantedAccess", "AccessStatus"]),
        #
        'AccessCheckAndAuditAlarmW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ObjectTypeName", "ObjectName", "SecurityDescriptor", "DesiredAccess", "GenericMapping", "ObjectCreation", "GrantedAccess", "AccessStatus", "pfGenerateOnClose"]),
        #
        'AccessCheckByType': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_TYPE_LIST", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "PrincipalSelfSid", "ClientToken", "DesiredAccess", "ObjectTypeList", "ObjectTypeListLength", "GenericMapping", "PrivilegeSet", "PrivilegeSetLength", "GrantedAccess", "AccessStatus"]),
        #
        'AccessCheckByTypeResultList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_TYPE_LIST", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "PrincipalSelfSid", "ClientToken", "DesiredAccess", "ObjectTypeList", "ObjectTypeListLength", "GenericMapping", "PrivilegeSet", "PrivilegeSetLength", "GrantedAccessList", "AccessStatusList"]),
        #
        'AccessCheckByTypeAndAuditAlarmW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="AUDIT_EVENT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_TYPE_LIST", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ObjectTypeName", "ObjectName", "SecurityDescriptor", "PrincipalSelfSid", "DesiredAccess", "AuditType", "Flags", "ObjectTypeList", "ObjectTypeListLength", "GenericMapping", "ObjectCreation", "GrantedAccess", "AccessStatus", "pfGenerateOnClose"]),
        #
        'AccessCheckByTypeResultListAndAuditAlarmW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="AUDIT_EVENT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_TYPE_LIST", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ObjectTypeName", "ObjectName", "SecurityDescriptor", "PrincipalSelfSid", "DesiredAccess", "AuditType", "Flags", "ObjectTypeList", "ObjectTypeListLength", "GenericMapping", "ObjectCreation", "GrantedAccessList", "AccessStatusList", "pfGenerateOnClose"]),
        #
        'AccessCheckByTypeResultListAndAuditAlarmByHandleW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="AUDIT_EVENT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_TYPE_LIST", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ClientToken", "ObjectTypeName", "ObjectName", "SecurityDescriptor", "PrincipalSelfSid", "DesiredAccess", "AuditType", "Flags", "ObjectTypeList", "ObjectTypeListLength", "GenericMapping", "ObjectCreation", "GrantedAccessList", "AccessStatusList", "pfGenerateOnClose"]),
        #
        'AddAccessAllowedAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "AccessMask", "pSid"]),
        #
        'AddAccessAllowedAceEx': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="ACE_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "AceFlags", "AccessMask", "pSid"]),
        #
        'AddAccessAllowedObjectAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="ACE_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "AceFlags", "AccessMask", "ObjectTypeGuid", "InheritedObjectTypeGuid", "pSid"]),
        #
        'AddAccessDeniedAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "AccessMask", "pSid"]),
        #
        'AddAccessDeniedAceEx': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="ACE_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "AceFlags", "AccessMask", "pSid"]),
        #
        'AddAccessDeniedObjectAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="ACE_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "AceFlags", "AccessMask", "ObjectTypeGuid", "InheritedObjectTypeGuid", "pSid"]),
        #
        'AddAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "dwStartingAceIndex", "pAceList", "nAceListLength"]),
        #
        'AddAuditAccessAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "dwAccessMask", "pSid", "bAuditSuccess", "bAuditFailure"]),
        #
        'AddAuditAccessAceEx': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="ACE_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "AceFlags", "dwAccessMask", "pSid", "bAuditSuccess", "bAuditFailure"]),
        #
        'AddAuditAccessObjectAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="ACE_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "AceFlags", "AccessMask", "ObjectTypeGuid", "InheritedObjectTypeGuid", "pSid", "bAuditSuccess", "bAuditFailure"]),
        #
        'AddMandatoryAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="ACE_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "AceFlags", "MandatoryPolicy", "pLabelSid"]),
        #
        'AdjustTokenGroups': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("TOKEN_GROUPS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TOKEN_GROUPS", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "ResetToDefault", "NewState", "BufferLength", "PreviousState", "ReturnLength"]),
        #
        'AdjustTokenPrivileges': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("TOKEN_PRIVILEGES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TOKEN_PRIVILEGES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "DisableAllPrivileges", "NewState", "BufferLength", "PreviousState", "ReturnLength"]),
        #
        'AllocateAndInitializeSid': SimTypeFunction([SimTypePointer(SimTypeRef("SID_IDENTIFIER_AUTHORITY", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIdentifierAuthority", "nSubAuthorityCount", "nSubAuthority0", "nSubAuthority1", "nSubAuthority2", "nSubAuthority3", "nSubAuthority4", "nSubAuthority5", "nSubAuthority6", "nSubAuthority7", "pSid"]),
        #
        'AllocateLocallyUniqueId': SimTypeFunction([SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Luid"]),
        #
        'AreAllAccessesGranted': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["GrantedAccess", "DesiredAccess"]),
        #
        'AreAnyAccessesGranted': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["GrantedAccess", "DesiredAccess"]),
        #
        'CheckTokenMembership': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "SidToCheck", "IsMember"]),
        #
        'ConvertToAutoInheritPrivateObjectSecurity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ParentDescriptor", "CurrentSecurityDescriptor", "NewSecurityDescriptor", "ObjectType", "IsDirectoryObject", "GenericMapping"]),
        #
        'CopySid': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nDestinationSidLength", "pDestinationSid", "pSourceSid"]),
        #
        'CreatePrivateObjectSecurity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ParentDescriptor", "CreatorDescriptor", "NewDescriptor", "IsDirectoryObject", "Token", "GenericMapping"]),
        #
        'CreatePrivateObjectSecurityEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="SECURITY_AUTO_INHERIT_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ParentDescriptor", "CreatorDescriptor", "NewDescriptor", "ObjectType", "IsContainerObject", "AutoInheritFlags", "Token", "GenericMapping"]),
        #
        'CreatePrivateObjectSecurityWithMultipleInheritance': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Guid"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="SECURITY_AUTO_INHERIT_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ParentDescriptor", "CreatorDescriptor", "NewDescriptor", "ObjectTypes", "GuidCount", "IsContainerObject", "AutoInheritFlags", "Token", "GenericMapping"]),
        #
        'CreateRestrictedToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CREATE_RESTRICTED_TOKEN_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SID_AND_ATTRIBUTES", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LUID_AND_ATTRIBUTES", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SID_AND_ATTRIBUTES", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExistingTokenHandle", "Flags", "DisableSidCount", "SidsToDisable", "DeletePrivilegeCount", "PrivilegesToDelete", "RestrictedSidCount", "SidsToRestrict", "NewTokenHandle"]),
        #
        'CreateWellKnownSid': SimTypeFunction([SimTypeInt(signed=False, label="WELL_KNOWN_SID_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["WellKnownSidType", "DomainSid", "pSid", "cbSid"]),
        #
        'EqualDomainSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSid1", "pSid2", "pfEqual"]),
        #
        'DeleteAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceIndex"]),
        #
        'DestroyPrivateObjectSecurity': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectDescriptor"]),
        #
        'DuplicateToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SECURITY_IMPERSONATION_LEVEL"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExistingTokenHandle", "ImpersonationLevel", "DuplicateTokenHandle"]),
        #
        'DuplicateTokenEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TOKEN_ACCESS_MASK"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="SECURITY_IMPERSONATION_LEVEL"), SimTypeInt(signed=False, label="TOKEN_TYPE"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hExistingToken", "dwDesiredAccess", "lpTokenAttributes", "ImpersonationLevel", "TokenType", "phNewToken"]),
        #
        'EqualPrefixSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSid1", "pSid2"]),
        #
        'EqualSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSid1", "pSid2"]),
        #
        'FindFirstFreeAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "pAce"]),
        #
        'FreeSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pSid"]),
        #
        'GetAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceIndex", "pAce"]),
        #
        'GetAclInformation': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ACL_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "pAclInformation", "nAclInformationLength", "dwAclInformationClass"]),
        #
        'GetFileSecurityW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "RequestedInformation", "pSecurityDescriptor", "nLength", "lpnLengthNeeded"]),
        #
        'GetKernelObjectSecurity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "RequestedInformation", "pSecurityDescriptor", "nLength", "lpnLengthNeeded"]),
        #
        'GetLengthSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pSid"]),
        #
        'GetPrivateObjectSecurity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectDescriptor", "SecurityInformation", "ResultantDescriptor", "DescriptorLength", "ReturnLength"]),
        #
        'GetSecurityDescriptorControl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "pControl", "lpdwRevision"]),
        #
        'GetSecurityDescriptorDacl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "lpbDaclPresent", "pDacl", "lpbDaclDefaulted"]),
        #
        'GetSecurityDescriptorGroup': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "pGroup", "lpbGroupDefaulted"]),
        #
        'GetSecurityDescriptorLength': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pSecurityDescriptor"]),
        #
        'GetSecurityDescriptorOwner': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "pOwner", "lpbOwnerDefaulted"]),
        #
        'GetSecurityDescriptorRMControl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SecurityDescriptor", "RMControl"]),
        #
        'GetSecurityDescriptorSacl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "lpbSaclPresent", "pSacl", "lpbSaclDefaulted"]),
        #
        'GetSidIdentifierAuthority': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("SID_IDENTIFIER_AUTHORITY", SimStruct), offset=0), arg_names=["pSid"]),
        #
        'GetSidLengthRequired': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["nSubAuthorityCount"]),
        #
        'GetSidSubAuthority': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), arg_names=["pSid", "nSubAuthority"]),
        #
        'GetSidSubAuthorityCount': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pSid"]),
        #
        'GetTokenInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TOKEN_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "TokenInformationClass", "TokenInformation", "TokenInformationLength", "ReturnLength"]),
        #
        'GetWindowsAccountDomainSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSid", "pDomainSid", "cbDomainSid"]),
        #
        'ImpersonateAnonymousToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ThreadHandle"]),
        #
        'ImpersonateLoggedOnUser': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken"]),
        #
        'ImpersonateSelf': SimTypeFunction([SimTypeInt(signed=False, label="SECURITY_IMPERSONATION_LEVEL")], SimTypeInt(signed=True, label="Int32"), arg_names=["ImpersonationLevel"]),
        #
        'InitializeAcl': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ACE_REVISION")], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "nAclLength", "dwAclRevision"]),
        #
        'InitializeSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "dwRevision"]),
        #
        'InitializeSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SID_IDENTIFIER_AUTHORITY", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["Sid", "pIdentifierAuthority", "nSubAuthorityCount"]),
        #
        'IsTokenRestricted': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle"]),
        #
        'IsValidAcl': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl"]),
        #
        'IsValidSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor"]),
        #
        'IsValidSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSid"]),
        #
        'IsWellKnownSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="WELL_KNOWN_SID_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSid", "WellKnownSidType"]),
        #
        'MakeAbsoluteSD': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSelfRelativeSecurityDescriptor", "pAbsoluteSecurityDescriptor", "lpdwAbsoluteSecurityDescriptorSize", "pDacl", "lpdwDaclSize", "pSacl", "lpdwSaclSize", "pOwner", "lpdwOwnerSize", "pPrimaryGroup", "lpdwPrimaryGroupSize"]),
        #
        'MakeSelfRelativeSD': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAbsoluteSecurityDescriptor", "pSelfRelativeSecurityDescriptor", "lpdwBufferLength"]),
        #
        'MapGenericMask': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["AccessMask", "GenericMapping"]),
        #
        'ObjectCloseAuditAlarmW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "GenerateOnClose"]),
        #
        'ObjectDeleteAuditAlarmW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "GenerateOnClose"]),
        #
        'ObjectOpenAuditAlarmW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ObjectTypeName", "ObjectName", "pSecurityDescriptor", "ClientToken", "DesiredAccess", "GrantedAccess", "Privileges", "ObjectCreation", "AccessGranted", "GenerateOnClose"]),
        #
        'ObjectPrivilegeAuditAlarmW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ClientToken", "DesiredAccess", "Privileges", "AccessGranted"]),
        #
        'PrivilegeCheck': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ClientToken", "RequiredPrivileges", "pfResult"]),
        #
        'PrivilegedServiceAuditAlarmW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "ServiceName", "ClientToken", "Privileges", "AccessGranted"]),
        #
        'QuerySecurityAccessMask': SimTypeFunction([SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["SecurityInformation", "DesiredAccess"]),
        #
        'RevertToSelf': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'SetAclInformation': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ACL_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "pAclInformation", "nAclInformationLength", "dwAclInformationClass"]),
        #
        'SetFileSecurityW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "SecurityInformation", "pSecurityDescriptor"]),
        #
        'SetKernelObjectSecurity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "SecurityInformation", "SecurityDescriptor"]),
        #
        'SetPrivateObjectSecurity': SimTypeFunction([SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityInformation", "ModificationDescriptor", "ObjectsSecurityDescriptor", "GenericMapping", "Token"]),
        #
        'SetPrivateObjectSecurityEx': SimTypeFunction([SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="SECURITY_AUTO_INHERIT_FLAGS"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityInformation", "ModificationDescriptor", "ObjectsSecurityDescriptor", "AutoInheritFlags", "GenericMapping", "Token"]),
        #
        'SetSecurityAccessMask': SimTypeFunction([SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["SecurityInformation", "DesiredAccess"]),
        #
        'SetSecurityDescriptorControl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="SECURITY_DESCRIPTOR_CONTROL"), SimTypeInt(signed=False, label="SECURITY_DESCRIPTOR_CONTROL")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "ControlBitsOfInterest", "ControlBitsToSet"]),
        #
        'SetSecurityDescriptorDacl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "bDaclPresent", "pDacl", "bDaclDefaulted"]),
        #
        'SetSecurityDescriptorGroup': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "pGroup", "bGroupDefaulted"]),
        #
        'SetSecurityDescriptorOwner': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "pOwner", "bOwnerDefaulted"]),
        #
        'SetSecurityDescriptorRMControl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SecurityDescriptor", "RMControl"]),
        #
        'SetSecurityDescriptorSacl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "bSaclPresent", "pSacl", "bSaclDefaulted"]),
        #
        'SetTokenInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TOKEN_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "TokenInformationClass", "TokenInformation", "TokenInformationLength"]),
        #
        'AccessCheckAndAuditAlarmA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ObjectTypeName", "ObjectName", "SecurityDescriptor", "DesiredAccess", "GenericMapping", "ObjectCreation", "GrantedAccess", "AccessStatus", "pfGenerateOnClose"]),
        #
        'AccessCheckByTypeAndAuditAlarmA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="AUDIT_EVENT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_TYPE_LIST", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ObjectTypeName", "ObjectName", "SecurityDescriptor", "PrincipalSelfSid", "DesiredAccess", "AuditType", "Flags", "ObjectTypeList", "ObjectTypeListLength", "GenericMapping", "ObjectCreation", "GrantedAccess", "AccessStatus", "pfGenerateOnClose"]),
        #
        'AccessCheckByTypeResultListAndAuditAlarmA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="AUDIT_EVENT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_TYPE_LIST", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ObjectTypeName", "ObjectName", "SecurityDescriptor", "PrincipalSelfSid", "DesiredAccess", "AuditType", "Flags", "ObjectTypeList", "ObjectTypeListLength", "GenericMapping", "ObjectCreation", "GrantedAccess", "AccessStatusList", "pfGenerateOnClose"]),
        #
        'AccessCheckByTypeResultListAndAuditAlarmByHandleA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="AUDIT_EVENT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_TYPE_LIST", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ClientToken", "ObjectTypeName", "ObjectName", "SecurityDescriptor", "PrincipalSelfSid", "DesiredAccess", "AuditType", "Flags", "ObjectTypeList", "ObjectTypeListLength", "GenericMapping", "ObjectCreation", "GrantedAccess", "AccessStatusList", "pfGenerateOnClose"]),
        #
        'ObjectOpenAuditAlarmA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ObjectTypeName", "ObjectName", "pSecurityDescriptor", "ClientToken", "DesiredAccess", "GrantedAccess", "Privileges", "ObjectCreation", "AccessGranted", "GenerateOnClose"]),
        #
        'ObjectPrivilegeAuditAlarmA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ClientToken", "DesiredAccess", "Privileges", "AccessGranted"]),
        #
        'ObjectCloseAuditAlarmA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "GenerateOnClose"]),
        #
        'ObjectDeleteAuditAlarmA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "GenerateOnClose"]),
        #
        'PrivilegedServiceAuditAlarmA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "ServiceName", "ClientToken", "Privileges", "AccessGranted"]),
        #
        'AddConditionalAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="ACE_FLAGS"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "AceFlags", "AceType", "AccessMask", "pSid", "ConditionStr", "ReturnLength"]),
        #
        'SetFileSecurityA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "SecurityInformation", "pSecurityDescriptor"]),
        #
        'GetFileSecurityA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "RequestedInformation", "pSecurityDescriptor", "nLength", "lpnLengthNeeded"]),
        #
        'LookupAccountSidA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SID_NAME_USE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemName", "Sid", "Name", "cchName", "ReferencedDomainName", "cchReferencedDomainName", "peUse"]),
        #
        'LookupAccountSidW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SID_NAME_USE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemName", "Sid", "Name", "cchName", "ReferencedDomainName", "cchReferencedDomainName", "peUse"]),
        #
        'LookupAccountNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SID_NAME_USE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemName", "lpAccountName", "Sid", "cbSid", "ReferencedDomainName", "cchReferencedDomainName", "peUse"]),
        #
        'LookupAccountNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SID_NAME_USE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemName", "lpAccountName", "Sid", "cbSid", "ReferencedDomainName", "cchReferencedDomainName", "peUse"]),
        #
        'LookupPrivilegeValueA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemName", "lpName", "lpLuid"]),
        #
        'LookupPrivilegeValueW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemName", "lpName", "lpLuid"]),
        #
        'LookupPrivilegeNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemName", "lpLuid", "lpName", "cchName"]),
        #
        'LookupPrivilegeNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemName", "lpLuid", "lpName", "cchName"]),
        #
        'LookupPrivilegeDisplayNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemName", "lpName", "lpDisplayName", "cchDisplayName", "lpLanguageId"]),
        #
        'LookupPrivilegeDisplayNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemName", "lpName", "lpDisplayName", "cchDisplayName", "lpLanguageId"]),
        #
        'LogonUserA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="LOGON32_LOGON"), SimTypeInt(signed=False, label="LOGON32_PROVIDER"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUsername", "lpszDomain", "lpszPassword", "dwLogonType", "dwLogonProvider", "phToken"]),
        #
        'LogonUserW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="LOGON32_LOGON"), SimTypeInt(signed=False, label="LOGON32_PROVIDER"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUsername", "lpszDomain", "lpszPassword", "dwLogonType", "dwLogonProvider", "phToken"]),
        #
        'LogonUserExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="LOGON32_LOGON"), SimTypeInt(signed=False, label="LOGON32_PROVIDER"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("QUOTA_LIMITS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUsername", "lpszDomain", "lpszPassword", "dwLogonType", "dwLogonProvider", "phToken", "ppLogonSid", "ppProfileBuffer", "pdwProfileLength", "pQuotaLimits"]),
        #
        'LogonUserExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="LOGON32_LOGON"), SimTypeInt(signed=False, label="LOGON32_PROVIDER"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("QUOTA_LIMITS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUsername", "lpszDomain", "lpszPassword", "dwLogonType", "dwLogonProvider", "phToken", "ppLogonSid", "ppProfileBuffer", "pdwProfileLength", "pQuotaLimits"]),
        #
        'QueryUsersOnEncryptedFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ENCRYPTION_CERTIFICATE_HASH_LIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "pUsers"]),
        #
        'QueryRecoveryAgentsOnEncryptedFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ENCRYPTION_CERTIFICATE_HASH_LIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "pRecoveryAgents"]),
        #
        'RemoveUsersFromEncryptedFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("ENCRYPTION_CERTIFICATE_HASH_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "pHashes"]),
        #
        'AddUsersToEncryptedFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("ENCRYPTION_CERTIFICATE_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "pEncryptionCertificates"]),
        #
        'SetUserFileEncryptionKey': SimTypeFunction([SimTypePointer(SimTypeRef("ENCRYPTION_CERTIFICATE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pEncryptionCertificate"]),
        #
        'SetUserFileEncryptionKeyEx': SimTypeFunction([SimTypePointer(SimTypeRef("ENCRYPTION_CERTIFICATE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pEncryptionCertificate", "dwCapabilities", "dwFlags", "pvReserved"]),
        #
        'FreeEncryptionCertificateHashList': SimTypeFunction([SimTypePointer(SimTypeRef("ENCRYPTION_CERTIFICATE_HASH_LIST", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pUsers"]),
        #
        'EncryptionDisable': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["DirPath", "Disable"]),
        #
        'DuplicateEncryptionInfoFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SrcFileName", "DstFileName", "dwCreationDistribution", "dwAttributes", "lpSecurityAttributes"]),
        #
        'GetEncryptedFileMetadata': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "pcbMetadata", "ppbMetadata"]),
        #
        'SetEncryptedFileMetadata': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("ENCRYPTION_CERTIFICATE_HASH", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ENCRYPTION_CERTIFICATE_HASH_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "pbOldMetadata", "pbNewMetadata", "pOwnerHash", "dwOperation", "pCertificatesAdded"]),
        #
        'FreeEncryptedFileMetadata': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pbMetadata"]),
        #
        'EncryptFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName"]),
        #
        'EncryptFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName"]),
        #
        'DecryptFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "dwReserved"]),
        #
        'DecryptFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "dwReserved"]),
        #
        'FileEncryptionStatusA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "lpStatus"]),
        #
        'FileEncryptionStatusW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "lpStatus"]),
        #
        'OpenEncryptedFileRawA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "ulFlags", "pvContext"]),
        #
        'OpenEncryptedFileRawW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "ulFlags", "pvContext"]),
        #
        'ReadEncryptedFileRaw': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pbData", "pvCallbackContext", "ulLength"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pfExportCallback", "pvCallbackContext", "pvContext"]),
        #
        'WriteEncryptedFileRaw': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pbData", "pvCallbackContext", "ulLength"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pfImportCallback", "pvCallbackContext", "pvContext"]),
        #
        'CloseEncryptedFileRaw': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pvContext"]),
        #
        'OperationStart': SimTypeFunction([SimTypePointer(SimTypeRef("OPERATION_START_PARAMETERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OperationStartParams"]),
        #
        'OperationEnd': SimTypeFunction([SimTypePointer(SimTypeRef("OPERATION_END_PARAMETERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OperationEndParams"]),
        #
        'OpenThreadWaitChainSession': SimTypeFunction([SimTypeInt(signed=False, label="OPEN_THREAD_WAIT_CHAIN_SESSION_FLAGS"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WAITCHAIN_NODE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["WctHandle", "Context", "CallbackStatus", "NodeCount", "NodeInfoArray", "IsCycle"]), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Flags", "callback"]),
        #
        'CloseThreadWaitChainSession': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["WctHandle"]),
        #
        'GetThreadWaitChain': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="WAIT_CHAIN_THREAD_OPTIONS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WAITCHAIN_NODE_INFO", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["WctHandle", "Context", "Flags", "ThreadId", "NodeCount", "NodeInfoArray", "IsCycle"]),
        #
        'RegisterWaitChainCOMCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeFunction([SimTypeBottom(label="Guid"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallStateCallback", "ActivationStateCallback"]),
        #
        'StartTraceW': SimTypeFunction([SimTypePointer(SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "InstanceName", "Properties"]),
        #
        'StartTraceA': SimTypeFunction([SimTypePointer(SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "InstanceName", "Properties"]),
        #
        'StopTraceW': SimTypeFunction([SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "InstanceName", "Properties"]),
        #
        'StopTraceA': SimTypeFunction([SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "InstanceName", "Properties"]),
        #
        'QueryTraceW': SimTypeFunction([SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "InstanceName", "Properties"]),
        #
        'QueryTraceA': SimTypeFunction([SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "InstanceName", "Properties"]),
        #
        'UpdateTraceW': SimTypeFunction([SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "InstanceName", "Properties"]),
        #
        'UpdateTraceA': SimTypeFunction([SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "InstanceName", "Properties"]),
        #
        'FlushTraceW': SimTypeFunction([SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "InstanceName", "Properties"]),
        #
        'FlushTraceA': SimTypeFunction([SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "InstanceName", "Properties"]),
        #
        'ControlTraceW': SimTypeFunction([SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0), SimTypeInt(signed=False, label="EVENT_TRACE_CONTROL")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "InstanceName", "Properties", "ControlCode"]),
        #
        'ControlTraceA': SimTypeFunction([SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0), SimTypeInt(signed=False, label="EVENT_TRACE_CONTROL")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "InstanceName", "Properties", "ControlCode"]),
        #
        'QueryAllTracesW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["PropertyArray", "PropertyArrayCount", "LoggerCount"]),
        #
        'QueryAllTracesA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("EVENT_TRACE_PROPERTIES", SimStruct), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["PropertyArray", "PropertyArrayCount", "LoggerCount"]),
        #
        'EnableTrace': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeRef("CONTROLTRACE_HANDLE", SimStruct)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Enable", "EnableFlag", "EnableLevel", "ControlGuid", "TraceHandle"]),
        #
        'EnableTraceEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EVENT_FILTER_DESCRIPTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["ProviderId", "SourceId", "TraceHandle", "IsEnabled", "Level", "MatchAnyKeyword", "MatchAllKeyword", "EnableProperty", "EnableFilterDesc"]),
        #
        'EnableTraceEx2': SimTypeFunction([SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ENABLE_TRACE_PARAMETERS", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "ProviderId", "ControlCode", "Level", "MatchAnyKeyword", "MatchAllKeyword", "Timeout", "EnableParameters"]),
        #
        'EnumerateTraceGuidsEx': SimTypeFunction([SimTypeInt(signed=False, label="TRACE_QUERY_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceQueryInfoClass", "InBuffer", "InBufferSize", "OutBuffer", "OutBufferSize", "ReturnLength"]),
        #
        'TraceSetInformation': SimTypeFunction([SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypeInt(signed=False, label="TRACE_QUERY_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["SessionHandle", "InformationClass", "TraceInformation", "InformationLength"]),
        #
        'TraceQueryInformation': SimTypeFunction([SimTypeRef("CONTROLTRACE_HANDLE", SimStruct), SimTypeInt(signed=False, label="TRACE_QUERY_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["SessionHandle", "InformationClass", "TraceInformation", "InformationLength", "ReturnLength"]),
        #
        'CreateTraceInstanceId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("EVENT_INSTANCE_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RegHandle", "InstInfo"]),
        #
        'TraceEvent': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("EVENT_TRACE_HEADER", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle", "EventTrace"]),
        #
        'TraceEventInstance': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("EVENT_INSTANCE_HEADER", SimStruct), offset=0), SimTypePointer(SimTypeRef("EVENT_INSTANCE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("EVENT_INSTANCE_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TraceHandle", "EventTrace", "InstInfo", "ParentInstInfo"]),
        #
        'RegisterTraceGuidsW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="WMIDPREQUESTCODE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestCode", "RequestContext", "BufferSize", "Buffer"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TRACE_GUID_REGISTRATION", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestAddress", "RequestContext", "ControlGuid", "GuidCount", "TraceGuidReg", "MofImagePath", "MofResourceName", "RegistrationHandle"]),
        #
        'RegisterTraceGuidsA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="WMIDPREQUESTCODE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestCode", "RequestContext", "BufferSize", "Buffer"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TRACE_GUID_REGISTRATION", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestAddress", "RequestContext", "ControlGuid", "GuidCount", "TraceGuidReg", "MofImagePath", "MofResourceName", "RegistrationHandle"]),
        #
        'EnumerateTraceGuids': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("TRACE_GUID_PROPERTIES", SimStruct), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["GuidPropertiesArray", "PropertyArrayCount", "GuidCount"]),
        #
        'UnregisterTraceGuids': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=False, label="UInt32"), arg_names=["RegistrationHandle"]),
        #
        'GetTraceLoggerHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["Buffer"]),
        #
        'GetTraceEnableLevel': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeChar(label="Byte"), arg_names=["TraceHandle"]),
        #
        'GetTraceEnableFlags': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=False, label="UInt32"), arg_names=["TraceHandle"]),
        #
        'OpenTraceW': SimTypeFunction([SimTypePointer(SimTypeRef("EVENT_TRACE_LOGFILEW", SimStruct), offset=0)], SimTypeRef("PROCESSTRACE_HANDLE", SimStruct), arg_names=["Logfile"]),
        #
        'ProcessTrace': SimTypeFunction([SimTypePointer(SimTypeRef("PROCESSTRACE_HANDLE", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["HandleArray", "HandleCount", "StartTime", "EndTime"]),
        #
        'CloseTrace': SimTypeFunction([SimTypeRef("PROCESSTRACE_HANDLE", SimStruct)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["TraceHandle"]),
        #
        'OpenTraceFromBufferStream': SimTypeFunction([SimTypePointer(SimTypeRef("ETW_OPEN_TRACE_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("ETW_BUFFER_HEADER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Buffer", "CallbackContext"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["Options", "BufferCompletionCallback", "BufferCompletionContext"]),
        #
        'OpenTraceFromRealTimeLogger': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("ETW_OPEN_TRACE_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRACE_LOGFILE_HEADER", SimStruct), offset=0)], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["LoggerName", "Options", "LogFileHeader"]),
        #
        'OpenTraceFromRealTimeLoggerWithAllocationOptions': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("ETW_OPEN_TRACE_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TRACE_LOGFILE_HEADER", SimStruct), offset=0)], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["LoggerName", "Options", "AllocationSize", "MemoryPartitionHandle", "LogFileHeader"]),
        #
        'OpenTraceFromFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("ETW_OPEN_TRACE_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRACE_LOGFILE_HEADER", SimStruct), offset=0)], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["LogFileName", "Options", "LogFileHeader"]),
        #
        'ProcessTraceBufferIncrementReference': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("ETW_BUFFER_HEADER", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TraceHandle", "Buffer"]),
        #
        'ProcessTraceBufferDecrementReference': SimTypeFunction([SimTypePointer(SimTypeRef("ETW_BUFFER_HEADER", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Buffer"]),
        #
        'ProcessTraceAddBufferToBufferStream': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("ETW_BUFFER_HEADER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["TraceHandle", "Buffer", "BufferSize"]),
        #
        'QueryTraceProcessingHandle': SimTypeFunction([SimTypeRef("PROCESSTRACE_HANDLE", SimStruct), SimTypeInt(signed=False, label="ETW_PROCESS_HANDLE_INFO_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["ProcessingHandle", "InformationClass", "InBuffer", "InBufferSize", "OutBuffer", "OutBufferSize", "ReturnLength"]),
        #
        'OpenTraceA': SimTypeFunction([SimTypePointer(SimTypeRef("EVENT_TRACE_LOGFILEA", SimStruct), offset=0)], SimTypeRef("PROCESSTRACE_HANDLE", SimStruct), arg_names=["Logfile"]),
        #
        'SetTraceCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("EVENT_TRACE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pEvent"]), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pGuid", "EventCallback"]),
        #
        'RemoveTraceCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pGuid"]),
        #
        'TraceMessage': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="TRACE_MESSAGE_FLAGS"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["LoggerHandle", "MessageFlags", "MessageGuid", "MessageNumber"]),
        #
        'TraceMessageVa': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="TRACE_MESSAGE_FLAGS"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["LoggerHandle", "MessageFlags", "MessageGuid", "MessageNumber", "MessageArgList"]),
        #
        'EventRegister': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="ENABLECALLBACK_ENABLED_STATE"), SimTypeChar(label="Byte"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("EVENT_FILTER_DESCRIPTOR", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["SourceId", "IsEnabled", "Level", "MatchAnyKeyword", "MatchAllKeyword", "FilterData", "CallbackContext"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProviderId", "EnableCallback", "CallbackContext", "RegHandle"]),
        #
        'EventUnregister': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=False, label="UInt32"), arg_names=["RegHandle"]),
        #
        'EventSetInformation': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="EVENT_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["RegHandle", "InformationClass", "EventInformation", "InformationLength"]),
        #
        'EventEnabled': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("EVENT_DESCRIPTOR", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["RegHandle", "EventDescriptor"]),
        #
        'EventProviderEnabled': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeChar(label="Byte"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeChar(label="Byte"), arg_names=["RegHandle", "Level", "Keyword"]),
        #
        'EventWrite': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("EVENT_DESCRIPTOR", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EVENT_DATA_DESCRIPTOR", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RegHandle", "EventDescriptor", "UserDataCount", "UserData"]),
        #
        'EventWriteTransfer': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("EVENT_DESCRIPTOR", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EVENT_DATA_DESCRIPTOR", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RegHandle", "EventDescriptor", "ActivityId", "RelatedActivityId", "UserDataCount", "UserData"]),
        #
        'EventWriteEx': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("EVENT_DESCRIPTOR", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EVENT_DATA_DESCRIPTOR", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RegHandle", "EventDescriptor", "Filter", "Flags", "ActivityId", "RelatedActivityId", "UserDataCount", "UserData"]),
        #
        'EventWriteString': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeChar(label="Byte"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RegHandle", "Level", "Keyword", "String"]),
        #
        'EventActivityIdControl': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ControlCode", "ActivityId"]),
        #
        'EventAccessControl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Guid", "Operation", "Sid", "Rights", "AllowOrDeny"]),
        #
        'EventAccessQuery': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Guid", "Buffer", "BufferSize"]),
        #
        'EventAccessRemove': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Guid"]),
        #
        'CveEventWrite': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CveId", "AdditionalDetails"]),
        #
        'ClearEventLogA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog", "lpBackupFileName"]),
        #
        'ClearEventLogW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog", "lpBackupFileName"]),
        #
        'BackupEventLogA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog", "lpBackupFileName"]),
        #
        'BackupEventLogW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog", "lpBackupFileName"]),
        #
        'CloseEventLog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog"]),
        #
        'DeregisterEventSource': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog"]),
        #
        'NotifyChangeEventLog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog", "hEvent"]),
        #
        'GetNumberOfEventLogRecords': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog", "NumberOfRecords"]),
        #
        'GetOldestEventLogRecord': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog", "OldestRecord"]),
        #
        'OpenEventLogA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpUNCServerName", "lpSourceName"]),
        #
        'OpenEventLogW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpUNCServerName", "lpSourceName"]),
        #
        'RegisterEventSourceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpUNCServerName", "lpSourceName"]),
        #
        'RegisterEventSourceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpUNCServerName", "lpSourceName"]),
        #
        'OpenBackupEventLogA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpUNCServerName", "lpFileName"]),
        #
        'OpenBackupEventLogW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpUNCServerName", "lpFileName"]),
        #
        'ReadEventLogA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="READ_EVENT_LOG_READ_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog", "dwReadFlags", "dwRecordOffset", "lpBuffer", "nNumberOfBytesToRead", "pnBytesRead", "pnMinNumberOfBytesNeeded"]),
        #
        'ReadEventLogW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="READ_EVENT_LOG_READ_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog", "dwReadFlags", "dwRecordOffset", "lpBuffer", "nNumberOfBytesToRead", "pnBytesRead", "pnMinNumberOfBytesNeeded"]),
        #
        'ReportEventA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="REPORT_EVENT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog", "wType", "wCategory", "dwEventID", "lpUserSid", "wNumStrings", "dwDataSize", "lpStrings", "lpRawData"]),
        #
        'ReportEventW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="REPORT_EVENT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog", "wType", "wCategory", "dwEventID", "lpUserSid", "wNumStrings", "dwDataSize", "lpStrings", "lpRawData"]),
        #
        'GetEventLogInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEventLog", "dwInfoLevel", "lpBuffer", "cbBufSize", "pcbBytesNeeded"]),
        #
        'InstallApplication': SimTypeFunction([SimTypePointer(SimTypeRef("INSTALLDATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInstallInfo"]),
        #
        'UninstallApplication': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProductCode", "dwStatus"]),
        #
        'CommandLineFromMsiDescriptor': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Descriptor", "CommandLine", "CommandLineLength"]),
        #
        'GetManagedApplications': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("MANAGEDAPPLICATION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pCategory", "dwQueryFlags", "dwInfoLevel", "pdwApps", "prgManagedApps"]),
        #
        'GetLocalManagedApplications': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LOCALMANAGEDAPPLICATION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["bUserApps", "pdwApps", "prgLocalApps"]),
        #
        'GetLocalManagedApplicationData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["ProductCode", "DisplayName", "SupportUrl"]),
        #
        'GetManagedApplicationCategories': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("APPCATEGORYINFOLIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwReserved", "pAppCategory"]),
        #
        'MSChapSrvChangePassword': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("LM_OWF_PASSWORD", SimStruct), offset=0), SimTypePointer(SimTypeRef("LM_OWF_PASSWORD", SimStruct), offset=0), SimTypePointer(SimTypeRef("LM_OWF_PASSWORD", SimStruct), offset=0), SimTypePointer(SimTypeRef("LM_OWF_PASSWORD", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerName", "UserName", "LmOldPresent", "LmOldOwfPassword", "LmNewOwfPassword", "NtOldOwfPassword", "NtNewOwfPassword"]),
        #
        'MSChapSrvChangePassword2': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SAMPR_ENCRYPTED_USER_PASSWORD", SimStruct), offset=0), SimTypePointer(SimTypeRef("ENCRYPTED_LM_OWF_PASSWORD", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("SAMPR_ENCRYPTED_USER_PASSWORD", SimStruct), offset=0), SimTypePointer(SimTypeRef("ENCRYPTED_LM_OWF_PASSWORD", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerName", "UserName", "NewPasswordEncryptedWithOldNt", "OldNtOwfPasswordEncryptedWithNewNt", "LmPresent", "NewPasswordEncryptedWithOldLm", "OldLmOwfPasswordEncryptedWithNewLmOrNt"]),
        #
        'PerfStartProvider': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestCode", "Buffer", "BufferSize"]), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProviderGuid", "ControlCallback", "phProvider"]),
        #
        'PerfStartProviderEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("PERF_PROVIDER_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProviderGuid", "ProviderContext", "Provider"]),
        #
        'PerfStopProvider': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProviderHandle"]),
        #
        'PerfSetCounterSetInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PERF_COUNTERSET_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProviderHandle", "Template", "TemplateSize"]),
        #
        'PerfCreateInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("PERF_COUNTERSET_INSTANCE", SimStruct), offset=0), arg_names=["ProviderHandle", "CounterSetGuid", "Name", "Id"]),
        #
        'PerfDeleteInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PERF_COUNTERSET_INSTANCE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Provider", "InstanceBlock"]),
        #
        'PerfQueryInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("PERF_COUNTERSET_INSTANCE", SimStruct), offset=0), arg_names=["ProviderHandle", "CounterSetGuid", "Name", "Id"]),
        #
        'PerfSetCounterRefValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PERF_COUNTERSET_INSTANCE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Provider", "Instance", "CounterId", "Address"]),
        #
        'PerfSetULongCounterValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PERF_COUNTERSET_INSTANCE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Provider", "Instance", "CounterId", "Value"]),
        #
        'PerfSetULongLongCounterValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PERF_COUNTERSET_INSTANCE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Provider", "Instance", "CounterId", "Value"]),
        #
        'PerfIncrementULongCounterValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PERF_COUNTERSET_INSTANCE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Provider", "Instance", "CounterId", "Value"]),
        #
        'PerfIncrementULongLongCounterValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PERF_COUNTERSET_INSTANCE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Provider", "Instance", "CounterId", "Value"]),
        #
        'PerfDecrementULongCounterValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PERF_COUNTERSET_INSTANCE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Provider", "Instance", "CounterId", "Value"]),
        #
        'PerfDecrementULongLongCounterValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PERF_COUNTERSET_INSTANCE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Provider", "Instance", "CounterId", "Value"]),
        #
        'PerfEnumerateCounterSet': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szMachine", "pCounterSetIds", "cCounterSetIds", "pcCounterSetIdsActual"]),
        #
        'PerfEnumerateCounterSetInstances': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("PERF_INSTANCE_HEADER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szMachine", "pCounterSetId", "pInstances", "cbInstances", "pcbInstancesActual"]),
        #
        'PerfQueryCounterSetRegistrationInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="PerfRegInfoType"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szMachine", "pCounterSetId", "requestCode", "requestLangId", "pbRegInfo", "cbRegInfo", "pcbRegInfoActual"]),
        #
        'PerfOpenQueryHandle': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szMachine", "phQuery"]),
        #
        'PerfCloseQueryHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery"]),
        #
        'PerfQueryCounterInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PERF_COUNTER_IDENTIFIER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery", "pCounters", "cbCounters", "pcbCountersActual"]),
        #
        'PerfQueryCounterData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PERF_DATA_HEADER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery", "pCounterBlock", "cbCounterBlock", "pcbCounterBlockActual"]),
        #
        'PerfAddCounters': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PERF_COUNTER_IDENTIFIER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery", "pCounters", "cbCounters"]),
        #
        'PerfDeleteCounters': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PERF_COUNTER_IDENTIFIER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery", "pCounters", "cbCounters"]),
        #
        'ImpersonateNamedPipeClient': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hNamedPipe"]),
        #
        'RegCloseKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey"]),
        #
        'RegOverridePredefKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "hNewHKey"]),
        #
        'RegOpenUserClassesRoot': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hToken", "dwOptions", "samDesired", "phkResult"]),
        #
        'RegOpenCurrentUser': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["samDesired", "phkResult"]),
        #
        'RegDisablePredefinedCache': SimTypeFunction([], SimTypeInt(signed=False, label="WIN32_ERROR")),
        #
        'RegDisablePredefinedCacheEx': SimTypeFunction([], SimTypeInt(signed=False, label="WIN32_ERROR")),
        #
        'RegConnectRegistryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpMachineName", "hKey", "phkResult"]),
        #
        'RegConnectRegistryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpMachineName", "hKey", "phkResult"]),
        #
        'RegConnectRegistryExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMachineName", "hKey", "Flags", "phkResult"]),
        #
        'RegConnectRegistryExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMachineName", "hKey", "Flags", "phkResult"]),
        #
        'RegCreateKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "phkResult"]),
        #
        'RegCreateKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "phkResult"]),
        #
        'RegCreateKeyExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="REG_OPEN_CREATE_OPTIONS"), SimTypeInt(signed=False, label="REG_SAM_FLAGS"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="REG_CREATE_KEY_DISPOSITION"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "Reserved", "lpClass", "dwOptions", "samDesired", "lpSecurityAttributes", "phkResult", "lpdwDisposition"]),
        #
        'RegCreateKeyExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="REG_OPEN_CREATE_OPTIONS"), SimTypeInt(signed=False, label="REG_SAM_FLAGS"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="REG_CREATE_KEY_DISPOSITION"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "Reserved", "lpClass", "dwOptions", "samDesired", "lpSecurityAttributes", "phkResult", "lpdwDisposition"]),
        #
        'RegCreateKeyTransactedA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="REG_OPEN_CREATE_OPTIONS"), SimTypeInt(signed=False, label="REG_SAM_FLAGS"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="REG_CREATE_KEY_DISPOSITION"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "Reserved", "lpClass", "dwOptions", "samDesired", "lpSecurityAttributes", "phkResult", "lpdwDisposition", "hTransaction", "pExtendedParemeter"]),
        #
        'RegCreateKeyTransactedW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="REG_OPEN_CREATE_OPTIONS"), SimTypeInt(signed=False, label="REG_SAM_FLAGS"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="REG_CREATE_KEY_DISPOSITION"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "Reserved", "lpClass", "dwOptions", "samDesired", "lpSecurityAttributes", "phkResult", "lpdwDisposition", "hTransaction", "pExtendedParemeter"]),
        #
        'RegDeleteKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey"]),
        #
        'RegDeleteKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey"]),
        #
        'RegDeleteKeyExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "samDesired", "Reserved"]),
        #
        'RegDeleteKeyExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "samDesired", "Reserved"]),
        #
        'RegDeleteKeyTransactedA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "samDesired", "Reserved", "hTransaction", "pExtendedParameter"]),
        #
        'RegDeleteKeyTransactedW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "samDesired", "Reserved", "hTransaction", "pExtendedParameter"]),
        #
        'RegDisableReflectionKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hBase"]),
        #
        'RegEnableReflectionKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hBase"]),
        #
        'RegQueryReflectionKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hBase", "bIsReflectionDisabled"]),
        #
        'RegDeleteValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpValueName"]),
        #
        'RegDeleteValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpValueName"]),
        #
        'RegEnumKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "dwIndex", "lpName", "cchName"]),
        #
        'RegEnumKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "dwIndex", "lpName", "cchName"]),
        #
        'RegEnumKeyExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "dwIndex", "lpName", "lpcchName", "lpReserved", "lpClass", "lpcchClass", "lpftLastWriteTime"]),
        #
        'RegEnumKeyExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "dwIndex", "lpName", "lpcchName", "lpReserved", "lpClass", "lpcchClass", "lpftLastWriteTime"]),
        #
        'RegEnumValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "dwIndex", "lpValueName", "lpcchValueName", "lpReserved", "lpType", "lpData", "lpcbData"]),
        #
        'RegEnumValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "dwIndex", "lpValueName", "lpcchValueName", "lpReserved", "lpType", "lpData", "lpcbData"]),
        #
        'RegFlushKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey"]),
        #
        'RegGetKeySecurity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "SecurityInformation", "pSecurityDescriptor", "lpcbSecurityDescriptor"]),
        #
        'RegLoadKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "lpFile"]),
        #
        'RegLoadKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "lpFile"]),
        #
        'RegNotifyChangeKeyValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="REG_NOTIFY_FILTER"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "bWatchSubtree", "dwNotifyFilter", "hEvent", "fAsynchronous"]),
        #
        'RegOpenKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "phkResult"]),
        #
        'RegOpenKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "phkResult"]),
        #
        'RegOpenKeyExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="REG_SAM_FLAGS"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "ulOptions", "samDesired", "phkResult"]),
        #
        'RegOpenKeyExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="REG_SAM_FLAGS"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "ulOptions", "samDesired", "phkResult"]),
        #
        'RegOpenKeyTransactedA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="REG_SAM_FLAGS"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "ulOptions", "samDesired", "phkResult", "hTransaction", "pExtendedParemeter"]),
        #
        'RegOpenKeyTransactedW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="REG_SAM_FLAGS"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "ulOptions", "samDesired", "phkResult", "hTransaction", "pExtendedParemeter"]),
        #
        'RegQueryInfoKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpClass", "lpcchClass", "lpReserved", "lpcSubKeys", "lpcbMaxSubKeyLen", "lpcbMaxClassLen", "lpcValues", "lpcbMaxValueNameLen", "lpcbMaxValueLen", "lpcbSecurityDescriptor", "lpftLastWriteTime"]),
        #
        'RegQueryInfoKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpClass", "lpcchClass", "lpReserved", "lpcSubKeys", "lpcbMaxSubKeyLen", "lpcbMaxClassLen", "lpcValues", "lpcbMaxValueNameLen", "lpcbMaxValueLen", "lpcbSecurityDescriptor", "lpftLastWriteTime"]),
        #
        'RegQueryValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "lpData", "lpcbData"]),
        #
        'RegQueryValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "lpData", "lpcbData"]),
        #
        'RegQueryMultipleValuesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("VALENTA", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "val_list", "num_vals", "lpValueBuf", "ldwTotsize"]),
        #
        'RegQueryMultipleValuesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("VALENTW", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "val_list", "num_vals", "lpValueBuf", "ldwTotsize"]),
        #
        'RegQueryValueExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="REG_VALUE_TYPE"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpValueName", "lpReserved", "lpType", "lpData", "lpcbData"]),
        #
        'RegQueryValueExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="REG_VALUE_TYPE"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpValueName", "lpReserved", "lpType", "lpData", "lpcbData"]),
        #
        'RegReplaceKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "lpNewFile", "lpOldFile"]),
        #
        'RegReplaceKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "lpNewFile", "lpOldFile"]),
        #
        'RegRestoreKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpFile", "dwFlags"]),
        #
        'RegRestoreKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpFile", "dwFlags"]),
        #
        'RegRenameKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKeyName", "lpNewKeyName"]),
        #
        'RegSaveKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpFile", "lpSecurityAttributes"]),
        #
        'RegSaveKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpFile", "lpSecurityAttributes"]),
        #
        'RegSetKeySecurity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "SecurityInformation", "pSecurityDescriptor"]),
        #
        'RegSetValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="REG_VALUE_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "dwType", "lpData", "cbData"]),
        #
        'RegSetValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="REG_VALUE_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "dwType", "lpData", "cbData"]),
        #
        'RegSetValueExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="REG_VALUE_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpValueName", "Reserved", "dwType", "lpData", "cbData"]),
        #
        'RegSetValueExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="REG_VALUE_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpValueName", "Reserved", "dwType", "lpData", "cbData"]),
        #
        'RegUnLoadKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey"]),
        #
        'RegUnLoadKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey"]),
        #
        'RegDeleteKeyValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "lpValueName"]),
        #
        'RegDeleteKeyValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "lpValueName"]),
        #
        'RegSetKeyValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "lpValueName", "dwType", "lpData", "cbData"]),
        #
        'RegSetKeyValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey", "lpValueName", "dwType", "lpData", "cbData"]),
        #
        'RegDeleteTreeA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey"]),
        #
        'RegDeleteTreeW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpSubKey"]),
        #
        'RegCopyTreeA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKeySrc", "lpSubKey", "hKeyDest"]),
        #
        'RegGetValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="REG_ROUTINE_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="REG_VALUE_TYPE"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hkey", "lpSubKey", "lpValue", "dwFlags", "pdwType", "pvData", "pcbData"]),
        #
        'RegGetValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="REG_ROUTINE_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="REG_VALUE_TYPE"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hkey", "lpSubKey", "lpValue", "dwFlags", "pdwType", "pvData", "pcbData"]),
        #
        'RegCopyTreeW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKeySrc", "lpSubKey", "hKeyDest"]),
        #
        'RegLoadMUIStringA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "pszValue", "pszOutBuf", "cbOutBuf", "pcbData", "Flags", "pszDirectory"]),
        #
        'RegLoadMUIStringW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "pszValue", "pszOutBuf", "cbOutBuf", "pcbData", "Flags", "pszDirectory"]),
        #
        'RegLoadAppKeyA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpFile", "phkResult", "samDesired", "dwOptions", "Reserved"]),
        #
        'RegLoadAppKeyW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpFile", "phkResult", "samDesired", "dwOptions", "Reserved"]),
        #
        'RegSaveKeyExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="REG_SAVE_FORMAT")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpFile", "lpSecurityAttributes", "Flags"]),
        #
        'RegSaveKeyExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="REG_SAVE_FORMAT")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hKey", "lpFile", "lpSecurityAttributes", "Flags"]),
        #
        'SetServiceBits': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hServiceStatus", "dwServiceBits", "bSetBitsOn", "bUpdateImmediately"]),
        #
        'ChangeServiceConfigA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ENUM_SERVICE_TYPE"), SimTypeInt(signed=False, label="SERVICE_START_TYPE"), SimTypeInt(signed=False, label="SERVICE_ERROR"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwServiceType", "dwStartType", "dwErrorControl", "lpBinaryPathName", "lpLoadOrderGroup", "lpdwTagId", "lpDependencies", "lpServiceStartName", "lpPassword", "lpDisplayName"]),
        #
        'ChangeServiceConfigW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ENUM_SERVICE_TYPE"), SimTypeInt(signed=False, label="SERVICE_START_TYPE"), SimTypeInt(signed=False, label="SERVICE_ERROR"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwServiceType", "dwStartType", "dwErrorControl", "lpBinaryPathName", "lpLoadOrderGroup", "lpdwTagId", "lpDependencies", "lpServiceStartName", "lpPassword", "lpDisplayName"]),
        #
        'ChangeServiceConfig2A': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SERVICE_CONFIG"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwInfoLevel", "lpInfo"]),
        #
        'ChangeServiceConfig2W': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SERVICE_CONFIG"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwInfoLevel", "lpInfo"]),
        #
        'CloseServiceHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSCObject"]),
        #
        'ControlService': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SERVICE_STATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwControl", "lpServiceStatus"]),
        #
        'CreateServiceA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ENUM_SERVICE_TYPE"), SimTypeInt(signed=False, label="SERVICE_START_TYPE"), SimTypeInt(signed=False, label="SERVICE_ERROR"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hSCManager", "lpServiceName", "lpDisplayName", "dwDesiredAccess", "dwServiceType", "dwStartType", "dwErrorControl", "lpBinaryPathName", "lpLoadOrderGroup", "lpdwTagId", "lpDependencies", "lpServiceStartName", "lpPassword"]),
        #
        'CreateServiceW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ENUM_SERVICE_TYPE"), SimTypeInt(signed=False, label="SERVICE_START_TYPE"), SimTypeInt(signed=False, label="SERVICE_ERROR"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hSCManager", "lpServiceName", "lpDisplayName", "dwDesiredAccess", "dwServiceType", "dwStartType", "dwErrorControl", "lpBinaryPathName", "lpLoadOrderGroup", "lpdwTagId", "lpDependencies", "lpServiceStartName", "lpPassword"]),
        #
        'DeleteService': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService"]),
        #
        'EnumDependentServicesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ENUM_SERVICE_STATE"), SimTypePointer(SimTypeRef("ENUM_SERVICE_STATUSA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwServiceState", "lpServices", "cbBufSize", "pcbBytesNeeded", "lpServicesReturned"]),
        #
        'EnumDependentServicesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ENUM_SERVICE_STATE"), SimTypePointer(SimTypeRef("ENUM_SERVICE_STATUSW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwServiceState", "lpServices", "cbBufSize", "pcbBytesNeeded", "lpServicesReturned"]),
        #
        'EnumServicesStatusA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ENUM_SERVICE_TYPE"), SimTypeInt(signed=False, label="ENUM_SERVICE_STATE"), SimTypePointer(SimTypeRef("ENUM_SERVICE_STATUSA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSCManager", "dwServiceType", "dwServiceState", "lpServices", "cbBufSize", "pcbBytesNeeded", "lpServicesReturned", "lpResumeHandle"]),
        #
        'EnumServicesStatusW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ENUM_SERVICE_TYPE"), SimTypeInt(signed=False, label="ENUM_SERVICE_STATE"), SimTypePointer(SimTypeRef("ENUM_SERVICE_STATUSW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSCManager", "dwServiceType", "dwServiceState", "lpServices", "cbBufSize", "pcbBytesNeeded", "lpServicesReturned", "lpResumeHandle"]),
        #
        'EnumServicesStatusExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SC_ENUM_TYPE"), SimTypeInt(signed=False, label="ENUM_SERVICE_TYPE"), SimTypeInt(signed=False, label="ENUM_SERVICE_STATE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSCManager", "InfoLevel", "dwServiceType", "dwServiceState", "lpServices", "cbBufSize", "pcbBytesNeeded", "lpServicesReturned", "lpResumeHandle", "pszGroupName"]),
        #
        'EnumServicesStatusExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SC_ENUM_TYPE"), SimTypeInt(signed=False, label="ENUM_SERVICE_TYPE"), SimTypeInt(signed=False, label="ENUM_SERVICE_STATE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSCManager", "InfoLevel", "dwServiceType", "dwServiceState", "lpServices", "cbBufSize", "pcbBytesNeeded", "lpServicesReturned", "lpResumeHandle", "pszGroupName"]),
        #
        'GetServiceKeyNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSCManager", "lpDisplayName", "lpServiceName", "lpcchBuffer"]),
        #
        'GetServiceKeyNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSCManager", "lpDisplayName", "lpServiceName", "lpcchBuffer"]),
        #
        'GetServiceDisplayNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSCManager", "lpServiceName", "lpDisplayName", "lpcchBuffer"]),
        #
        'GetServiceDisplayNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSCManager", "lpServiceName", "lpDisplayName", "lpcchBuffer"]),
        #
        'LockServiceDatabase': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hSCManager"]),
        #
        'NotifyBootConfigStatus': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["BootAcceptable"]),
        #
        'OpenSCManagerA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpMachineName", "lpDatabaseName", "dwDesiredAccess"]),
        #
        'OpenSCManagerW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpMachineName", "lpDatabaseName", "dwDesiredAccess"]),
        #
        'OpenServiceA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hSCManager", "lpServiceName", "dwDesiredAccess"]),
        #
        'OpenServiceW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hSCManager", "lpServiceName", "dwDesiredAccess"]),
        #
        'QueryServiceConfigA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("QUERY_SERVICE_CONFIGA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "lpServiceConfig", "cbBufSize", "pcbBytesNeeded"]),
        #
        'QueryServiceConfigW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("QUERY_SERVICE_CONFIGW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "lpServiceConfig", "cbBufSize", "pcbBytesNeeded"]),
        #
        'QueryServiceConfig2A': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SERVICE_CONFIG"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwInfoLevel", "lpBuffer", "cbBufSize", "pcbBytesNeeded"]),
        #
        'QueryServiceConfig2W': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SERVICE_CONFIG"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwInfoLevel", "lpBuffer", "cbBufSize", "pcbBytesNeeded"]),
        #
        'QueryServiceLockStatusA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("QUERY_SERVICE_LOCK_STATUSA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSCManager", "lpLockStatus", "cbBufSize", "pcbBytesNeeded"]),
        #
        'QueryServiceLockStatusW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("QUERY_SERVICE_LOCK_STATUSW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSCManager", "lpLockStatus", "cbBufSize", "pcbBytesNeeded"]),
        #
        'QueryServiceObjectSecurity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwSecurityInformation", "lpSecurityDescriptor", "cbBufSize", "pcbBytesNeeded"]),
        #
        'QueryServiceStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SERVICE_STATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "lpServiceStatus"]),
        #
        'QueryServiceStatusEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SC_STATUS_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "InfoLevel", "lpBuffer", "cbBufSize", "pcbBytesNeeded"]),
        #
        'RegisterServiceCtrlHandlerA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwControl"]), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpServiceName", "lpHandlerProc"]),
        #
        'RegisterServiceCtrlHandlerW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwControl"]), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpServiceName", "lpHandlerProc"]),
        #
        'RegisterServiceCtrlHandlerExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwControl", "dwEventType", "lpEventData", "lpContext"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpServiceName", "lpHandlerProc", "lpContext"]),
        #
        'RegisterServiceCtrlHandlerExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwControl", "dwEventType", "lpEventData", "lpContext"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpServiceName", "lpHandlerProc", "lpContext"]),
        #
        'SetServiceObjectSecurity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwSecurityInformation", "lpSecurityDescriptor"]),
        #
        'SetServiceStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SERVICE_STATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hServiceStatus", "lpServiceStatus"]),
        #
        'StartServiceCtrlDispatcherA': SimTypeFunction([SimTypePointer(SimTypeRef("SERVICE_TABLE_ENTRYA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpServiceStartTable"]),
        #
        'StartServiceCtrlDispatcherW': SimTypeFunction([SimTypePointer(SimTypeRef("SERVICE_TABLE_ENTRYW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpServiceStartTable"]),
        #
        'StartServiceA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwNumServiceArgs", "lpServiceArgVectors"]),
        #
        'StartServiceW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwNumServiceArgs", "lpServiceArgVectors"]),
        #
        'UnlockServiceDatabase': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ScLock"]),
        #
        'NotifyServiceStatusChangeA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SERVICE_NOTIFY"), SimTypePointer(SimTypeRef("SERVICE_NOTIFY_2A", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hService", "dwNotifyMask", "pNotifyBuffer"]),
        #
        'NotifyServiceStatusChangeW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SERVICE_NOTIFY"), SimTypePointer(SimTypeRef("SERVICE_NOTIFY_2W", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hService", "dwNotifyMask", "pNotifyBuffer"]),
        #
        'ControlServiceExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwControl", "dwInfoLevel", "pControlParams"]),
        #
        'ControlServiceExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "dwControl", "dwInfoLevel", "pControlParams"]),
        #
        'QueryServiceDynamicInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hServiceStatus", "dwInfoLevel", "ppDynamicInfo"]),
        #
        'WaitServiceState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hService", "dwNotify", "dwTimeout", "hCancelEvent"]),
        #
        'InitiateSystemShutdownA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMachineName", "lpMessage", "dwTimeout", "bForceAppsClosed", "bRebootAfterShutdown"]),
        #
        'InitiateSystemShutdownW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMachineName", "lpMessage", "dwTimeout", "bForceAppsClosed", "bRebootAfterShutdown"]),
        #
        'AbortSystemShutdownA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMachineName"]),
        #
        'AbortSystemShutdownW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMachineName"]),
        #
        'InitiateSystemShutdownExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="SHUTDOWN_REASON")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMachineName", "lpMessage", "dwTimeout", "bForceAppsClosed", "bRebootAfterShutdown", "dwReason"]),
        #
        'InitiateSystemShutdownExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="SHUTDOWN_REASON")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMachineName", "lpMessage", "dwTimeout", "bForceAppsClosed", "bRebootAfterShutdown", "dwReason"]),
        #
        'InitiateShutdownA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="SHUTDOWN_FLAGS"), SimTypeInt(signed=False, label="SHUTDOWN_REASON")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpMachineName", "lpMessage", "dwGracePeriod", "dwShutdownFlags", "dwReason"]),
        #
        'InitiateShutdownW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="SHUTDOWN_FLAGS"), SimTypeInt(signed=False, label="SHUTDOWN_REASON")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpMachineName", "lpMessage", "dwGracePeriod", "dwShutdownFlags", "dwReason"]),
        #
        'CheckForHiberboot': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pHiberboot", "bClearFlag"]),
        #
        'CreateProcessAsUserW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="PROCESS_CREATION_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("STARTUPINFOW", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROCESS_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken", "lpApplicationName", "lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"]),
        #
        'SetThreadToken': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Thread", "Token"]),
        #
        'OpenProcessToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TOKEN_ACCESS_MASK"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "DesiredAccess", "TokenHandle"]),
        #
        'OpenThreadToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TOKEN_ACCESS_MASK"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ThreadHandle", "DesiredAccess", "OpenAsSelf", "TokenHandle"]),
        #
        'CreateProcessAsUserA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="PROCESS_CREATION_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("STARTUPINFOA", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROCESS_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken", "lpApplicationName", "lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"]),
        #
        'CreateProcessWithLogonW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="CREATE_PROCESS_LOGON_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="PROCESS_CREATION_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("STARTUPINFOW", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROCESS_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpUsername", "lpDomain", "lpPassword", "dwLogonFlags", "lpApplicationName", "lpCommandLine", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"]),
        #
        'CreateProcessWithTokenW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CREATE_PROCESS_LOGON_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="PROCESS_CREATION_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("STARTUPINFOW", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROCESS_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken", "dwLogonFlags", "lpApplicationName", "lpCommandLine", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"]),
        #
        'EnumDynamicTimeZoneInformation': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DYNAMIC_TIME_ZONE_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwIndex", "lpTimeZoneInformation"]),
        #
        'GetDynamicTimeZoneInformationEffectiveYears': SimTypeFunction([SimTypePointer(SimTypeRef("DYNAMIC_TIME_ZONE_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpTimeZoneInformation", "FirstYear", "LastYear"]),
        #
        'GetUserNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpBuffer", "pcbBuffer"]),
        #
        'GetUserNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpBuffer", "pcbBuffer"]),
        #
        'IsTokenUntrusted': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle"]),
        #
        'GetCurrentHwProfileA': SimTypeFunction([SimTypePointer(SimTypeRef("HW_PROFILE_INFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpHwProfileInfo"]),
        #
        'GetCurrentHwProfileW': SimTypeFunction([SimTypePointer(SimTypeRef("HW_PROFILE_INFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpHwProfileInfo"]),
        #
        'GetInformationCodeAuthzLevelW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiFreeBuffer': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetNamedSecurityInfoExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiQuerySingleInstanceMultipleA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertSecurityDescriptorToAccessA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CredProfileLoaded': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'WmiExecuteMethodW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ProcessIdleTasksW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'MD4Final': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction013': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CredpConvertOneCredentialSize': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'EncryptedFileKeyInfo': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfBackupEventLogFileW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'MD4Update': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CloseCodeAuthzLevel': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'EnumServiceGroupW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetSecurityInfoExA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfReportEventA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction027': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaEnumeratePrivilegesOfAccount': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction024': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertAccessToSecurityDescriptorW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiDevInstToInstanceNameA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiEnumerateGuids': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SaferiRegisterExtensionDll': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaCreateSecret': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfOpenEventLogW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfOpenEventLogA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaGetUserName': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'A_SHAInit': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaOpenPolicySce': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfChangeNotify': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'I_ScSetServiceBitsA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiOpenBlock': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetAccessPermissionsForObjectA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaICLookupNames': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'UnregisterIdleTask': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction025': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfRegisterEventSourceA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction010': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiMofEnumerateResourcesA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertSDToStringSDRootDomainW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'A_SHAFinal': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaSetSecurityObject': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaSetSystemAccessAccount': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiFileHandleToInstanceNameA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'FreeEncryptedFileKeyInfo': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaGetRemoteUserName': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'EventWriteStartScenario': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction014': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'AddUsersToEncryptedFileEx': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfRegisterEventSourceW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CredEncryptAndMarshalBinaryBlob': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SaferiPopulateDefaultsInRegistry': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SaferiSearchMatchingHashRules': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaGetSystemAccessAccount': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfReadEventLogW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiExecuteMethodA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiSetSingleInstanceA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaLookupPrivilegeValue': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiSetSingleItemW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiQueryAllDataA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CredBackupCredentials': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertStringSDToSDRootDomainW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaCreateTrustedDomain': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetAccessPermissionsForObjectW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfReportEventW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetSecurityInfoExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction015': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfCloseEventLog': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'UsePinForEncryptedFilesW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaManageSidNameMapping': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CredProfileUnloaded': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'SystemFunction007': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiSetSingleItemA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetNamedSecurityInfoExA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiFileHandleToInstanceNameW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SaferiChangeRegistryScope': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'MD5Init': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'I_ScPnPGetServiceName': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CredpConvertTargetInfo': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetSecurityInfoExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'IsValidRelativeSecurityDescriptor': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CredpDecodeCredential': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'I_ScSetServiceBitsW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegisterIdleTask': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction017': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction033': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CancelOverlappedAccess': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'TrusteeAccessToObjectW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaOpenSecret': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'EventWriteEndScenario': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ComputeAccessTokenFromCodeAuthzLevel': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaGetQuotasForAccount': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'I_ScIsSecurityProcess': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'SetNamedSecurityInfoExA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction019': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiQueryAllDataMultipleW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfDeregisterEventSource': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfClearEventLogFileA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertAccessToSecurityDescriptorA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction016': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiMofEnumerateResourcesW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiNotificationRegistrationA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaAddPrivilegesToAccount': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction003': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction020': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction006': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertStringSDToSDRootDomainA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertStringSDToSDDomainW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertSecurityDescriptorToAccessNamedA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaRemovePrivilegesFromAccount': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiQuerySingleInstanceW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ProcessIdleTasks': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'ConvertStringSDToSDDomainA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetEntriesInAuditListA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'NotifyServiceStatusChange': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaQuerySecurityObject': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfBackupEventLogFileA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction018': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SaferiIsDllAllowed': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiCloseBlock': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction035': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiSetSingleInstanceW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CredpEncodeCredential': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiQueryAllDataMultipleA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction030': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaOpenTrustedDomain': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction005': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction012': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction031': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetEntriesInAuditListW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'I_ScGetCurrentGroupStateW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetNamedSecurityInfoExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfNumberOfRecords': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaClearAuditLog': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CreateCodeAuthzLevel': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'MD5Update': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfFlushEventLog': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'MakeAbsoluteSD2': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SaferiCompareTokenLevels': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetEntriesInAccessListA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction008': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'FlushEfsCache': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertSecurityDescriptorToAccessNamedW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaCreateAccount': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaEnumerateAccounts': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiQueryGuidInformation': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'I_QueryTagInformation': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetInformationCodeAuthzLevelW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaQueryInfoTrustedDomain': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction028': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiQuerySingleInstanceMultipleW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiReceiveNotificationsW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaSetInformationTrustedDomain': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'I_ScValidatePnPService': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfReportEventAndSourceW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertSDToStringSDRootDomainA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'TrusteeAccessToObjectA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'MD4Init': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetOverlappedAccessResults': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LogonUserExExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaLookupPrivilegeName': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaOpenAccount': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CredRestoreCredentials': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'I_ScSendTSMessage': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaLookupPrivilegeDisplayName': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'I_ScSendPnPMessage': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaICLookupSids': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction034': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SaferiRecordEventLogEntry': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction026': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfOpenBackupEventLogA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction029': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaSetSecret': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfReadEventLogA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CredpConvertCredential': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertSecurityDescriptorToAccessW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaICLookupSidsWithCreds': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetSecurityInfoExA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction001': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'UsePinForEncryptedFilesA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaQuerySecret': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaEnumeratePrivileges': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction032': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetInformationCodeAuthzPolicyW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CredpEncodeSecret': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfOpenBackupEventLogW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'IdentifyCodeAuthzLevelW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction009': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'A_SHAUpdate': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaDelete': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfClearEventLogFileW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetInformationCodeAuthzPolicyW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'I_ScQueryServiceConfig': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiDevInstToInstanceNameW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction022': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiQueryAllDataW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiQuerySingleInstanceA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ElfOldestRecord': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction002': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetEntriesInAccessListW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaSetQuotasForAccount': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CredReadByTokenHandle': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction004': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LsaICLookupNamesWithCreds': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction023': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction011': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiNotificationRegistrationW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SystemFunction021': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WmiReceiveNotificationsA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'MD5Final': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
    }

lib.set_prototypes(prototypes)
