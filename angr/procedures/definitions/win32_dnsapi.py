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
lib.set_library_names("dnsapi.dll")
prototypes = \
    {
        #
        'DnsQueryConfig': SimTypeFunction([SimTypeInt(signed=False, label="DNS_CONFIG_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Config", "Flag", "pwsAdapterName", "pReserved", "pBuffer", "pBufLen"]),
        #
        'DnsRecordCopyEx': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypeInt(signed=False, label="DNS_CHARSET"), SimTypeInt(signed=False, label="DNS_CHARSET")], SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), arg_names=["pRecord", "CharSetIn", "CharSetOut"]),
        #
        'DnsRecordSetCopyEx': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypeInt(signed=False, label="DNS_CHARSET"), SimTypeInt(signed=False, label="DNS_CHARSET")], SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), arg_names=["pRecordSet", "CharSetIn", "CharSetOut"]),
        #
        'DnsRecordCompare': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRecord1", "pRecord2"]),
        #
        'DnsRecordSetCompare': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRR1", "pRR2", "ppDiff1", "ppDiff2"]),
        #
        'DnsRecordSetDetach': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0)], SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), arg_names=["pRecordList"]),
        #
        'DnsFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="DNS_FREE_TYPE")], SimTypeBottom(label="Void"), arg_names=["pData", "FreeType"]),
        #
        'DnsQuery_A': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="DNS_TYPE"), SimTypeInt(signed=False, label="DNS_QUERY_OPTIONS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pszName", "wType", "Options", "pExtra", "ppQueryResults", "pReserved"]),
        #
        'DnsQuery_UTF8': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="DNS_TYPE"), SimTypeInt(signed=False, label="DNS_QUERY_OPTIONS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pszName", "wType", "Options", "pExtra", "ppQueryResults", "pReserved"]),
        #
        'DnsQuery_W': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="DNS_TYPE"), SimTypeInt(signed=False, label="DNS_QUERY_OPTIONS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pszName", "wType", "Options", "pExtra", "ppQueryResults", "pReserved"]),
        #
        'DnsFreeCustomServers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DNS_CUSTOM_SERVER", SimStruct), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["pcServers", "ppServers"]),
        #
        'DnsGetApplicationSettings': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DNS_CUSTOM_SERVER", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("DNS_APPLICATION_SETTINGS", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pcServers", "ppDefaultServers", "pSettings"]),
        #
        'DnsSetApplicationSettings': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DNS_CUSTOM_SERVER", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("DNS_APPLICATION_SETTINGS", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["cServers", "pServers", "pSettings"]),
        #
        'DnsQueryEx': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_QUERY_REQUEST", SimStruct), offset=0), SimTypePointer(SimTypeRef("DNS_QUERY_RESULT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DNS_QUERY_CANCEL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pQueryRequest", "pQueryResults", "pCancelHandle"]),
        #
        'DnsCancelQuery': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_QUERY_CANCEL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCancelHandle"]),
        #
        'DnsQueryRawResultFree': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_QUERY_RAW_RESULT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["queryResults"]),
        #
        'DnsQueryRaw': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_QUERY_RAW_REQUEST", SimStruct), offset=0), SimTypePointer(SimTypeRef("DNS_QUERY_RAW_CANCEL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["queryRequest", "cancelHandle"]),
        #
        'DnsCancelQueryRaw': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_QUERY_RAW_CANCEL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cancelHandle"]),
        #
        'DnsAcquireContextHandle_W': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CredentialFlags", "Credentials", "pContext"]),
        #
        'DnsAcquireContextHandle_A': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CredentialFlags", "Credentials", "pContext"]),
        #
        'DnsReleaseContextHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hContext"]),
        #
        'DnsModifyRecordsInSet_W': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAddRecords", "pDeleteRecords", "Options", "hCredentials", "pExtraList", "pReserved"]),
        #
        'DnsModifyRecordsInSet_A': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAddRecords", "pDeleteRecords", "Options", "hCredentials", "pExtraList", "pReserved"]),
        #
        'DnsModifyRecordsInSet_UTF8': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAddRecords", "pDeleteRecords", "Options", "hCredentials", "pExtraList", "pReserved"]),
        #
        'DnsReplaceRecordSetW': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pReplaceSet", "Options", "hContext", "pExtraInfo", "pReserved"]),
        #
        'DnsReplaceRecordSetA': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pReplaceSet", "Options", "hContext", "pExtraInfo", "pReserved"]),
        #
        'DnsReplaceRecordSetUTF8': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pReplaceSet", "Options", "hContext", "pExtraInfo", "pReserved"]),
        #
        'DnsValidateName_W': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="DNS_NAME_FORMAT")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszName", "Format"]),
        #
        'DnsValidateName_A': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="DNS_NAME_FORMAT")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszName", "Format"]),
        #
        'DnsValidateName_UTF8': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="DNS_NAME_FORMAT")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszName", "Format"]),
        #
        'DnsNameCompare_A': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pName1", "pName2"]),
        #
        'DnsNameCompare_W': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pName1", "pName2"]),
        #
        'DnsWriteQuestionToBuffer_W': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_MESSAGE_BUFFER", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pDnsBuffer", "pdwBufferSize", "pszName", "wType", "Xid", "fRecursionDesired"]),
        #
        'DnsWriteQuestionToBuffer_UTF8': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_MESSAGE_BUFFER", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pDnsBuffer", "pdwBufferSize", "pszName", "wType", "Xid", "fRecursionDesired"]),
        #
        'DnsExtractRecordsFromMessage_W': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_MESSAGE_BUFFER", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDnsBuffer", "wMessageLength", "ppRecord"]),
        #
        'DnsExtractRecordsFromMessage_UTF8': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_MESSAGE_BUFFER", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypePointer(SimTypeRef("DNS_RECORDA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDnsBuffer", "wMessageLength", "ppRecord"]),
        #
        'DnsGetProxyInformation': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DNS_PROXY_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("DNS_PROXY_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["completionContext", "status"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hostName", "proxyInformation", "defaultProxyInformation", "completionRoutine", "completionContext"]),
        #
        'DnsFreeProxyName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["proxyName"]),
        #
        'DnsConnectionGetProxyInfoForHostUrl': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DNS_CONNECTION_PROXY_INFO_EX", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszHostUrl", "pSelectionContext", "dwSelectionContextLength", "dwExplicitInterfaceIndex", "pProxyInfoEx"]),
        #
        'DnsConnectionGetProxyInfoForHostUrlEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DNS_CONNECTION_PROXY_INFO_EX", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszHostUrl", "pSelectionContext", "dwSelectionContextLength", "dwExplicitInterfaceIndex", "pwszConnectionName", "pProxyInfoEx"]),
        #
        'DnsConnectionFreeProxyInfoEx': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_CONNECTION_PROXY_INFO_EX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pProxyInfoEx"]),
        #
        'DnsConnectionGetProxyInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="DNS_CONNECTION_PROXY_TYPE"), SimTypePointer(SimTypeRef("DNS_CONNECTION_PROXY_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszConnectionName", "Type", "pProxyInfo"]),
        #
        'DnsConnectionFreeProxyInfo': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_CONNECTION_PROXY_INFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pProxyInfo"]),
        #
        'DnsConnectionSetProxyInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="DNS_CONNECTION_PROXY_TYPE"), SimTypePointer(SimTypeRef("DNS_CONNECTION_PROXY_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszConnectionName", "Type", "pProxyInfo"]),
        #
        'DnsConnectionDeleteProxyInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="DNS_CONNECTION_PROXY_TYPE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszConnectionName", "Type"]),
        #
        'DnsConnectionGetProxyList': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DNS_CONNECTION_PROXY_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszConnectionName", "pProxyList"]),
        #
        'DnsConnectionFreeProxyList': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_CONNECTION_PROXY_LIST", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pProxyList"]),
        #
        'DnsConnectionGetNameList': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_CONNECTION_NAME_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pNameList"]),
        #
        'DnsConnectionFreeNameList': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_CONNECTION_NAME_LIST", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pNameList"]),
        #
        'DnsConnectionUpdateIfIndexTable': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_CONNECTION_IFINDEX_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pConnectionIfIndexEntries"]),
        #
        'DnsConnectionSetPolicyEntries': SimTypeFunction([SimTypeInt(signed=False, label="DNS_CONNECTION_POLICY_TAG"), SimTypePointer(SimTypeRef("DNS_CONNECTION_POLICY_ENTRY_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PolicyEntryTag", "pPolicyEntryList"]),
        #
        'DnsConnectionDeletePolicyEntries': SimTypeFunction([SimTypeInt(signed=False, label="DNS_CONNECTION_POLICY_TAG")], SimTypeInt(signed=False, label="UInt32"), arg_names=["PolicyEntryTag"]),
        #
        'DnsServiceConstructInstance': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimUnion({"IP6Dword": SimTypeArray(SimTypeInt(signed=False, label="UInt32"), 4), "IP6Word": SimTypeArray(SimTypeShort(signed=False, label="UInt16"), 8), "IP6Byte": SimTypeArray(SimTypeChar(label="Byte"), 16)}, name="<anon>", label="None"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0)], SimTypePointer(SimTypeRef("DNS_SERVICE_INSTANCE", SimStruct), offset=0), arg_names=["pServiceName", "pHostName", "pIp4", "pIp6", "wPort", "wPriority", "wWeight", "dwPropertiesCount", "keys", "values"]),
        #
        'DnsServiceCopyInstance': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_SERVICE_INSTANCE", SimStruct), offset=0)], SimTypePointer(SimTypeRef("DNS_SERVICE_INSTANCE", SimStruct), offset=0), arg_names=["pOrig"]),
        #
        'DnsServiceFreeInstance': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_SERVICE_INSTANCE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pInstance"]),
        #
        'DnsServiceBrowse': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_SERVICE_BROWSE_REQUEST", SimStruct), offset=0), SimTypePointer(SimTypeRef("DNS_SERVICE_CANCEL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRequest", "pCancel"]),
        #
        'DnsServiceBrowseCancel': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_SERVICE_CANCEL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCancelHandle"]),
        #
        'DnsServiceResolve': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_SERVICE_RESOLVE_REQUEST", SimStruct), offset=0), SimTypePointer(SimTypeRef("DNS_SERVICE_CANCEL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRequest", "pCancel"]),
        #
        'DnsServiceResolveCancel': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_SERVICE_CANCEL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCancelHandle"]),
        #
        'DnsServiceRegister': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_SERVICE_REGISTER_REQUEST", SimStruct), offset=0), SimTypePointer(SimTypeRef("DNS_SERVICE_CANCEL", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRequest", "pCancel"]),
        #
        'DnsServiceDeRegister': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_SERVICE_REGISTER_REQUEST", SimStruct), offset=0), SimTypePointer(SimTypeRef("DNS_SERVICE_CANCEL", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRequest", "pCancel"]),
        #
        'DnsServiceRegisterCancel': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_SERVICE_CANCEL", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pCancelHandle"]),
        #
        'DnsStartMulticastQuery': SimTypeFunction([SimTypePointer(SimTypeRef("MDNS_QUERY_REQUEST", SimStruct), offset=0), SimTypePointer(SimTypeRef("MDNS_QUERY_HANDLE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pQueryRequest", "pHandle"]),
        #
        'DnsStopMulticastQuery': SimTypeFunction([SimTypePointer(SimTypeRef("MDNS_QUERY_HANDLE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pHandle"]),
    }

lib.set_prototypes(prototypes)
