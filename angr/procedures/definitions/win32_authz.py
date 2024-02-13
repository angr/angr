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
lib.set_library_names("authz.dll")
prototypes = \
    {
        #
        'AuthzAccessCheck': SimTypeFunction([SimTypeInt(signed=False, label="AUTHZ_ACCESS_CHECK_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("AUTHZ_ACCESS_REQUEST", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("AUTHZ_ACCESS_REPLY", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "hAuthzClientContext", "pRequest", "hAuditEvent", "pSecurityDescriptor", "OptionalSecurityDescriptorArray", "OptionalSecurityDescriptorCount", "pReply", "phAccessCheckResults"]),
        #
        'AuthzCachedAccessCheck': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("AUTHZ_ACCESS_REQUEST", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("AUTHZ_ACCESS_REPLY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "hAccessCheckResults", "pRequest", "hAuditEvent", "pReply"]),
        #
        'AuthzOpenObjectAudit': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("AUTHZ_ACCESS_REQUEST", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("AUTHZ_ACCESS_REPLY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "hAuthzClientContext", "pRequest", "hAuditEvent", "pSecurityDescriptor", "OptionalSecurityDescriptorArray", "OptionalSecurityDescriptorCount", "pReply"]),
        #
        'AuthzFreeHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAccessCheckResults"]),
        #
        'AuthzInitializeResourceManager': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("ACE_HEADER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAuthzClientContext", "pAce", "pArgs", "pbAceApplicable"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SID_AND_ATTRIBUTES", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SID_AND_ATTRIBUTES", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAuthzClientContext", "Args", "pSidAttrArray", "pSidCount", "pRestrictedSidAttrArray", "pRestrictedSidCount"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("SID_AND_ATTRIBUTES", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pSidAttrArray"]), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "pfnDynamicAccessCheck", "pfnComputeDynamicGroups", "pfnFreeDynamicGroups", "szResourceManagerName", "phAuthzResourceManager"]),
        #
        'AuthzInitializeResourceManagerEx': SimTypeFunction([SimTypeInt(signed=False, label="AUTHZ_RESOURCE_MANAGER_FLAGS"), SimTypePointer(SimTypeRef("AUTHZ_INIT_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "pAuthzInitInfo", "phAuthzResourceManager"]),
        #
        'AuthzInitializeRemoteResourceManager': SimTypeFunction([SimTypePointer(SimTypeRef("AUTHZ_RPC_INIT_INFO_CLIENT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRpcInitInfo", "phAuthzResourceManager"]),
        #
        'AuthzFreeResourceManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAuthzResourceManager"]),
        #
        'AuthzInitializeContextFromToken': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeRef("LUID", SimStruct), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "TokenHandle", "hAuthzResourceManager", "pExpirationTime", "Identifier", "DynamicGroupArgs", "phAuthzClientContext"]),
        #
        'AuthzInitializeContextFromSid': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeRef("LUID", SimStruct), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "UserSid", "hAuthzResourceManager", "pExpirationTime", "Identifier", "DynamicGroupArgs", "phAuthzClientContext"]),
        #
        'AuthzInitializeContextFromAuthzContext': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeRef("LUID", SimStruct), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "hAuthzClientContext", "pExpirationTime", "Identifier", "DynamicGroupArgs", "phNewAuthzClientContext"]),
        #
        'AuthzInitializeCompoundContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["UserContext", "DeviceContext", "phCompoundContext"]),
        #
        'AuthzAddSidsToContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SID_AND_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SID_AND_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAuthzClientContext", "Sids", "SidCount", "RestrictedSids", "RestrictedSidCount", "phNewAuthzClientContext"]),
        #
        'AuthzModifySecurityAttributes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="AUTHZ_SECURITY_ATTRIBUTE_OPERATION"), offset=0), SimTypePointer(SimTypeRef("AUTHZ_SECURITY_ATTRIBUTES_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAuthzClientContext", "pOperations", "pAttributes"]),
        #
        'AuthzModifyClaims': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="AUTHZ_CONTEXT_INFORMATION_CLASS"), SimTypePointer(SimTypeInt(signed=False, label="AUTHZ_SECURITY_ATTRIBUTE_OPERATION"), offset=0), SimTypePointer(SimTypeRef("AUTHZ_SECURITY_ATTRIBUTES_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAuthzClientContext", "ClaimClass", "pClaimOperations", "pClaims"]),
        #
        'AuthzModifySids': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="AUTHZ_CONTEXT_INFORMATION_CLASS"), SimTypePointer(SimTypeInt(signed=False, label="AUTHZ_SID_OPERATION"), offset=0), SimTypePointer(SimTypeRef("TOKEN_GROUPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAuthzClientContext", "SidClass", "pSidOperations", "pSids"]),
        #
        'AuthzSetAppContainerInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SID_AND_ATTRIBUTES", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAuthzClientContext", "pAppContainerSid", "CapabilityCount", "pCapabilitySids"]),
        #
        'AuthzGetInformationFromContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="AUTHZ_CONTEXT_INFORMATION_CLASS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAuthzClientContext", "InfoClass", "BufferSize", "pSizeRequired", "Buffer"]),
        #
        'AuthzFreeContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAuthzClientContext"]),
        #
        'AuthzInitializeObjectAccessAuditEvent': SimTypeFunction([SimTypeInt(signed=False, label="AUTHZ_INITIALIZE_OBJECT_ACCESS_AUDIT_EVENT_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "hAuditEventType", "szOperationType", "szObjectType", "szObjectName", "szAdditionalInfo", "phAuditEvent", "dwAdditionalParameterCount"]),
        #
        'AuthzInitializeObjectAccessAuditEvent2': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "hAuditEventType", "szOperationType", "szObjectType", "szObjectName", "szAdditionalInfo", "szAdditionalInfo2", "phAuditEvent", "dwAdditionalParameterCount"]),
        #
        'AuthzFreeAuditEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAuditEvent"]),
        #
        'AuthzEvaluateSacl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("AUTHZ_ACCESS_REQUEST", SimStruct), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AuthzClientContext", "pRequest", "Sacl", "GrantedAccess", "AccessGranted", "pbGenerateAudit"]),
        #
        'AuthzInstallSecurityEventSource': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("AUTHZ_SOURCE_SCHEMA_REGISTRATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pRegistration"]),
        #
        'AuthzUninstallSecurityEventSource': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "szEventSourceName"]),
        #
        'AuthzEnumerateSecurityEventSources': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("AUTHZ_SOURCE_SCHEMA_REGISTRATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "Buffer", "pdwCount", "pdwLength"]),
        #
        'AuthzRegisterSecurityEventSource': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "szEventSourceName", "phEventProvider"]),
        #
        'AuthzUnregisterSecurityEventSource': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "phEventProvider"]),
        #
        'AuthzReportSecurityEvent': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "hEventProvider", "dwAuditId", "pUserSid", "dwCount"]),
        #
        'AuthzReportSecurityEventFromParams': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("AUDIT_PARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "hEventProvider", "dwAuditId", "pUserSid", "pParams"]),
        #
        'AuthzRegisterCapChangeNotification': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpThreadParameter"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phCapChangeSubscription", "pfnCapChangeCallback", "pCallbackContext"]),
        #
        'AuthzUnregisterCapChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCapChangeSubscription"]),
        #
        'AuthzFreeCentralAccessPolicyCache': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
    }

lib.set_prototypes(prototypes)
