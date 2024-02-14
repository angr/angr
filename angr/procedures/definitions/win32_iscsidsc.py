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
lib.set_library_names("iscsidsc.dll")
prototypes = \
    {
        #
        'GetIScsiVersionInformation': SimTypeFunction([SimTypePointer(SimTypeRef("ISCSI_VERSION_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["VersionInfo"]),
        #
        'GetIScsiTargetInformationW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="TARGET_INFORMATION_CLASS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TargetName", "DiscoveryMechanism", "InfoClass", "BufferSize", "Buffer"]),
        #
        'GetIScsiTargetInformationA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="TARGET_INFORMATION_CLASS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TargetName", "DiscoveryMechanism", "InfoClass", "BufferSize", "Buffer"]),
        #
        'AddIScsiConnectionW': SimTypeFunction([SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALW", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("ISCSI_LOGIN_OPTIONS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["UniqueSessionId", "Reserved", "InitiatorPortNumber", "TargetPortal", "SecurityFlags", "LoginOptions", "KeySize", "Key", "ConnectionId"]),
        #
        'AddIScsiConnectionA': SimTypeFunction([SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALA", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("ISCSI_LOGIN_OPTIONS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["UniqueSessionId", "Reserved", "InitiatorPortNumber", "TargetPortal", "SecurityFlags", "LoginOptions", "KeySize", "Key", "ConnectionId"]),
        #
        'RemoveIScsiConnection': SimTypeFunction([SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0), SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["UniqueSessionId", "ConnectionId"]),
        #
        'ReportIScsiTargetsW': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ForceUpdate", "BufferSize", "Buffer"]),
        #
        'ReportIScsiTargetsA': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ForceUpdate", "BufferSize", "Buffer"]),
        #
        'AddIScsiStaticTargetW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("ISCSI_TARGET_MAPPINGW", SimStruct), offset=0), SimTypePointer(SimTypeRef("ISCSI_LOGIN_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTAL_GROUPW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TargetName", "TargetAlias", "TargetFlags", "Persist", "Mappings", "LoginOptions", "PortalGroup"]),
        #
        'AddIScsiStaticTargetA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("ISCSI_TARGET_MAPPINGA", SimStruct), offset=0), SimTypePointer(SimTypeRef("ISCSI_LOGIN_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTAL_GROUPA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TargetName", "TargetAlias", "TargetFlags", "Persist", "Mappings", "LoginOptions", "PortalGroup"]),
        #
        'RemoveIScsiStaticTargetW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TargetName"]),
        #
        'RemoveIScsiStaticTargetA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TargetName"]),
        #
        'AddIScsiSendTargetPortalW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ISCSI_LOGIN_OPTIONS", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorInstance", "InitiatorPortNumber", "LoginOptions", "SecurityFlags", "Portal"]),
        #
        'AddIScsiSendTargetPortalA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ISCSI_LOGIN_OPTIONS", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorInstance", "InitiatorPortNumber", "LoginOptions", "SecurityFlags", "Portal"]),
        #
        'RemoveIScsiSendTargetPortalW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorInstance", "InitiatorPortNumber", "Portal"]),
        #
        'RemoveIScsiSendTargetPortalA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorInstance", "InitiatorPortNumber", "Portal"]),
        #
        'RefreshIScsiSendTargetPortalW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorInstance", "InitiatorPortNumber", "Portal"]),
        #
        'RefreshIScsiSendTargetPortalA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorInstance", "InitiatorPortNumber", "Portal"]),
        #
        'ReportIScsiSendTargetPortalsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTAL_INFOW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PortalCount", "PortalInfo"]),
        #
        'ReportIScsiSendTargetPortalsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTAL_INFOA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PortalCount", "PortalInfo"]),
        #
        'ReportIScsiSendTargetPortalsExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTAL_INFO_EXW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PortalCount", "PortalInfoSize", "PortalInfo"]),
        #
        'ReportIScsiSendTargetPortalsExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTAL_INFO_EXA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PortalCount", "PortalInfoSize", "PortalInfo"]),
        #
        'LoginIScsiTargetW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALW", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("ISCSI_TARGET_MAPPINGW", SimStruct), offset=0), SimTypePointer(SimTypeRef("ISCSI_LOGIN_OPTIONS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0), SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TargetName", "IsInformationalSession", "InitiatorInstance", "InitiatorPortNumber", "TargetPortal", "SecurityFlags", "Mappings", "LoginOptions", "KeySize", "Key", "IsPersistent", "UniqueSessionId", "UniqueConnectionId"]),
        #
        'LoginIScsiTargetA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALA", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("ISCSI_TARGET_MAPPINGA", SimStruct), offset=0), SimTypePointer(SimTypeRef("ISCSI_LOGIN_OPTIONS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0), SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TargetName", "IsInformationalSession", "InitiatorInstance", "InitiatorPortNumber", "TargetPortal", "SecurityFlags", "Mappings", "LoginOptions", "KeySize", "Key", "IsPersistent", "UniqueSessionId", "UniqueConnectionId"]),
        #
        'ReportIScsiPersistentLoginsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PERSISTENT_ISCSI_LOGIN_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Count", "PersistentLoginInfo", "BufferSizeInBytes"]),
        #
        'ReportIScsiPersistentLoginsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PERSISTENT_ISCSI_LOGIN_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Count", "PersistentLoginInfo", "BufferSizeInBytes"]),
        #
        'LogoutIScsiTarget': SimTypeFunction([SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["UniqueSessionId"]),
        #
        'RemoveIScsiPersistentTargetW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorInstance", "InitiatorPortNumber", "TargetName", "Portal"]),
        #
        'RemoveIScsiPersistentTargetA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorInstance", "InitiatorPortNumber", "TargetName", "Portal"]),
        #
        'SendScsiInquiry': SimTypeFunction([SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["UniqueSessionId", "Lun", "EvpdCmddt", "PageCode", "ScsiStatus", "ResponseSize", "ResponseBuffer", "SenseSize", "SenseBuffer"]),
        #
        'SendScsiReadCapacity': SimTypeFunction([SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["UniqueSessionId", "Lun", "ScsiStatus", "ResponseSize", "ResponseBuffer", "SenseSize", "SenseBuffer"]),
        #
        'SendScsiReportLuns': SimTypeFunction([SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["UniqueSessionId", "ScsiStatus", "ResponseSize", "ResponseBuffer", "SenseSize", "SenseBuffer"]),
        #
        'ReportIScsiInitiatorListW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSize", "Buffer"]),
        #
        'ReportIScsiInitiatorListA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSize", "Buffer"]),
        #
        'ReportActiveIScsiTargetMappingsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ISCSI_TARGET_MAPPINGW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSize", "MappingCount", "Mappings"]),
        #
        'ReportActiveIScsiTargetMappingsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ISCSI_TARGET_MAPPINGA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSize", "MappingCount", "Mappings"]),
        #
        'SetIScsiTunnelModeOuterAddressW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorName", "InitiatorPortNumber", "DestinationAddress", "OuterModeAddress", "Persist"]),
        #
        'SetIScsiTunnelModeOuterAddressA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorName", "InitiatorPortNumber", "DestinationAddress", "OuterModeAddress", "Persist"]),
        #
        'SetIScsiIKEInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IKE_AUTHENTICATION_INFORMATION", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorName", "InitiatorPortNumber", "AuthInfo", "Persist"]),
        #
        'SetIScsiIKEInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IKE_AUTHENTICATION_INFORMATION", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorName", "InitiatorPortNumber", "AuthInfo", "Persist"]),
        #
        'GetIScsiIKEInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("IKE_AUTHENTICATION_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorName", "InitiatorPortNumber", "Reserved", "AuthInfo"]),
        #
        'GetIScsiIKEInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("IKE_AUTHENTICATION_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorName", "InitiatorPortNumber", "Reserved", "AuthInfo"]),
        #
        'SetIScsiGroupPresharedKey': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["KeyLength", "Key", "Persist"]),
        #
        'SetIScsiInitiatorCHAPSharedSecret': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SharedSecretLength", "SharedSecret"]),
        #
        'SetIScsiInitiatorRADIUSSharedSecret': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SharedSecretLength", "SharedSecret"]),
        #
        'SetIScsiInitiatorNodeNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorNodeName"]),
        #
        'SetIScsiInitiatorNodeNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorNodeName"]),
        #
        'GetIScsiInitiatorNodeNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorNodeName"]),
        #
        'GetIScsiInitiatorNodeNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorNodeName"]),
        #
        'AddISNSServerW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Address"]),
        #
        'AddISNSServerA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Address"]),
        #
        'RemoveISNSServerW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Address"]),
        #
        'RemoveISNSServerA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Address"]),
        #
        'RefreshISNSServerW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Address"]),
        #
        'RefreshISNSServerA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Address"]),
        #
        'ReportISNSServerListW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSizeInChar", "Buffer"]),
        #
        'ReportISNSServerListA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSizeInChar", "Buffer"]),
        #
        'GetIScsiSessionListW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ISCSI_SESSION_INFOW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSize", "SessionCount", "SessionInfo"]),
        #
        'GetIScsiSessionListA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ISCSI_SESSION_INFOA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSize", "SessionCount", "SessionInfo"]),
        #
        'GetIScsiSessionListEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ISCSI_SESSION_INFO_EX", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSize", "SessionCountPtr", "SessionInfo"]),
        #
        'GetDevicesForIScsiSessionW': SimTypeFunction([SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ISCSI_DEVICE_ON_SESSIONW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["UniqueSessionId", "DeviceCount", "Devices"]),
        #
        'GetDevicesForIScsiSessionA': SimTypeFunction([SimTypePointer(SimTypeRef("ISCSI_UNIQUE_SESSION_ID", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ISCSI_DEVICE_ON_SESSIONA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["UniqueSessionId", "DeviceCount", "Devices"]),
        #
        'SetupPersistentIScsiVolumes': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'SetupPersistentIScsiDevices': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'AddPersistentIScsiDeviceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DevicePath"]),
        #
        'AddPersistentIScsiDeviceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DevicePath"]),
        #
        'RemovePersistentIScsiDeviceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DevicePath"]),
        #
        'RemovePersistentIScsiDeviceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DevicePath"]),
        #
        'ClearPersistentIScsiDevices': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'ReportPersistentIScsiDevicesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSizeInChar", "Buffer"]),
        #
        'ReportPersistentIScsiDevicesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSizeInChar", "Buffer"]),
        #
        'ReportIScsiTargetPortalsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorName", "TargetName", "TargetPortalTag", "ElementCount", "Portals"]),
        #
        'ReportIScsiTargetPortalsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ISCSI_TARGET_PORTALA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InitiatorName", "TargetName", "TargetPortalTag", "ElementCount", "Portals"]),
        #
        'AddRadiusServerW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Address"]),
        #
        'AddRadiusServerA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Address"]),
        #
        'RemoveRadiusServerW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Address"]),
        #
        'RemoveRadiusServerA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Address"]),
        #
        'ReportRadiusServerListW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSizeInChar", "Buffer"]),
        #
        'ReportRadiusServerListA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSizeInChar", "Buffer"]),
    }

lib.set_prototypes(prototypes)
