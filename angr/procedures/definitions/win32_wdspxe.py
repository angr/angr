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
lib.set_library_names("wdspxe.dll")
prototypes = \
    {
        # 
        'PxeProviderRegister': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszProviderName", "pszModulePath", "Index", "bIsCritical", "phProviderKey"]),
        # 
        'PxeProviderUnRegister': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszProviderName"]),
        # 
        'PxeProviderQueryIndex': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszProviderName", "puIndex"]),
        # 
        'PxeProviderEnumFirst': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["phEnum"]),
        # 
        'PxeProviderEnumNext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimStruct({"uSizeOfStruct": SimTypeInt(signed=False, label="UInt32"), "pwszName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pwszFilePath": SimTypePointer(SimTypeChar(label="Char"), offset=0), "bIsCritical": SimTypeInt(signed=True, label="Int32"), "uIndex": SimTypeInt(signed=False, label="UInt32")}, name="PXE_PROVIDER", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEnum", "ppProvider"]),
        # 
        'PxeProviderEnumClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEnum"]),
        # 
        'PxeProviderFreeInfo': SimTypeFunction([SimTypePointer(SimStruct({"uSizeOfStruct": SimTypeInt(signed=False, label="UInt32"), "pwszName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pwszFilePath": SimTypePointer(SimTypeChar(label="Char"), offset=0), "bIsCritical": SimTypeInt(signed=True, label="Int32"), "uIndex": SimTypeInt(signed=False, label="UInt32")}, name="PXE_PROVIDER", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pProvider"]),
        # 
        'PxeRegisterCallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProvider", "CallbackType", "pCallbackFunction", "pContext"]),
        # 
        'PxeSendReply': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"uFlags": SimTypeInt(signed=False, label="UInt32"), "Anonymous": SimUnion({"bAddress": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 16), "uIpAddress": SimTypeInt(signed=False, label="UInt32")}, name="<anon>", label="None"), "uAddrLen": SimTypeInt(signed=False, label="UInt32"), "uPort": SimTypeShort(signed=False, label="UInt16")}, name="PXE_ADDRESS", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hClientRequest", "pPacket", "uPacketLen", "pAddress"]),
        # 
        'PxeAsyncRecvDone': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hClientRequest", "Action"]),
        # 
        'PxeTrace': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProvider", "Severity", "pszFormat"]),
        # 
        'PxeTraceV': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProvider", "Severity", "pszFormat", "Params"]),
        # 
        'PxePacketAllocate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hProvider", "hClientRequest", "uSize"]),
        # 
        'PxePacketFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProvider", "hClientRequest", "pPacket"]),
        # 
        'PxeProviderSetAttribute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProvider", "Attribute", "pParameterBuffer", "uParamLen"]),
        # 
        'PxeDhcpInitialize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRecvPacket", "uRecvPacketLen", "pReplyPacket", "uMaxReplyPacketLen", "puReplyPacketLen"]),
        # 
        'PxeDhcpv6Initialize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRequest", "cbRequest", "pReply", "cbReply", "pcbReplyUsed"]),
        # 
        'PxeDhcpAppendOption': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pReplyPacket", "uMaxReplyPacketLen", "puReplyPacketLen", "bOption", "bOptionLen", "pValue"]),
        # 
        'PxeDhcpv6AppendOption': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pReply", "cbReply", "pcbReplyUsed", "wOptionType", "cbOption", "pOption"]),
        # 
        'PxeDhcpAppendOptionRaw': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pReplyPacket", "uMaxReplyPacketLen", "puReplyPacketLen", "uBufferLen", "pBuffer"]),
        # 
        'PxeDhcpv6AppendOptionRaw': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pReply", "cbReply", "pcbReplyUsed", "cbBuffer", "pBuffer"]),
        # 
        'PxeDhcpIsValid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPacket", "uPacketLen", "bRequestPacket", "pbPxeOptionPresent"]),
        # 
        'PxeDhcpv6IsValid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPacket", "uPacketLen", "bRequestPacket", "pbPxeOptionPresent"]),
        # 
        'PxeDhcpGetOptionValue': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPacket", "uPacketLen", "uInstance", "bOption", "pbOptionLen", "ppOptionValue"]),
        # 
        'PxeDhcpv6GetOptionValue': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPacket", "uPacketLen", "uInstance", "wOption", "pwOptionLen", "ppOptionValue"]),
        # 
        'PxeDhcpGetVendorOptionValue': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPacket", "uPacketLen", "bOption", "uInstance", "pbOptionLen", "ppOptionValue"]),
        # 
        'PxeDhcpv6GetVendorOptionValue': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPacket", "uPacketLen", "dwEnterpriseNumber", "wOption", "uInstance", "pwOptionLen", "ppOptionValue"]),
        # 
        'PxeDhcpv6ParseRelayForw': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"pRelayMessage": SimTypePointer(SimStruct({"MessageType": SimTypeChar(label="Byte"), "HopCount": SimTypeChar(label="Byte"), "LinkAddress": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 16), "PeerAddress": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 16), "Options": SimTypePointer(SimStruct({"OptionCode": SimTypeShort(signed=False, label="UInt16"), "DataLength": SimTypeShort(signed=False, label="UInt16"), "Data": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="PXE_DHCPV6_OPTION", pack=False, align=None), offset=0)}, name="PXE_DHCPV6_RELAY_MESSAGE", pack=False, align=None), offset=0), "cbRelayMessage": SimTypeInt(signed=False, label="UInt32"), "pInterfaceIdOption": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "cbInterfaceIdOption": SimTypeShort(signed=False, label="UInt16")}, name="PXE_DHCPV6_NESTED_RELAY_MESSAGE", pack=False, align=None), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRelayForwPacket", "uRelayForwPacketLen", "pRelayMessages", "nRelayMessages", "pnRelayMessages", "ppInnerPacket", "pcbInnerPacket"]),
        # 
        'PxeDhcpv6CreateRelayRepl': SimTypeFunction([SimTypePointer(SimStruct({"pRelayMessage": SimTypePointer(SimStruct({"MessageType": SimTypeChar(label="Byte"), "HopCount": SimTypeChar(label="Byte"), "LinkAddress": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 16), "PeerAddress": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 16), "Options": SimTypePointer(SimStruct({"OptionCode": SimTypeShort(signed=False, label="UInt16"), "DataLength": SimTypeShort(signed=False, label="UInt16"), "Data": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="PXE_DHCPV6_OPTION", pack=False, align=None), offset=0)}, name="PXE_DHCPV6_RELAY_MESSAGE", pack=False, align=None), offset=0), "cbRelayMessage": SimTypeInt(signed=False, label="UInt32"), "pInterfaceIdOption": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "cbInterfaceIdOption": SimTypeShort(signed=False, label="UInt16")}, name="PXE_DHCPV6_NESTED_RELAY_MESSAGE", pack=False, align=None), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRelayMessages", "nRelayMessages", "pInnerPacket", "cbInnerPacket", "pReplyBuffer", "cbReplyBuffer", "pcbReplyBuffer"]),
        # 
        'PxeGetServerInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["uInfoType", "pBuffer", "uBufferLen"]),
        # 
        'PxeGetServerInfoEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["uInfoType", "pBuffer", "uBufferLen", "puBufferUsed"]),
    }

lib.set_prototypes(prototypes)
