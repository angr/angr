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
lib.set_library_names("rtm.dll")
prototypes = \
    {
        #
        'MgmRegisterMProtocol': SimTypeFunction([SimTypePointer(SimTypeRef("ROUTING_PROTOCOL_CONFIG", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["prpiInfo", "dwProtocolId", "dwComponentId", "phProtocol"]),
        #
        'MgmDeRegisterMProtocol': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProtocol"]),
        #
        'MgmTakeInterfaceOwnership': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProtocol", "dwIfIndex", "dwIfNextHopAddr"]),
        #
        'MgmReleaseInterfaceOwnership': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProtocol", "dwIfIndex", "dwIfNextHopAddr"]),
        #
        'MgmGetProtocolOnInterface': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwIfIndex", "dwIfNextHopAddr", "pdwIfProtocolId", "pdwIfComponentId"]),
        #
        'MgmAddGroupMembershipEntry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProtocol", "dwSourceAddr", "dwSourceMask", "dwGroupAddr", "dwGroupMask", "dwIfIndex", "dwIfNextHopIPAddr", "dwFlags"]),
        #
        'MgmDeleteGroupMembershipEntry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProtocol", "dwSourceAddr", "dwSourceMask", "dwGroupAddr", "dwGroupMask", "dwIfIndex", "dwIfNextHopIPAddr", "dwFlags"]),
        #
        'MgmGetMfe': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPMCAST_MFE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pimm", "pdwBufferSize", "pbBuffer"]),
        #
        'MgmGetFirstMfe': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pdwBufferSize", "pbBuffer", "pdwNumEntries"]),
        #
        'MgmGetNextMfe': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPMCAST_MFE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pimmStart", "pdwBufferSize", "pbBuffer", "pdwNumEntries"]),
        #
        'MgmGetMfeStats': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPMCAST_MFE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pimm", "pdwBufferSize", "pbBuffer", "dwFlags"]),
        #
        'MgmGetFirstMfeStats': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pdwBufferSize", "pbBuffer", "pdwNumEntries", "dwFlags"]),
        #
        'MgmGetNextMfeStats': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPMCAST_MFE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pimmStart", "pdwBufferSize", "pbBuffer", "pdwNumEntries", "dwFlags"]),
        #
        'MgmGroupEnumerationStart': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MGM_ENUM_TYPES"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProtocol", "metEnumType", "phEnumHandle"]),
        #
        'MgmGroupEnumerationGetNext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEnum", "pdwBufferSize", "pbBuffer", "pdwNumEntries"]),
        #
        'MgmGroupEnumerationEnd': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEnum"]),
        #
        'RtmConvertNetAddressToIpv6AddressAndLength': SimTypeFunction([SimTypePointer(SimTypeRef("RTM_NET_ADDRESS", SimStruct), offset=0), SimTypePointer(SimTypeRef("IN6_ADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pNetAddress", "pAddress", "pLength", "dwAddressSize"]),
        #
        'RtmConvertIpv6AddressAndLengthToNetAddress': SimTypeFunction([SimTypePointer(SimTypeRef("RTM_NET_ADDRESS", SimStruct), offset=0), SimTypeRef("IN6_ADDR", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pNetAddress", "Address", "dwLength", "dwAddressSize"]),
        #
        'RtmRegisterEntity': SimTypeFunction([SimTypePointer(SimTypeRef("RTM_ENTITY_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTM_ENTITY_EXPORT_METHODS", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="RTM_EVENT_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "EventType", "Context1", "Context2"]), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RTM_REGN_PROFILE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmEntityInfo", "ExportMethods", "EventCallback", "ReserveOpaquePointer", "RtmRegProfile", "RtmRegHandle"]),
        #
        'RtmDeregisterEntity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle"]),
        #
        'RtmGetRegisteredEntities': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RTM_ENTITY_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NumEntities", "EntityHandles", "EntityInfos"]),
        #
        'RtmReleaseEntities': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NumEntities", "EntityHandles"]),
        #
        'RtmLockDestination': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "DestHandle", "Exclusive", "LockDest"]),
        #
        'RtmGetOpaqueInformationPointer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "DestHandle", "OpaqueInfoPointer"]),
        #
        'RtmGetEntityMethods': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_ENTITY_METHOD_INPUT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTM_ENTITY_METHOD_OUTPUT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallerHandle", "CalleeHandle", "Input", "Output"]), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "EntityHandle", "NumMethods", "ExptMethods"]),
        #
        'RtmInvokeMethod': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_ENTITY_METHOD_INPUT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("RTM_ENTITY_METHOD_OUTPUT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "EntityHandle", "Input", "OutputSize", "Output"]),
        #
        'RtmBlockMethods': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "TargetHandle", "TargetType", "BlockingFlag"]),
        #
        'RtmGetEntityInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_ENTITY_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "EntityHandle", "EntityInfo"]),
        #
        'RtmGetDestInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RTM_DEST_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "DestHandle", "ProtocolId", "TargetViews", "DestInfo"]),
        #
        'RtmGetRouteInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_ROUTE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTM_NET_ADDRESS", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "RouteHandle", "RouteInfo", "DestAddress"]),
        #
        'RtmGetNextHopInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_NEXTHOP_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NextHopHandle", "NextHopInfo"]),
        #
        'RtmReleaseEntityInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_ENTITY_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "EntityInfo"]),
        #
        'RtmReleaseDestInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_DEST_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "DestInfo"]),
        #
        'RtmReleaseRouteInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_ROUTE_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "RouteInfo"]),
        #
        'RtmReleaseNextHopInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_NEXTHOP_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NextHopInfo"]),
        #
        'RtmAddRouteToDest': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("RTM_NET_ADDRESS", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTM_ROUTE_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "RouteHandle", "DestAddress", "RouteInfo", "TimeToLive", "RouteListHandle", "NotifyType", "NotifyHandle", "ChangeFlags"]),
        #
        'RtmDeleteRouteToDest': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "RouteHandle", "ChangeFlags"]),
        #
        'RtmHoldDestination': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "DestHandle", "TargetViews", "HoldTime"]),
        #
        'RtmGetRoutePointer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("RTM_ROUTE_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "RouteHandle", "RoutePointer"]),
        #
        'RtmLockRoute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeRef("RTM_ROUTE_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "RouteHandle", "Exclusive", "LockRoute", "RoutePointer"]),
        #
        'RtmUpdateAndUnlockRoute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "RouteHandle", "TimeToLive", "RouteListHandle", "NotifyType", "NotifyHandle", "ChangeFlags"]),
        #
        'RtmGetExactMatchDestination': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_NET_ADDRESS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RTM_DEST_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "DestAddress", "ProtocolId", "TargetViews", "DestInfo"]),
        #
        'RtmGetMostSpecificDestination': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_NET_ADDRESS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RTM_DEST_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "DestAddress", "ProtocolId", "TargetViews", "DestInfo"]),
        #
        'RtmGetLessSpecificDestination': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RTM_DEST_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "DestHandle", "ProtocolId", "TargetViews", "DestInfo"]),
        #
        'RtmGetExactMatchRoute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_NET_ADDRESS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RTM_ROUTE_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "DestAddress", "MatchingFlags", "RouteInfo", "InterfaceIndex", "TargetViews", "RouteHandle"]),
        #
        'RtmIsBestRoute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "RouteHandle", "BestInViews"]),
        #
        'RtmAddNextHop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_NEXTHOP_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NextHopInfo", "NextHopHandle", "ChangeFlags"]),
        #
        'RtmFindNextHop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_NEXTHOP_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("RTM_NEXTHOP_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NextHopInfo", "NextHopHandle", "NextHopPointer"]),
        #
        'RtmDeleteNextHop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RTM_NEXTHOP_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NextHopHandle", "NextHopInfo"]),
        #
        'RtmGetNextHopPointer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("RTM_NEXTHOP_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NextHopHandle", "NextHopPointer"]),
        #
        'RtmLockNextHop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeRef("RTM_NEXTHOP_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NextHopHandle", "Exclusive", "LockNextHop", "NextHopPointer"]),
        #
        'RtmCreateDestEnum': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RTM_NET_ADDRESS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "TargetViews", "EnumFlags", "NetAddress", "ProtocolId", "RtmEnumHandle"]),
        #
        'RtmGetEnumDests': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("RTM_DEST_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "EnumHandle", "NumDests", "DestInfos"]),
        #
        'RtmReleaseDests': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RTM_DEST_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NumDests", "DestInfos"]),
        #
        'RtmCreateRouteEnum': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RTM_NET_ADDRESS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RTM_ROUTE_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "DestHandle", "TargetViews", "EnumFlags", "StartDest", "MatchingFlags", "CriteriaRoute", "CriteriaInterface", "RtmEnumHandle"]),
        #
        'RtmGetEnumRoutes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "EnumHandle", "NumRoutes", "RouteHandles"]),
        #
        'RtmReleaseRoutes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NumRoutes", "RouteHandles"]),
        #
        'RtmCreateNextHopEnum': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RTM_NET_ADDRESS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "EnumFlags", "NetAddress", "RtmEnumHandle"]),
        #
        'RtmGetEnumNextHops': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "EnumHandle", "NumNextHops", "NextHopHandles"]),
        #
        'RtmReleaseNextHops': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NumNextHops", "NextHopHandles"]),
        #
        'RtmDeleteEnumHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "EnumHandle"]),
        #
        'RtmRegisterForChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "TargetViews", "NotifyFlags", "NotifyContext", "NotifyHandle"]),
        #
        'RtmGetChangedDests': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("RTM_DEST_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NotifyHandle", "NumDests", "ChangedDests"]),
        #
        'RtmReleaseChangedDests': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RTM_DEST_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NotifyHandle", "NumDests", "ChangedDests"]),
        #
        'RtmIgnoreChangedDests': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NotifyHandle", "NumDests", "ChangedDests"]),
        #
        'RtmGetChangeStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NotifyHandle", "DestHandle", "ChangeStatus"]),
        #
        'RtmMarkDestForChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NotifyHandle", "DestHandle", "MarkDest"]),
        #
        'RtmIsMarkedForChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NotifyHandle", "DestHandle", "DestMarked"]),
        #
        'RtmDeregisterFromChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NotifyHandle"]),
        #
        'RtmCreateRouteList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "RouteListHandle"]),
        #
        'RtmInsertInRouteList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "RouteListHandle", "NumRoutes", "RouteHandles"]),
        #
        'RtmCreateRouteListEnum': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "RouteListHandle", "RtmEnumHandle"]),
        #
        'RtmGetListEnumRoutes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "EnumHandle", "NumRoutes", "RouteHandles"]),
        #
        'RtmDeleteRouteList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "RouteListHandle"]),
        #
        'RtmReferenceHandles': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RtmRegHandle", "NumHandles", "RtmHandles"]),
        #
        'CreateTable': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lppBuffer"]), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lpObject", "lppBuffer"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SPropTagArray", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="ITableData"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpInterface", "lpAllocateBuffer", "lpAllocateMore", "lpFreeBuffer", "lpvReserved", "ulTableType", "ulPropTagIndexColumn", "lpSPropTagArrayColumns", "lppTableData"]),
    }

lib.set_prototypes(prototypes)
