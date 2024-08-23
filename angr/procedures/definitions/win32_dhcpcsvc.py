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
lib.set_library_names("dhcpcsvc.dll")
prototypes = \
    {
        #
        'DhcpCApiInitialize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Version"]),
        #
        'DhcpCApiCleanup': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'DhcpRequestParams': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCPCAPI_CLASSID", SimStruct), offset=0), SimTypeRef("DHCPCAPI_PARAMS_ARRAY", SimStruct), SimTypeRef("DHCPCAPI_PARAMS_ARRAY", SimStruct), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Flags", "Reserved", "AdapterName", "ClassId", "SendParams", "RecdParams", "Buffer", "pSize", "RequestIdStr"]),
        #
        'DhcpUndoRequestParams': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Flags", "Reserved", "AdapterName", "RequestIdStr"]),
        #
        'DhcpRegisterParamChange': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCPCAPI_CLASSID", SimStruct), offset=0), SimTypeRef("DHCPCAPI_PARAMS_ARRAY", SimStruct), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Flags", "Reserved", "AdapterName", "ClassId", "Params", "Handle"]),
        #
        'DhcpDeRegisterParamChange': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Flags", "Reserved", "Event"]),
        #
        'DhcpRemoveDNSRegistrations': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'DhcpGetOriginalSubnetMask': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["sAdapterName", "dwSubnetMask"]),
        #
        'McastApiStartup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Version"]),
        #
        'McastApiCleanup': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'McastGenUID': SimTypeFunction([SimTypePointer(SimTypeRef("MCAST_CLIENT_UID", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRequestID"]),
        #
        'McastEnumerateScopes': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("MCAST_SCOPE_ENTRY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AddrFamily", "ReQuery", "pScopeList", "pScopeLen", "pScopeCount"]),
        #
        'McastRequestAddress': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("MCAST_CLIENT_UID", SimStruct), offset=0), SimTypePointer(SimTypeRef("MCAST_SCOPE_CTX", SimStruct), offset=0), SimTypePointer(SimTypeRef("MCAST_LEASE_REQUEST", SimStruct), offset=0), SimTypePointer(SimTypeRef("MCAST_LEASE_RESPONSE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AddrFamily", "pRequestID", "pScopeCtx", "pAddrRequest", "pAddrResponse"]),
        #
        'McastRenewAddress': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("MCAST_CLIENT_UID", SimStruct), offset=0), SimTypePointer(SimTypeRef("MCAST_LEASE_REQUEST", SimStruct), offset=0), SimTypePointer(SimTypeRef("MCAST_LEASE_RESPONSE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AddrFamily", "pRequestID", "pRenewRequest", "pRenewResponse"]),
        #
        'McastReleaseAddress': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("MCAST_CLIENT_UID", SimStruct), offset=0), SimTypePointer(SimTypeRef("MCAST_LEASE_REQUEST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AddrFamily", "pRequestID", "pReleaseRequest"]),
    }

lib.set_prototypes(prototypes)
