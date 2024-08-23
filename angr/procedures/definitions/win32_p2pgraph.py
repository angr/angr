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
lib.set_library_names("p2pgraph.dll")
prototypes = \
    {
        #
        'PeerGraphStartup': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("PEER_VERSION_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["wVersionRequested", "pVersionData"]),
        #
        'PeerGraphShutdown': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'PeerGraphFreeData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pvData"]),
        #
        'PeerGraphGetItemCount': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPeerEnum", "pCount"]),
        #
        'PeerGraphGetNextItem': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPeerEnum", "pCount", "pppvItems"]),
        #
        'PeerGraphEndEnumeration': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPeerEnum"]),
        #
        'PeerGraphCreate': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_GRAPH_PROPERTIES", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PEER_SECURITY_INTERFACE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pGraphProperties", "pwzDatabaseName", "pSecurityInterface", "phGraph"]),
        #
        'PeerGraphOpen': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PEER_SECURITY_INTERFACE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzGraphId", "pwzPeerId", "pwzDatabaseName", "pSecurityInterface", "cRecordTypeSyncPrecedence", "pRecordTypeSyncPrecedence", "phGraph"]),
        #
        'PeerGraphListen': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "dwScope", "dwScopeId", "wPort"]),
        #
        'PeerGraphConnect': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PEER_ADDRESS", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pwzPeerId", "pAddress", "pullConnectionId"]),
        #
        'PeerGraphClose': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph"]),
        #
        'PeerGraphDelete': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzGraphId", "pwzPeerId", "pwzDatabaseName"]),
        #
        'PeerGraphGetStatus': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pdwStatus"]),
        #
        'PeerGraphGetProperties': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_GRAPH_PROPERTIES", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "ppGraphProperties"]),
        #
        'PeerGraphSetProperties': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("PEER_GRAPH_PROPERTIES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pGraphProperties"]),
        #
        'PeerGraphRegisterEvent': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PEER_GRAPH_EVENT_REGISTRATION", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "hEvent", "cEventRegistrations", "pEventRegistrations", "phPeerEvent"]),
        #
        'PeerGraphUnregisterEvent': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPeerEvent"]),
        #
        'PeerGraphGetEventData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_GRAPH_EVENT_DATA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPeerEvent", "ppEventData"]),
        #
        'PeerGraphGetRecord': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_RECORD", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pRecordId", "ppRecord"]),
        #
        'PeerGraphAddRecord': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("PEER_RECORD", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pRecord", "pRecordId"]),
        #
        'PeerGraphUpdateRecord': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("PEER_RECORD", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pRecord"]),
        #
        'PeerGraphDeleteRecord': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pRecordId", "fLocal"]),
        #
        'PeerGraphEnumRecords': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pRecordType", "pwzPeerId", "phPeerEnum"]),
        #
        'PeerGraphSearchRecords': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pwzCriteria", "phPeerEnum"]),
        #
        'PeerGraphExportDatabase': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pwzFilePath"]),
        #
        'PeerGraphImportDatabase': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pwzFilePath"]),
        #
        'PeerGraphValidateDeferredRecords': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "cRecordIds", "pRecordIds"]),
        #
        'PeerGraphOpenDirectConnection': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PEER_ADDRESS", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pwzPeerId", "pAddress", "pullConnectionId"]),
        #
        'PeerGraphSendData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "ullConnectionId", "pType", "cbData", "pvData"]),
        #
        'PeerGraphCloseDirectConnection': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "ullConnectionId"]),
        #
        'PeerGraphEnumConnections': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "dwFlags", "phPeerEnum"]),
        #
        'PeerGraphEnumNodes': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pwzPeerId", "phPeerEnum"]),
        #
        'PeerGraphSetPresence': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "fPresent"]),
        #
        'PeerGraphGetNodeInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypePointer(SimTypeRef("PEER_NODE_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "ullNodeId", "ppNodeInfo"]),
        #
        'PeerGraphSetNodeAttributes': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pwzAttributes"]),
        #
        'PeerGraphPeerTimeToUniversalTime': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pftPeerTime", "pftUniversalTime"]),
        #
        'PeerGraphUniversalTimeToPeerTime': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGraph", "pftUniversalTime", "pftPeerTime"]),
    }

lib.set_prototypes(prototypes)
