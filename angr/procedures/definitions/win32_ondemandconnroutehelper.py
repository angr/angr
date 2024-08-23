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
lib.set_library_names("ondemandconnroutehelper.dll")
prototypes = \
    {
        #
        'OnDemandGetRoutingHint': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["destinationHostName", "interfaceIndex"]),
        #
        'OnDemandRegisterNotification': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["callback", "callbackContext", "registrationHandle"]),
        #
        'OnDemandUnRegisterNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["registrationHandle"]),
        #
        'GetInterfaceContextTableForHostName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("NET_INTERFACE_CONTEXT_TABLE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["HostName", "ProxyName", "Flags", "ConnectionProfileFilterRawData", "ConnectionProfileFilterRawDataSize", "InterfaceContextTable"]),
        #
        'FreeInterfaceContextTable': SimTypeFunction([SimTypePointer(SimTypeRef("NET_INTERFACE_CONTEXT_TABLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["InterfaceContextTable"]),
    }

lib.set_prototypes(prototypes)
