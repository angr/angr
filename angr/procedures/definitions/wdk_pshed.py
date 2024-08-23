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
lib.set_library_names("pshed.dll")
prototypes = \
    {
        #
        'PshedAllocateMemory': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Size"]),
        #
        'PshedFreeMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Address"]),
        #
        'PshedIsSystemWheaEnabled': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'PshedRegisterPlugin': SimTypeFunction([SimTypePointer(SimTypeRef("WHEA_PSHED_PLUGIN_REGISTRATION_PACKET_V2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Packet"]),
        #
        'PshedUnregisterPlugin': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["PluginHandle"]),
        #
        'PshedSynchronizeExecution': SimTypeFunction([SimTypePointer(SimTypeRef("WHEA_ERROR_SOURCE_DESCRIPTOR", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeChar(label="Byte")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["ErrorSource", "SynchronizeRoutine", "SynchronizeContext"]),
    }

lib.set_prototypes(prototypes)
