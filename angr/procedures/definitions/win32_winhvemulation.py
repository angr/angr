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
lib.set_library_names("winhvemulation.dll")
prototypes = \
    {
        #
        'WHvEmulatorCreateEmulator': SimTypeFunction([SimTypePointer(SimTypeRef("WHV_EMULATOR_CALLBACKS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Callbacks", "Emulator"]),
        #
        'WHvEmulatorDestroyEmulator': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Emulator"]),
        #
        'WHvEmulatorTryIoEmulation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("WHV_VP_EXIT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeRef("WHV_X64_IO_PORT_ACCESS_CONTEXT", SimStruct), offset=0), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("_bitfield", SimTypeInt(signed=False, label="UInt32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "AsUINT32": SimTypeInt(signed=False, label="UInt32")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Emulator", "Context", "VpContext", "IoInstructionContext", "EmulatorReturnStatus"]),
        #
        'WHvEmulatorTryMmioEmulation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("WHV_VP_EXIT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeRef("WHV_MEMORY_ACCESS_CONTEXT", SimStruct), offset=0), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("_bitfield", SimTypeInt(signed=False, label="UInt32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "AsUINT32": SimTypeInt(signed=False, label="UInt32")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Emulator", "Context", "VpContext", "MmioInstructionContext", "EmulatorReturnStatus"]),
    }

lib.set_prototypes(prototypes)
