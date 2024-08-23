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
lib.set_library_names("api-ms-win-core-memory-l1-1-6.dll")
prototypes = \
    {
        #
        'VirtualAlloc2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="VIRTUAL_ALLOCATION_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MEM_EXTENDED_PARAMETER", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Process", "BaseAddress", "Size", "AllocationType", "PageProtection", "ExtendedParameters", "ParameterCount"]),
        #
        'MapViewOfFile3': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="VIRTUAL_ALLOCATION_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MEM_EXTENDED_PARAMETER", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeRef("MEMORY_MAPPED_VIEW_ADDRESS", SimStruct), arg_names=["FileMapping", "Process", "BaseAddress", "Offset", "ViewSize", "AllocationType", "PageProtection", "ExtendedParameters", "ParameterCount"]),
        #
        'VirtualAlloc2FromApp': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="VIRTUAL_ALLOCATION_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MEM_EXTENDED_PARAMETER", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Process", "BaseAddress", "Size", "AllocationType", "PageProtection", "ExtendedParameters", "ParameterCount"]),
        #
        'MapViewOfFile3FromApp': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="VIRTUAL_ALLOCATION_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MEM_EXTENDED_PARAMETER", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeRef("MEMORY_MAPPED_VIEW_ADDRESS", SimStruct), arg_names=["FileMapping", "Process", "BaseAddress", "Offset", "ViewSize", "AllocationType", "PageProtection", "ExtendedParameters", "ParameterCount"]),
    }

lib.set_prototypes(prototypes)
