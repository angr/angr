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
lib.set_library_names("d3d9.dll")
prototypes = \
    {
        #
        'Direct3DCreate9': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="IDirect3D9"), arg_names=["SDKVersion"]),
        #
        'D3DPERF_BeginEvent': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["col", "wszName"]),
        #
        'D3DPERF_EndEvent': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'D3DPERF_SetMarker': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["col", "wszName"]),
        #
        'D3DPERF_SetRegion': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["col", "wszName"]),
        #
        'D3DPERF_QueryRepeatFrame': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'D3DPERF_SetOptions': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwOptions"]),
        #
        'D3DPERF_GetStatus': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'Direct3DCreate9Ex': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IDirect3D9Ex"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SDKVersion", "param1"]),
        #
        'Direct3DCreate9On12Ex': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("D3D9ON12_ARGS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IDirect3D9Ex"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SDKVersion", "pOverrideList", "NumOverrideEntries", "ppOutputInterface"]),
        #
        'Direct3DCreate9On12': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("D3D9ON12_ARGS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="IDirect3D9"), arg_names=["SDKVersion", "pOverrideList", "NumOverrideEntries"]),
    }

lib.set_prototypes(prototypes)
