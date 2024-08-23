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
lib.set_library_names("dcomp.dll")
prototypes = \
    {
        #
        'CreatePresentationFactory': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["d3dDevice", "riid", "presentationFactory"]),
        #
        'DCompositionCreateDevice': SimTypeFunction([SimTypeBottom(label="IDXGIDevice"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dxgiDevice", "iid", "dcompositionDevice"]),
        #
        'DCompositionCreateDevice2': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["renderingDevice", "iid", "dcompositionDevice"]),
        #
        'DCompositionCreateDevice3': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["renderingDevice", "iid", "dcompositionDevice"]),
        #
        'DCompositionCreateSurfaceHandle': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["desiredAccess", "securityAttributes", "surfaceHandle"]),
        #
        'DCompositionAttachMouseWheelToHwnd': SimTypeFunction([SimTypeBottom(label="IDCompositionVisual"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["visual", "hwnd", "enable"]),
        #
        'DCompositionAttachMouseDragToHwnd': SimTypeFunction([SimTypeBottom(label="IDCompositionVisual"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["visual", "hwnd", "enable"]),
        #
        'DCompositionGetFrameId': SimTypeFunction([SimTypeInt(signed=False, label="COMPOSITION_FRAME_ID_TYPE"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["frameIdType", "frameId"]),
        #
        'DCompositionGetStatistics': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("COMPOSITION_FRAME_STATS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("COMPOSITION_TARGET_ID", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["frameId", "frameStats", "targetIdCount", "targetIds", "actualTargetIdCount"]),
        #
        'DCompositionGetTargetStatistics': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("COMPOSITION_TARGET_ID", SimStruct), offset=0), SimTypePointer(SimTypeRef("COMPOSITION_TARGET_STATS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["frameId", "targetId", "targetStats"]),
        #
        'DCompositionBoostCompositorClock': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["enable"]),
        #
        'DCompositionWaitForCompositorClock': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["count", "handles", "timeoutInMs"]),
    }

lib.set_prototypes(prototypes)
