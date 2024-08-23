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
lib.set_library_names("ninput.dll")
prototypes = \
    {
        #
        'CreateInteractionContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext"]),
        #
        'DestroyInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext"]),
        #
        'RegisterOutputCallbackInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("INTERACTION_CONTEXT_OUTPUT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["clientData", "output"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "outputCallback", "clientData"]),
        #
        'RegisterOutputCallbackInteractionContext2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("INTERACTION_CONTEXT_OUTPUT2", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["clientData", "output"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "outputCallback", "clientData"]),
        #
        'SetInteractionConfigurationInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("INTERACTION_CONTEXT_CONFIGURATION", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "configurationCount", "configuration"]),
        #
        'GetInteractionConfigurationInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("INTERACTION_CONTEXT_CONFIGURATION", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "configurationCount", "configuration"]),
        #
        'SetPropertyInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="INTERACTION_CONTEXT_PROPERTY"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "contextProperty", "value"]),
        #
        'GetPropertyInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="INTERACTION_CONTEXT_PROPERTY"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "contextProperty", "value"]),
        #
        'SetInertiaParameterInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="INERTIA_PARAMETER"), SimTypeFloat(size=32)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "inertiaParameter", "value"]),
        #
        'GetInertiaParameterInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="INERTIA_PARAMETER"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "inertiaParameter", "value"]),
        #
        'SetCrossSlideParametersInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CROSS_SLIDE_PARAMETER", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "parameterCount", "crossSlideParameters"]),
        #
        'GetCrossSlideParameterInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CROSS_SLIDE_THRESHOLD"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "threshold", "distance"]),
        #
        'SetTapParameterInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TAP_PARAMETER"), SimTypeFloat(size=32)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "parameter", "value"]),
        #
        'GetTapParameterInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TAP_PARAMETER"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "parameter", "value"]),
        #
        'SetHoldParameterInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HOLD_PARAMETER"), SimTypeFloat(size=32)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "parameter", "value"]),
        #
        'GetHoldParameterInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HOLD_PARAMETER"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "parameter", "value"]),
        #
        'SetTranslationParameterInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TRANSLATION_PARAMETER"), SimTypeFloat(size=32)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "parameter", "value"]),
        #
        'GetTranslationParameterInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TRANSLATION_PARAMETER"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "parameter", "value"]),
        #
        'SetMouseWheelParameterInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MOUSE_WHEEL_PARAMETER"), SimTypeFloat(size=32)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "parameter", "value"]),
        #
        'GetMouseWheelParameterInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MOUSE_WHEEL_PARAMETER"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "parameter", "value"]),
        #
        'ResetInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext"]),
        #
        'GetStateInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINTER_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="INTERACTION_STATE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "pointerInfo", "state"]),
        #
        'AddPointerInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "pointerId"]),
        #
        'RemovePointerInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "pointerId"]),
        #
        'ProcessPointerFramesInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POINTER_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "entriesCount", "pointerCount", "pointerInfo"]),
        #
        'BufferPointerPacketsInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POINTER_INFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "entriesCount", "pointerInfo"]),
        #
        'ProcessBufferedPacketsInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext"]),
        #
        'ProcessInertiaInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext"]),
        #
        'StopInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext"]),
        #
        'SetPivotInteractionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeFloat(size=32), SimTypeFloat(size=32), SimTypeFloat(size=32)], SimTypeInt(signed=True, label="Int32"), arg_names=["interactionContext", "x", "y", "radius"]),
    }

lib.set_prototypes(prototypes)
