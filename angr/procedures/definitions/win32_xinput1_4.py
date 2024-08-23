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
lib.set_library_names("xinput1_4.dll")
prototypes = \
    {
        #
        'XInputGetState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("XINPUT_STATE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwUserIndex", "pState"]),
        #
        'XInputSetState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("XINPUT_VIBRATION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwUserIndex", "pVibration"]),
        #
        'XInputGetCapabilities': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="XINPUT_FLAG"), SimTypePointer(SimTypeRef("XINPUT_CAPABILITIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwUserIndex", "dwFlags", "pCapabilities"]),
        #
        'XInputEnable': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["enable"]),
        #
        'XInputGetAudioDeviceIds': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwUserIndex", "pRenderDeviceId", "pRenderCount", "pCaptureDeviceId", "pCaptureCount"]),
        #
        'XInputGetBatteryInformation': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="BATTERY_DEVTYPE"), SimTypePointer(SimTypeRef("XINPUT_BATTERY_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwUserIndex", "devType", "pBatteryInformation"]),
        #
        'XInputGetKeystroke': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("XINPUT_KEYSTROKE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwUserIndex", "dwReserved", "pKeystroke"]),
    }

lib.set_prototypes(prototypes)
