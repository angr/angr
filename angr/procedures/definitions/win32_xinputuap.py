# pylint:disable=line-too-long
import logging

from ...sim_type import SimTypeFunction,     SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat,     SimTypePointer,     SimTypeChar,     SimStruct,     SimTypeFixedSizeArray,     SimTypeBottom,     SimUnion,     SimTypeBool
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
lib.set_library_names("xinputuap.dll")
prototypes = \
    {
        #
        'XInputGetState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"dwPacketNumber": SimTypeInt(signed=False, label="UInt32"), "Gamepad": SimStruct({"wButtons": SimTypeShort(signed=False, label="UInt16"), "bLeftTrigger": SimTypeChar(label="Byte"), "bRightTrigger": SimTypeChar(label="Byte"), "sThumbLX": SimTypeShort(signed=True, label="Int16"), "sThumbLY": SimTypeShort(signed=True, label="Int16"), "sThumbRX": SimTypeShort(signed=True, label="Int16"), "sThumbRY": SimTypeShort(signed=True, label="Int16")}, name="XINPUT_GAMEPAD", pack=False, align=None)}, name="XINPUT_STATE", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwUserIndex", "pState"]),
        #
        'XInputSetState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"wLeftMotorSpeed": SimTypeShort(signed=False, label="UInt16"), "wRightMotorSpeed": SimTypeShort(signed=False, label="UInt16")}, name="XINPUT_VIBRATION", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwUserIndex", "pVibration"]),
        #
        'XInputGetCapabilities': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Type": SimTypeChar(label="Byte"), "SubType": SimTypeChar(label="Byte"), "Flags": SimTypeShort(signed=False, label="UInt16"), "Gamepad": SimStruct({"wButtons": SimTypeShort(signed=False, label="UInt16"), "bLeftTrigger": SimTypeChar(label="Byte"), "bRightTrigger": SimTypeChar(label="Byte"), "sThumbLX": SimTypeShort(signed=True, label="Int16"), "sThumbLY": SimTypeShort(signed=True, label="Int16"), "sThumbRX": SimTypeShort(signed=True, label="Int16"), "sThumbRY": SimTypeShort(signed=True, label="Int16")}, name="XINPUT_GAMEPAD", pack=False, align=None), "Vibration": SimStruct({"wLeftMotorSpeed": SimTypeShort(signed=False, label="UInt16"), "wRightMotorSpeed": SimTypeShort(signed=False, label="UInt16")}, name="XINPUT_VIBRATION", pack=False, align=None)}, name="XINPUT_CAPABILITIES", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwUserIndex", "dwFlags", "pCapabilities"]),
        #
        'XInputEnable': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["enable"]),
        #
        'XInputGetAudioDeviceIds': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwUserIndex", "pRenderDeviceId", "pRenderCount", "pCaptureDeviceId", "pCaptureCount"]),
        #
        'XInputGetBatteryInformation': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimStruct({"BatteryType": SimTypeChar(label="Byte"), "BatteryLevel": SimTypeChar(label="Byte")}, name="XINPUT_BATTERY_INFORMATION", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwUserIndex", "devType", "pBatteryInformation"]),
        #
        'XInputGetKeystroke': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"VirtualKey": SimTypeInt(signed=False, label="XINPUT_VIRTUAL_KEY"), "Unicode": SimTypeChar(label="Char"), "Flags": SimTypeShort(signed=False, label="UInt16"), "UserIndex": SimTypeChar(label="Byte"), "HidCode": SimTypeChar(label="Byte")}, name="XINPUT_KEYSTROKE", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwUserIndex", "dwReserved", "pKeystroke"]),
    }

lib.set_prototypes(prototypes)
