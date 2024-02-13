# pylint:disable=line-too-long
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
lib.set_library_names("bthprops.cpl")
prototypes = \
    {
        #
        'BluetoothSelectDevices': SimTypeFunction([SimTypePointer(SimTypeRef("BLUETOOTH_SELECT_DEVICE_PARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbtsdp"]),
        #
        'BluetoothSelectDevicesFree': SimTypeFunction([SimTypePointer(SimTypeRef("BLUETOOTH_SELECT_DEVICE_PARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbtsdp"]),
        #
        'BluetoothDisplayDeviceProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "pbtdi"]),
        #
        'BluetoothAuthenticateDevice': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwndParent", "hRadio", "pbtbi", "pszPasskey", "ulPasskeyLength"]),
        #
        'BluetoothAuthenticateDeviceEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_OOB_DATA_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="AUTHENTICATION_REQUIREMENTS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwndParentIn", "hRadioIn", "pbtdiInout", "pbtOobData", "authenticationRequirement"]),
        #
        'BluetoothAuthenticateMultipleDevices': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwndParent", "hRadio", "cDevices", "rgbtdi"]),
    }

lib.set_prototypes(prototypes)
