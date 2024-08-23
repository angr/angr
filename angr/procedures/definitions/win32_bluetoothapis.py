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
lib.set_library_names("bluetoothapis.dll")
prototypes = \
    {
        #
        'BluetoothFindFirstRadio': SimTypeFunction([SimTypePointer(SimTypeRef("BLUETOOTH_FIND_RADIO_PARAMS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pbtfrp", "phRadio"]),
        #
        'BluetoothFindNextRadio': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFind", "phRadio"]),
        #
        'BluetoothFindRadioClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFind"]),
        #
        'BluetoothGetRadioInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_RADIO_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadio", "pRadioInfo"]),
        #
        'BluetoothFindFirstDevice': SimTypeFunction([SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_SEARCH_PARAMS", SimStruct), offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pbtsp", "pbtdi"]),
        #
        'BluetoothFindNextDevice': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFind", "pbtdi"]),
        #
        'BluetoothFindDeviceClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFind"]),
        #
        'BluetoothGetDeviceInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadio", "pbtdi"]),
        #
        'BluetoothUpdateDeviceRecord': SimTypeFunction([SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pbtdi"]),
        #
        'BluetoothRemoveDevice': SimTypeFunction([SimTypePointer(SimTypeRef("BLUETOOTH_ADDRESS", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pAddress"]),
        #
        'BluetoothSetServiceState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadio", "pbtdi", "pGuidService", "dwServiceFlags"]),
        #
        'BluetoothEnumerateInstalledServices': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadio", "pbtdi", "pcServiceInout", "pGuidServices"]),
        #
        'BluetoothEnableDiscovery': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hRadio", "fEnabled"]),
        #
        'BluetoothIsDiscoverable': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRadio"]),
        #
        'BluetoothEnableIncomingConnections': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hRadio", "fEnabled"]),
        #
        'BluetoothIsConnectable': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRadio"]),
        #
        'BluetoothRegisterForAuthentication': SimTypeFunction([SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvParam", "pDevice"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pbtdi", "phRegHandle", "pfnCallback", "pvParam"]),
        #
        'BluetoothRegisterForAuthenticationEx': SimTypeFunction([SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_AUTHENTICATION_CALLBACK_PARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvParam", "pAuthCallbackParams"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pbtdiIn", "phRegHandleOut", "pfnCallbackIn", "pvParam"]),
        #
        'BluetoothUnregisterAuthentication': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRegHandle"]),
        #
        'BluetoothSendAuthenticationResponse': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_DEVICE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadio", "pbtdi", "pszPasskey"]),
        #
        'BluetoothSendAuthenticationResponseEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BLUETOOTH_AUTHENTICATE_RESPONSE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadioIn", "pauthResponse"]),
        #
        'BluetoothSdpGetElementData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SDP_ELEMENT_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pSdpStream", "cbSdpStreamLength", "pData"]),
        #
        'BluetoothSdpGetContainerElementData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("SDP_ELEMENT_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pContainerStream", "cbContainerLength", "pElement", "pData"]),
        #
        'BluetoothSdpGetAttributeValue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("SDP_ELEMENT_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRecordStream", "cbRecordLength", "usAttributeId", "pAttributeData"]),
        #
        'BluetoothSdpGetString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SDP_STRING_TYPE_DATA", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRecordStream", "cbRecordLength", "pStringData", "usStringOffset", "pszString", "pcchStringLength"]),
        #
        'BluetoothSdpEnumAttributes': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uAttribId", "pValueStream", "cbStreamSize", "pvParam"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSDPStream", "cbStreamSize", "pfnCallback", "pvParam"]),
        #
        'BluetoothSetLocalServiceInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BLUETOOTH_LOCAL_SERVICE_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadioIn", "pClassGuid", "ulInstance", "pServiceInfoIn"]),
        #
        'BluetoothIsVersionAvailable': SimTypeFunction([SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["MajorVersion", "MinorVersion"]),
        #
        'BluetoothGATTGetServices': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("BTH_LE_GATT_SERVICE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice", "ServicesBufferCount", "ServicesBuffer", "ServicesBufferActual", "Flags"]),
        #
        'BluetoothGATTGetIncludedServices': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BTH_LE_GATT_SERVICE", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("BTH_LE_GATT_SERVICE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice", "ParentService", "IncludedServicesBufferCount", "IncludedServicesBuffer", "IncludedServicesBufferActual", "Flags"]),
        #
        'BluetoothGATTGetCharacteristics': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BTH_LE_GATT_SERVICE", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("BTH_LE_GATT_CHARACTERISTIC", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice", "Service", "CharacteristicsBufferCount", "CharacteristicsBuffer", "CharacteristicsBufferActual", "Flags"]),
        #
        'BluetoothGATTGetDescriptors': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BTH_LE_GATT_CHARACTERISTIC", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("BTH_LE_GATT_DESCRIPTOR", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice", "Characteristic", "DescriptorsBufferCount", "DescriptorsBuffer", "DescriptorsBufferActual", "Flags"]),
        #
        'BluetoothGATTGetCharacteristicValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BTH_LE_GATT_CHARACTERISTIC", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BTH_LE_GATT_CHARACTERISTIC_VALUE", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice", "Characteristic", "CharacteristicValueDataSize", "CharacteristicValue", "CharacteristicValueSizeRequired", "Flags"]),
        #
        'BluetoothGATTGetDescriptorValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BTH_LE_GATT_DESCRIPTOR", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BTH_LE_GATT_DESCRIPTOR_VALUE", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice", "Descriptor", "DescriptorValueDataSize", "DescriptorValue", "DescriptorValueSizeRequired", "Flags"]),
        #
        'BluetoothGATTBeginReliableWrite': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice", "ReliableWriteContext", "Flags"]),
        #
        'BluetoothGATTSetCharacteristicValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BTH_LE_GATT_CHARACTERISTIC", SimStruct), offset=0), SimTypePointer(SimTypeRef("BTH_LE_GATT_CHARACTERISTIC_VALUE", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice", "Characteristic", "CharacteristicValue", "ReliableWriteContext", "Flags"]),
        #
        'BluetoothGATTEndReliableWrite': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice", "ReliableWriteContext", "Flags"]),
        #
        'BluetoothGATTAbortReliableWrite': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice", "ReliableWriteContext", "Flags"]),
        #
        'BluetoothGATTSetDescriptorValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BTH_LE_GATT_DESCRIPTOR", SimStruct), offset=0), SimTypePointer(SimTypeRef("BTH_LE_GATT_DESCRIPTOR_VALUE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice", "Descriptor", "DescriptorValue", "Flags"]),
        #
        'BluetoothGATTRegisterEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="BTH_LE_GATT_EVENT_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="BTH_LE_GATT_EVENT_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["EventType", "EventOutParameter", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hService", "EventType", "EventParameterIn", "Callback", "CallbackContext", "pEventHandle", "Flags"]),
        #
        'BluetoothGATTUnregisterEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["EventHandle", "Flags"]),
    }

lib.set_prototypes(prototypes)
