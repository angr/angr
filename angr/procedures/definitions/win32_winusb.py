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
lib.set_library_names("winusb.dll")
prototypes = \
    {
        #
        'WinUsb_Initialize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceHandle", "InterfaceHandle"]),
        #
        'WinUsb_Free': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle"]),
        #
        'WinUsb_GetAssociatedInterface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "AssociatedInterfaceIndex", "AssociatedInterfaceHandle"]),
        #
        'WinUsb_GetDescriptor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "DescriptorType", "Index", "LanguageID", "Buffer", "BufferLength", "LengthTransferred"]),
        #
        'WinUsb_QueryInterfaceSettings': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("USB_INTERFACE_DESCRIPTOR", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "AlternateInterfaceNumber", "UsbAltInterfaceDescriptor"]),
        #
        'WinUsb_QueryDeviceInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "InformationType", "BufferLength", "Buffer"]),
        #
        'WinUsb_SetCurrentAlternateSetting': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "SettingNumber"]),
        #
        'WinUsb_GetCurrentAlternateSetting': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "SettingNumber"]),
        #
        'WinUsb_QueryPipe': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("WINUSB_PIPE_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "AlternateInterfaceNumber", "PipeIndex", "PipeInformation"]),
        #
        'WinUsb_QueryPipeEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("WINUSB_PIPE_INFORMATION_EX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "AlternateSettingNumber", "PipeIndex", "PipeInformationEx"]),
        #
        'WinUsb_SetPipePolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="WINUSB_PIPE_POLICY"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "PipeID", "PolicyType", "ValueLength", "Value"]),
        #
        'WinUsb_GetPipePolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="WINUSB_PIPE_POLICY"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "PipeID", "PolicyType", "ValueLength", "Value"]),
        #
        'WinUsb_ReadPipe': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "PipeID", "Buffer", "BufferLength", "LengthTransferred", "Overlapped"]),
        #
        'WinUsb_WritePipe': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "PipeID", "Buffer", "BufferLength", "LengthTransferred", "Overlapped"]),
        #
        'WinUsb_ControlTransfer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("WINUSB_SETUP_PACKET", SimStruct), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "SetupPacket", "Buffer", "BufferLength", "LengthTransferred", "Overlapped"]),
        #
        'WinUsb_ResetPipe': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "PipeID"]),
        #
        'WinUsb_AbortPipe': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "PipeID"]),
        #
        'WinUsb_FlushPipe': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "PipeID"]),
        #
        'WinUsb_SetPowerPolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WINUSB_POWER_POLICY"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "PolicyType", "ValueLength", "Value"]),
        #
        'WinUsb_GetPowerPolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WINUSB_POWER_POLICY"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "PolicyType", "ValueLength", "Value"]),
        #
        'WinUsb_GetOverlappedResult': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "lpOverlapped", "lpNumberOfBytesTransferred", "bWait"]),
        #
        'WinUsb_ParseConfigurationDescriptor': SimTypeFunction([SimTypePointer(SimTypeRef("USB_CONFIGURATION_DESCRIPTOR", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeRef("USB_INTERFACE_DESCRIPTOR", SimStruct), offset=0), arg_names=["ConfigurationDescriptor", "StartPosition", "InterfaceNumber", "AlternateSetting", "InterfaceClass", "InterfaceSubClass", "InterfaceProtocol"]),
        #
        'WinUsb_ParseDescriptors': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeRef("USB_COMMON_DESCRIPTOR", SimStruct), offset=0), arg_names=["DescriptorBuffer", "TotalLength", "StartPosition", "DescriptorType"]),
        #
        'WinUsb_GetCurrentFrameNumber': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "CurrentFrameNumber", "TimeStamp"]),
        #
        'WinUsb_GetAdjustedFrameNumber': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeInt(signed=True, label="Int32"), arg_names=["CurrentFrameNumber", "TimeStamp"]),
        #
        'WinUsb_RegisterIsochBuffer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "PipeID", "Buffer", "BufferLength", "IsochBufferHandle"]),
        #
        'WinUsb_UnregisterIsochBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["IsochBufferHandle"]),
        #
        'WinUsb_WriteIsochPipe': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["BufferHandle", "Offset", "Length", "FrameNumber", "Overlapped"]),
        #
        'WinUsb_ReadIsochPipe': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("USBD_ISO_PACKET_DESCRIPTOR", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["BufferHandle", "Offset", "Length", "FrameNumber", "NumberOfPackets", "IsoPacketDescriptors", "Overlapped"]),
        #
        'WinUsb_WriteIsochPipeAsap': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["BufferHandle", "Offset", "Length", "ContinueStream", "Overlapped"]),
        #
        'WinUsb_ReadIsochPipeAsap': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("USBD_ISO_PACKET_DESCRIPTOR", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["BufferHandle", "Offset", "Length", "ContinueStream", "NumberOfPackets", "IsoPacketDescriptors", "Overlapped"]),
        #
        'WinUsb_StartTrackingForTimeSync': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("USB_START_TRACKING_FOR_TIME_SYNC_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "StartTrackingInfo"]),
        #
        'WinUsb_GetCurrentFrameNumberAndQpc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("USB_FRAME_NUMBER_AND_QPC_FOR_TIME_SYNC_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "FrameQpcInfo"]),
        #
        'WinUsb_StopTrackingForTimeSync': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("USB_STOP_TRACKING_FOR_TIME_SYNC_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceHandle", "StopTrackingInfo"]),
    }

lib.set_prototypes(prototypes)
