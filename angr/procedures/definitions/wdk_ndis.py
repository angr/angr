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
lib.set_library_names("ndis.sys")
prototypes = \
    {
        #
        'NdisInitializeReadWriteLock': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_RW_LOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Lock"]),
        #
        'NdisAcquireReadWriteLock': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_RW_LOCK", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("LOCK_STATE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Lock", "fWrite", "LockState"]),
        #
        'NdisReleaseReadWriteLock': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_RW_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("LOCK_STATE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Lock", "LockState"]),
        #
        'NdisGetCurrentProcessorCpuUsage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pCpuUsage"]),
        #
        'NdisGetCurrentProcessorCounts': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pIdleCount", "pKernelAndUser", "pIndex"]),
        #
        'NdisOpenConfigurationKeyByName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "ConfigurationHandle", "SubKeyName", "SubKeyHandle"]),
        #
        'NdisOpenConfigurationKeyByIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "ConfigurationHandle", "Index", "KeyName", "KeyHandle"]),
        #
        'NdisReadConfiguration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("NDIS_CONFIGURATION_PARAMETER", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="NDIS_PARAMETER_TYPE")], SimTypeBottom(label="Void"), arg_names=["Status", "ParameterValue", "ConfigurationHandle", "Keyword", "ParameterType"]),
        #
        'NdisWriteConfiguration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("NDIS_CONFIGURATION_PARAMETER", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "ConfigurationHandle", "Keyword", "ParameterValue"]),
        #
        'NdisCloseConfiguration': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ConfigurationHandle"]),
        #
        'NdisReadNetworkAddress': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "NetworkAddress", "NetworkAddressLength", "ConfigurationHandle"]),
        #
        'NdisCopyBuffer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Status", "Buffer", "PoolHandle", "MemoryDescriptor", "Offset", "Length"]),
        #
        'NdisAllocateMemoryWithTag': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["VirtualAddress", "Length", "Tag"]),
        #
        'NdisFreeMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["VirtualAddress", "Length", "MemoryFlags"]),
        #
        'NdisInitializeEvent': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_EVENT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Event"]),
        #
        'NdisSetEvent': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_EVENT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Event"]),
        #
        'NdisResetEvent': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_EVENT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Event"]),
        #
        'NdisWaitEvent': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_EVENT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["Event", "MsToWait"]),
        #
        'NdisOpenFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeBottom(label="Void"), arg_names=["Status", "FileHandle", "FileLength", "FileName", "HighestAcceptableAddress"]),
        #
        'NdisCloseFile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileHandle"]),
        #
        'NdisMapFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "MappedBuffer", "FileHandle"]),
        #
        'NdisUnmapFile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileHandle"]),
        #
        'NdisGetSharedDataAlignment': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'NdisWriteErrorLogEntry': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["NdisAdapterHandle", "ErrorCode", "NumberOfErrorValues"]),
        #
        'NdisInitializeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Destination", "Source"]),
        #
        'NdisInitializeTimer': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_TIMER", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Timer", "TimerFunction", "FunctionContext"]),
        #
        'NdisCancelTimer': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_TIMER", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Timer", "TimerCancelled"]),
        #
        'NdisSetTimer': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_TIMER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Timer", "MillisecondsToDelay"]),
        #
        'NdisSetPeriodicTimer': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_TIMER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["NdisTimer", "MillisecondsPeriod"]),
        #
        'NdisSetTimerEx': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_TIMER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["NdisTimer", "MillisecondsToDelay", "FunctionContext"]),
        #
        'NdisSystemProcessorCount': SimTypeFunction([], SimTypeChar(label="SByte")),
        #
        'NdisGetRoutineAddress': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["NdisRoutineName"]),
        #
        'NdisGetVersion': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'NdisReEnumerateProtocolBindings': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["NdisProtocolHandle"]),
        #
        'NdisWriteEventLogEntry': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogHandle", "EventCode", "UniqueEventValue", "NumStrings", "StringsList", "DataSize", "Data"]),
        #
        'NdisQueryAdapterInstanceName': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapterInstanceName", "NdisBindingHandle"]),
        #
        'NdisQueryBindInstanceName': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapterInstanceName", "BindingContext"]),
        #
        'NdisRegisterTdiCallBack': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceName", "TdiHandle"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["UpperComponent", "LowerComponent", "BindList", "ReconfigBuffer", "ReconfigBufferSize", "Operation"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["RegisterCallback", "PnPHandler"]),
        #
        'NdisDeregisterTdiCallBack': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'NdisGeneratePartialCancelId': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'NdisMAllocateSharedMemoryAsync': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MiniportAdapterHandle", "Length", "Cached", "Context"]),
        #
        'NdisSetupDmaTransfer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["Status", "NdisDmaHandle", "Buffer", "Offset", "Length", "WriteToDevice"]),
        #
        'NdisCompleteDmaTransfer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["Status", "NdisDmaHandle", "Buffer", "Offset", "Length", "WriteToDevice"]),
        #
        'NdisMRegisterDmaChannel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("NDIS_DMA_DESCRIPTION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["MiniportDmaHandle", "MiniportAdapterHandle", "DmaChannel", "Dma32BitAddresses", "DmaDescription", "MaximumLength"]),
        #
        'NdisMDeregisterDmaChannel': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["MiniportDmaHandle"]),
        #
        'NdisMReadDmaCounter': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["MiniportDmaHandle"]),
        #
        'NdisUpdateSharedMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeBottom(label="Void"), arg_names=["NdisAdapterHandle", "Length", "VirtualAddress", "PhysicalAddress"]),
        #
        'NdisIMAssociateMiniport': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["DriverHandle", "ProtocolHandle"]),
        #
        'NdisMRegisterIoPortRange': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["PortOffset", "MiniportAdapterHandle", "InitialPort", "NumberOfPorts"]),
        #
        'NdisMDeregisterIoPortRange': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["MiniportAdapterHandle", "InitialPort", "NumberOfPorts", "PortOffset"]),
        #
        'NdisMMapIoSpace': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["VirtualAddress", "MiniportAdapterHandle", "PhysicalAddress", "Length"]),
        #
        'NdisMUnmapIoSpace': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["MiniportAdapterHandle", "VirtualAddress", "Length"]),
        #
        'NdisMSetPeriodicTimer': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_MINIPORT_TIMER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Timer", "MillisecondPeriod"]),
        #
        'NdisMInitializeTimer': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_MINIPORT_TIMER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Timer", "MiniportAdapterHandle", "TimerFunction", "FunctionContext"]),
        #
        'NdisMCancelTimer': SimTypeFunction([SimTypePointer(SimTypeRef("NDIS_MINIPORT_TIMER", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Timer", "TimerCancelled"]),
        #
        'NdisMSleep': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["MicrosecondsToSleep"]),
        #
        'NdisMGetDmaAlignment': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["MiniportAdapterHandle"]),
        #
        'NdisMAllocateSharedMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeBottom(label="Void"), arg_names=["MiniportAdapterHandle", "Length", "Cached", "VirtualAddress", "PhysicalAddress"]),
        #
        'NdisMFreeSharedMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeBottom(label="Void"), arg_names=["MiniportAdapterHandle", "Length", "Cached", "VirtualAddress", "PhysicalAddress"]),
        #
        'NdisIMInitializeDeviceInstanceEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverHandle", "DriverInstance", "DeviceContext"]),
        #
        'NdisIMCancelInitializeDeviceInstance': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverHandle", "DeviceInstance"]),
        #
        'NdisIMGetBindingContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["NdisBindingHandle"]),
        #
        'NdisIMDeInitializeDeviceInstance': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisMiniportHandle"]),
        #
        'NdisMRemoveMiniport': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MiniportHandle"]),
        #
        'NdisMCreateLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MiniportAdapterHandle", "Size", "LogHandle"]),
        #
        'NdisMCloseLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["LogHandle"]),
        #
        'NdisMWriteLogData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["LogHandle", "LogBuffer", "LogBufferSize"]),
        #
        'NdisMFlushLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["LogHandle"]),
        #
        'NdisMGetDeviceProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CM_RESOURCE_LIST", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CM_RESOURCE_LIST", SimStruct), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["MiniportAdapterHandle", "PhysicalDeviceObject", "FunctionalDeviceObject", "NextDeviceObject", "AllocatedResources", "AllocatedResourcesTranslated"]),
        #
        'NdisMQueryAdapterInstanceName': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapterInstanceName", "MiniportHandle"]),
        #
        'NdisMCoActivateVcComplete': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "NdisVcHandle", "CallParameters"]),
        #
        'NdisMCoDeactivateVcComplete': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "NdisVcHandle"]),
        #
        'NdisMCmRegisterAddressFamily': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CO_ADDRESS_FAMILY", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["MiniportAdapterHandle", "AddressFamily", "CmCharacteristics", "SizeOfCmCharacteristics"]),
        #
        'NdisMCmCreateVc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MiniportAdapterHandle", "NdisAfHandle", "MiniportVcContext", "NdisVcHandle"]),
        #
        'NdisMCmDeleteVc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisVcHandle"]),
        #
        'NdisMCmActivateVc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisVcHandle", "CallParameters"]),
        #
        'NdisMCmDeactivateVc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisVcHandle"]),
        #
        'NdisCoAssignInstanceName': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisVcHandle", "BaseInstanceName", "VcInstanceName"]),
        #
        'NdisCoCreateVc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisBindingHandle", "NdisAfHandle", "ProtocolVcContext", "NdisVcHandle"]),
        #
        'NdisCoDeleteVc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisVcHandle"]),
        #
        'NdisCoGetTapiCallId': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("VAR_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisVcHandle", "TapiCallId"]),
        #
        'NdisClCloseAddressFamily': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisAfHandle"]),
        #
        'NdisClRegisterSap': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CO_SAP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisAfHandle", "ProtocolSapContext", "Sap", "NdisSapHandle"]),
        #
        'NdisClDeregisterSap': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisSapHandle"]),
        #
        'NdisClMakeCall': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisVcHandle", "CallParameters", "ProtocolPartyContext", "NdisPartyHandle"]),
        #
        'NdisClCloseCall': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisVcHandle", "NdisPartyHandle", "Buffer", "Size"]),
        #
        'NdisClModifyCallQoS': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisVcHandle", "CallParameters"]),
        #
        'NdisClIncomingCallComplete': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "NdisVcHandle", "CallParameters"]),
        #
        'NdisClAddParty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisVcHandle", "ProtocolPartyContext", "CallParameters", "NdisPartyHandle"]),
        #
        'NdisClDropParty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisPartyHandle", "Buffer", "Size"]),
        #
        'NdisClGetProtocolVcContextFromTapiCallId': SimTypeFunction([SimTypeRef("UNICODE_STRING", SimStruct), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TapiCallId", "ProtocolVcContext"]),
        #
        'NdisCmOpenAddressFamilyComplete': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "NdisAfHandle", "CallMgrAfContext"]),
        #
        'NdisCmCloseAddressFamilyComplete': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "NdisAfHandle"]),
        #
        'NdisCmRegisterSapComplete': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "NdisSapHandle", "CallMgrSapContext"]),
        #
        'NdisCmDeregisterSapComplete': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "NdisSapHandle"]),
        #
        'NdisCmActivateVc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisVcHandle", "CallParameters"]),
        #
        'NdisCmDeactivateVc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisVcHandle"]),
        #
        'NdisCmMakeCallComplete': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "NdisVcHandle", "NdisPartyHandle", "CallMgrPartyContext", "CallParameters"]),
        #
        'NdisCmCloseCallComplete': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "NdisVcHandle", "NdisPartyHandle"]),
        #
        'NdisCmAddPartyComplete': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "NdisPartyHandle", "CallMgrPartyContext", "CallParameters"]),
        #
        'NdisCmDropPartyComplete': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "NdisPartyHandle"]),
        #
        'NdisCmDispatchIncomingCall': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NdisSapHandle", "NdisVcHandle", "CallParameters"]),
        #
        'NdisCmDispatchCallConnected': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["NdisVcHandle"]),
        #
        'NdisCmModifyCallQoSComplete': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "NdisVcHandle", "CallParameters"]),
        #
        'NdisCmDispatchIncomingCallQoSChange': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["NdisVcHandle", "CallParameters"]),
        #
        'NdisCmDispatchIncomingCloseCall': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["CloseStatus", "NdisVcHandle", "Buffer", "Size"]),
        #
        'NdisCmDispatchIncomingDropParty': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["DropStatus", "NdisPartyHandle", "Buffer", "Size"]),
    }

lib.set_prototypes(prototypes)
