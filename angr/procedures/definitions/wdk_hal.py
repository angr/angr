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
lib.set_library_names("hal.dll")
prototypes = \
    {
        #
        'KeFlushWriteBuffer': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'KeQueryPerformanceCounter': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["PerformanceFrequency"]),
        #
        'KeStallExecutionProcessor': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["MicroSeconds"]),
        #
        'HalAcquireDisplayOwnership': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["Columns", "Rows"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["ResetDisplayParameters"]),
        #
        'HalAssignSlotResources': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="INTERFACE_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("CM_RESOURCE_LIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RegistryPath", "DriverClassName", "DriverObject", "DeviceObject", "BusType", "BusNumber", "SlotNumber", "AllocatedResources"]),
        #
        'HalGetInterruptVector': SimTypeFunction([SimTypeInt(signed=False, label="INTERFACE_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InterfaceType", "BusNumber", "BusInterruptLevel", "BusInterruptVector", "Irql", "Affinity"]),
        #
        'HalSetBusData': SimTypeFunction([SimTypeInt(signed=False, label="BUS_DATA_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["BusDataType", "BusNumber", "SlotNumber", "Buffer", "Length"]),
        #
        'HalSetBusDataByOffset': SimTypeFunction([SimTypeInt(signed=False, label="BUS_DATA_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["BusDataType", "BusNumber", "SlotNumber", "Buffer", "Offset", "Length"]),
        #
        'HalTranslateBusAddress': SimTypeFunction([SimTypeInt(signed=False, label="INTERFACE_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeChar(label="Byte"), arg_names=["InterfaceType", "BusNumber", "BusAddress", "AddressSpace", "TranslatedAddress"]),
        #
        'HalAllocateCrashDumpRegisters': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["AdapterObject", "NumberOfMapRegisters"]),
        #
        'HalDmaAllocateCrashDumpRegistersEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="HAL_DMA_CRASH_DUMP_REGISTER_TYPE"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Adapter", "NumberOfMapRegisters", "Type", "MapRegisterBase", "MapRegistersAvailable"]),
        #
        'HalDmaFreeCrashDumpRegistersEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="HAL_DMA_CRASH_DUMP_REGISTER_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["Adapter", "Type"]),
        #
        'HalGetBusData': SimTypeFunction([SimTypeInt(signed=False, label="BUS_DATA_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["BusDataType", "BusNumber", "SlotNumber", "Buffer", "Length"]),
        #
        'HalGetBusDataByOffset': SimTypeFunction([SimTypeInt(signed=False, label="BUS_DATA_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["BusDataType", "BusNumber", "SlotNumber", "Buffer", "Offset", "Length"]),
        #
        'HalGetAdapter': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_DESCRIPTION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["DeviceDescription", "NumberOfMapRegisters"]),
        #
        'HalMakeBeep': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["Frequency"]),
        #
        'HalAllocateAdapterChannel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("WAIT_CONTEXT_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="IO_ALLOCATION_ACTION"), arg_names=["DeviceObject", "Irp", "MapRegisterBase", "Context"]), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AdapterObject", "Wcb", "NumberOfMapRegisters", "ExecutionRoutine"]),
        #
        'HalAllocateCommonBuffer': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["AdapterObject", "Length", "LogicalAddress", "CacheEnabled"]),
        #
        'HalFreeCommonBuffer': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["AdapterObject", "Length", "LogicalAddress", "VirtualAddress", "CacheEnabled"]),
        #
        'HalReadDmaCounter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AdapterObject"]),
        #
        'IoFlushAdapterBuffers': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["AdapterObject", "Mdl", "MapRegisterBase", "CurrentVa", "Length", "WriteToDevice"]),
        #
        'IoFreeAdapterChannel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["AdapterObject"]),
        #
        'IoFreeMapRegisters': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["AdapterObject", "MapRegisterBase", "NumberOfMapRegisters"]),
        #
        'IoMapTransfer': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeChar(label="Byte")], SimTypeLongLong(signed=True, label="Int64"), arg_names=["AdapterObject", "Mdl", "MapRegisterBase", "CurrentVa", "Length", "WriteToDevice"]),
        #
        'HalBugCheckSystem': SimTypeFunction([SimTypePointer(SimTypeRef("WHEA_ERROR_SOURCE_DESCRIPTOR", SimStruct), offset=0), SimTypePointer(SimTypeRef("WHEA_ERROR_RECORD", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ErrorSource", "ErrorRecord"]),
        #
        'HalAllocateHardwareCounters': SimTypeFunction([SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHYSICAL_COUNTER_RESOURCE_LIST", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["GroupAffinty", "GroupCount", "ResourceList", "CounterSetHandle"]),
        #
        'HalFreeHardwareCounters': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CounterSetHandle"]),
    }

lib.set_prototypes(prototypes)
