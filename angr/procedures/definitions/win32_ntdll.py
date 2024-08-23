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
lib.add('RtlEncodePointer', P['win32']['EncodePointer'])
lib.add('RtlDecodePointer', P['win32']['EncodePointer'])
lib.add('RtlAllocateHeap', P['win32']['HeapAlloc'])
lib.set_library_names("ntdll.dll")
prototypes = \
    {
        #
        'RtlNtStatusToDosError': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Status"]),
        #
        'RtlIpv4AddressToStringA': SimTypeFunction([SimTypePointer(SimTypeRef("IN_ADDR", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["Addr", "S"]),
        #
        'RtlIpv4AddressToStringExA': SimTypeFunction([SimTypePointer(SimTypeRef("IN_ADDR", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Address", "Port", "AddressString", "AddressStringLength"]),
        #
        'RtlIpv4AddressToStringW': SimTypeFunction([SimTypePointer(SimTypeRef("IN_ADDR", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["Addr", "S"]),
        #
        'RtlIpv4AddressToStringExW': SimTypeFunction([SimTypePointer(SimTypeRef("IN_ADDR", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Address", "Port", "AddressString", "AddressStringLength"]),
        #
        'RtlIpv4StringToAddressA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeRef("IN_ADDR", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["S", "Strict", "Terminator", "Addr"]),
        #
        'RtlIpv4StringToAddressExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("IN_ADDR", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AddressString", "Strict", "Address", "Port"]),
        #
        'RtlIpv4StringToAddressW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeRef("IN_ADDR", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["S", "Strict", "Terminator", "Addr"]),
        #
        'RtlIpv4StringToAddressExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("IN_ADDR", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AddressString", "Strict", "Address", "Port"]),
        #
        'RtlIpv6AddressToStringA': SimTypeFunction([SimTypePointer(SimTypeRef("IN6_ADDR", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["Addr", "S"]),
        #
        'RtlIpv6AddressToStringExA': SimTypeFunction([SimTypePointer(SimTypeRef("IN6_ADDR", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Address", "ScopeId", "Port", "AddressString", "AddressStringLength"]),
        #
        'RtlIpv6AddressToStringW': SimTypeFunction([SimTypePointer(SimTypeRef("IN6_ADDR", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["Addr", "S"]),
        #
        'RtlIpv6AddressToStringExW': SimTypeFunction([SimTypePointer(SimTypeRef("IN6_ADDR", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Address", "ScopeId", "Port", "AddressString", "AddressStringLength"]),
        #
        'RtlIpv6StringToAddressA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeRef("IN6_ADDR", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["S", "Terminator", "Addr"]),
        #
        'RtlIpv6StringToAddressExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("IN6_ADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AddressString", "Address", "ScopeId", "Port"]),
        #
        'RtlIpv6StringToAddressW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeRef("IN6_ADDR", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["S", "Terminator", "Addr"]),
        #
        'RtlIpv6StringToAddressExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("IN6_ADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AddressString", "Address", "ScopeId", "Port"]),
        #
        'RtlEthernetAddressToStringA': SimTypeFunction([SimTypePointer(SimUnion({"Byte": SimTypeArray(SimTypeChar(label="Byte"), 6), "Anonymous": SimStruct(OrderedDict((("Oui", SimUnion({"Byte": SimTypeArray(SimTypeChar(label="Byte"), 3), "Anonymous": SimStruct(OrderedDict((("_bitfield", SimTypeChar(label="Byte")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None")), ("Ei48", SimUnion({"Byte": SimTypeArray(SimTypeChar(label="Byte"), 3)}, name="<anon>", label="None")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["Addr", "S"]),
        #
        'RtlEthernetAddressToStringW': SimTypeFunction([SimTypePointer(SimUnion({"Byte": SimTypeArray(SimTypeChar(label="Byte"), 6), "Anonymous": SimStruct(OrderedDict((("Oui", SimUnion({"Byte": SimTypeArray(SimTypeChar(label="Byte"), 3), "Anonymous": SimStruct(OrderedDict((("_bitfield", SimTypeChar(label="Byte")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None")), ("Ei48", SimUnion({"Byte": SimTypeArray(SimTypeChar(label="Byte"), 3)}, name="<anon>", label="None")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["Addr", "S"]),
        #
        'RtlEthernetStringToAddressA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimUnion({"Byte": SimTypeArray(SimTypeChar(label="Byte"), 6), "Anonymous": SimStruct(OrderedDict((("Oui", SimUnion({"Byte": SimTypeArray(SimTypeChar(label="Byte"), 3), "Anonymous": SimStruct(OrderedDict((("_bitfield", SimTypeChar(label="Byte")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None")), ("Ei48", SimUnion({"Byte": SimTypeArray(SimTypeChar(label="Byte"), 3)}, name="<anon>", label="None")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["S", "Terminator", "Addr"]),
        #
        'RtlEthernetStringToAddressW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimUnion({"Byte": SimTypeArray(SimTypeChar(label="Byte"), 6), "Anonymous": SimStruct(OrderedDict((("Oui", SimUnion({"Byte": SimTypeArray(SimTypeChar(label="Byte"), 3), "Anonymous": SimStruct(OrderedDict((("_bitfield", SimTypeChar(label="Byte")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None")), ("Ei48", SimUnion({"Byte": SimTypeArray(SimTypeChar(label="Byte"), 3)}, name="<anon>", label="None")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["S", "Terminator", "Addr"]),
        #
        'RtlNormalizeSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["SecurityDescriptor", "SecurityDescriptorLength", "NewSecurityDescriptor", "NewSecurityDescriptorLength", "CheckOnly"]),
        #
        'RtlConvertSidToUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["UnicodeString", "Sid", "AllocateDestinationString"]),
        #
        'RtlInitializeCorrelationVector': SimTypeFunction([SimTypePointer(SimTypeRef("CORRELATION_VECTOR", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["CorrelationVector", "Version", "Guid"]),
        #
        'RtlIncrementCorrelationVector': SimTypeFunction([SimTypePointer(SimTypeRef("CORRELATION_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["CorrelationVector"]),
        #
        'RtlExtendCorrelationVector': SimTypeFunction([SimTypePointer(SimTypeRef("CORRELATION_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["CorrelationVector"]),
        #
        'RtlValidateCorrelationVector': SimTypeFunction([SimTypePointer(SimTypeRef("CORRELATION_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Vector"]),
        #
        'RtlAddGrowableFunctionTable': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DynamicTable", "FunctionTable", "EntryCount", "MaximumEntryCount", "RangeBase", "RangeEnd"]),
        #
        'RtlAddGrowableFunctionTable': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("IMAGE_RUNTIME_FUNCTION_ENTRY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DynamicTable", "FunctionTable", "EntryCount", "MaximumEntryCount", "RangeBase", "RangeEnd"]),
        #
        'RtlGrowFunctionTable': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["DynamicTable", "NewEntryCount"]),
        #
        'RtlDeleteGrowableFunctionTable': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["DynamicTable"]),
        #
        'RtlInitializeSListHead': SimTypeFunction([SimTypePointer(SimUnion({"Alignment": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct(OrderedDict((("Next", SimTypeRef("SINGLE_LIST_ENTRY", SimStruct)), ("Depth", SimTypeShort(signed=False, label="UInt16")), ("CpuId", SimTypeShort(signed=False, label="UInt16")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ListHead"]),
        #
        'RtlFirstEntrySList': SimTypeFunction([SimTypePointer(SimUnion({"Alignment": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct(OrderedDict((("Next", SimTypeRef("SINGLE_LIST_ENTRY", SimStruct)), ("Depth", SimTypeShort(signed=False, label="UInt16")), ("CpuId", SimTypeShort(signed=False, label="UInt16")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0)], SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0), arg_names=["ListHead"]),
        #
        'RtlInterlockedPopEntrySList': SimTypeFunction([SimTypePointer(SimUnion({"Alignment": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct(OrderedDict((("Next", SimTypeRef("SINGLE_LIST_ENTRY", SimStruct)), ("Depth", SimTypeShort(signed=False, label="UInt16")), ("CpuId", SimTypeShort(signed=False, label="UInt16")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0)], SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0), arg_names=["ListHead"]),
        #
        'RtlInterlockedPushEntrySList': SimTypeFunction([SimTypePointer(SimUnion({"Alignment": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct(OrderedDict((("Next", SimTypeRef("SINGLE_LIST_ENTRY", SimStruct)), ("Depth", SimTypeShort(signed=False, label="UInt16")), ("CpuId", SimTypeShort(signed=False, label="UInt16")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0)], SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0), arg_names=["ListHead", "ListEntry"]),
        #
        'RtlInterlockedPushListSListEx': SimTypeFunction([SimTypePointer(SimUnion({"Alignment": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct(OrderedDict((("Next", SimTypeRef("SINGLE_LIST_ENTRY", SimStruct)), ("Depth", SimTypeShort(signed=False, label="UInt16")), ("CpuId", SimTypeShort(signed=False, label="UInt16")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0), SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0), arg_names=["ListHead", "List", "ListEnd", "Count"]),
        #
        'RtlInterlockedFlushSList': SimTypeFunction([SimTypePointer(SimUnion({"Alignment": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct(OrderedDict((("Next", SimTypeRef("SINGLE_LIST_ENTRY", SimStruct)), ("Depth", SimTypeShort(signed=False, label="UInt16")), ("CpuId", SimTypeShort(signed=False, label="UInt16")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0)], SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0), arg_names=["ListHead"]),
        #
        'RtlQueryDepthSList': SimTypeFunction([SimTypePointer(SimUnion({"Alignment": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct(OrderedDict((("Next", SimTypeRef("SINGLE_LIST_ENTRY", SimStruct)), ("Depth", SimTypeShort(signed=False, label="UInt16")), ("CpuId", SimTypeShort(signed=False, label="UInt16")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["ListHead"]),
        #
        'RtlCrc32': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Buffer", "Size", "InitialCrc"]),
        #
        'RtlCrc64': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["Buffer", "Size", "InitialCrc"]),
        #
        'RtlIsZeroMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["Buffer", "Length"]),
        #
        'RtlGetNonVolatileToken': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["NvBuffer", "Size", "NvToken"]),
        #
        'RtlFreeNonVolatileToken': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["NvToken"]),
        #
        'RtlFlushNonVolatileMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["NvToken", "NvBuffer", "Size", "Flags"]),
        #
        'RtlDrainNonVolatileFlush': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["NvToken"]),
        #
        'RtlWriteNonVolatileMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["NvToken", "NvDestination", "Source", "Size", "Flags"]),
        #
        'RtlFillNonVolatileMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["NvToken", "NvDestination", "Size", "Value", "Flags"]),
        #
        'RtlFlushNonVolatileMemoryRanges': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("NV_MEMORY_RANGE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["NvToken", "NvRanges", "NumRanges", "Flags"]),
        #
        'RtlGetProductInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["OSMajorVersion", "OSMinorVersion", "SpMajorVersion", "SpMinorVersion", "ReturnedProductType"]),
        #
        'RtlOsDeploymentState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="OS_DEPLOYEMENT_STATE_VALUES"), arg_names=["Flags"]),
        #
        'RtlGetDeviceFamilyInfoEnum': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="DEVICEFAMILYINFOENUM"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="DEVICEFAMILYDEVICEFORM"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pullUAPInfo", "pulDeviceFamily", "pulDeviceForm"]),
        #
        'RtlConvertDeviceFamilyInfoToString': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pulDeviceFamilyBufferSize", "pulDeviceFormBufferSize", "DeviceFamily", "DeviceForm"]),
        #
        'RtlSwitchedVVI': SimTypeFunction([SimTypePointer(SimTypeRef("OSVERSIONINFOEXW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=False, label="UInt32"), arg_names=["VersionInfo", "TypeMask", "ConditionMask"]),
        #
        'RtlGetReturnAddressHijackTarget': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)),
        #
        'RtlRaiseCustomSystemEventTrigger': SimTypeFunction([SimTypePointer(SimTypeRef("CUSTOM_SYSTEM_EVENT_TRIGGER_CONFIG", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TriggerConfig"]),
        #
        'RtlIsNameLegalDOS8Dot3': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Name", "OemName", "NameContainsSpaces"]),
        #
        'RtlLocalTimeToSystemTime': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LocalTime", "SystemTime"]),
        #
        'RtlTimeToSecondsSince1970': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Time", "ElapsedSeconds"]),
        #
        'RtlFreeAnsiString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["AnsiString"]),
        #
        'RtlFreeUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["UnicodeString"]),
        #
        'RtlFreeOemString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["OemString"]),
        #
        'RtlInitString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["DestinationString", "SourceString"]),
        #
        'RtlInitStringEx': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString"]),
        #
        'RtlInitAnsiString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["DestinationString", "SourceString"]),
        #
        'RtlInitAnsiStringEx': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString"]),
        #
        'RtlInitUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["DestinationString", "SourceString"]),
        #
        'RtlAnsiStringToUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString", "AllocateDestinationString"]),
        #
        'RtlUnicodeStringToAnsiString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString", "AllocateDestinationString"]),
        #
        'RtlUnicodeStringToOemString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString", "AllocateDestinationString"]),
        #
        'RtlUnicodeToMultiByteSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["BytesInMultiByteString", "UnicodeString", "BytesInUnicodeString"]),
        #
        'RtlCharToInteger': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["String", "Base", "Value"]),
        #
        'RtlUniform': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Seed"]),
    }

lib.set_prototypes(prototypes)
