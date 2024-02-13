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
lib.set_library_names("vmsavedstatedumpprovider.dll")
prototypes = \
    {
        #
        'LocateSavedStateFiles': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmName", "snapshotName", "binPath", "vsvPath", "vmrsPath"]),
        #
        'LoadSavedStateFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmrsFile", "vmSavedStateDumpHandle"]),
        #
        'ApplyPendingSavedStateFileReplayLog': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmrsFile"]),
        #
        'LoadSavedStateFiles': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["binFile", "vsvFile", "vmSavedStateDumpHandle"]),
        #
        'ReleaseSavedStateFiles': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle"]),
        #
        'GetGuestEnabledVirtualTrustLevels': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "virtualTrustLevels"]),
        #
        'GetGuestOsInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimUnion({"AsUINT64": SimTypeLongLong(signed=False, label="UInt64"), "ClosedSource": SimTypeRef("_ClosedSource_e__Struct", SimStruct), "OpenSource": SimTypeRef("_OpenSource_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "virtualTrustLevel", "guestOsInfo"]),
        #
        'GetVpCount': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpCount"]),
        #
        'GetArchitecture': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="VIRTUAL_PROCESSOR_ARCH"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "architecture"]),
        #
        'ForceArchitecture': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="VIRTUAL_PROCESSOR_ARCH")], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "architecture"]),
        #
        'GetActiveVirtualTrustLevel': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "virtualTrustLevel"]),
        #
        'GetEnabledVirtualTrustLevels': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "virtualTrustLevels"]),
        #
        'ForceActiveVirtualTrustLevel': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "virtualTrustLevel"]),
        #
        'IsActiveVirtualTrustLevelEnabled': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "activeVirtualTrustLevelEnabled"]),
        #
        'IsNestedVirtualizationEnabled': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "enabled"]),
        #
        'GetNestedVirtualizationMode': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "enabled"]),
        #
        'ForceNestedHostMode': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "hostMode", "oldMode"]),
        #
        'InKernelSpace': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "inKernelSpace"]),
        #
        'GetRegisterValue': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimUnion({"Reg64": SimTypeLongLong(signed=False, label="UInt64"), "Reg32": SimTypeInt(signed=False, label="UInt32"), "Reg16": SimTypeShort(signed=False, label="UInt16"), "Reg8": SimTypeChar(label="Byte"), "Reg128": SimTypeRef("_Reg128_e__Struct", SimStruct), "X64": SimUnion({"Segment": SimTypeRef("_Segment_e__Struct", SimStruct), "Table": SimTypeRef("_Table_e__Struct", SimStruct), "FpControlStatus": SimTypeRef("_FpControlStatus_e__Struct", SimStruct), "XmmControlStatus": SimTypeRef("_XmmControlStatus_e__Struct", SimStruct)}, name="<anon>", label="None")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "registerId", "registerValue"]),
        #
        'GetPagingMode': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="PAGING_MODE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "pagingMode"]),
        #
        'ForcePagingMode': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="PAGING_MODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "pagingMode"]),
        #
        'ReadGuestPhysicalAddress': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "physicalAddress", "buffer", "bufferSize", "bytesRead"]),
        #
        'GuestVirtualAddressToPhysicalAddress': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "virtualAddress", "physicalAddress", "unmappedRegionSize"]),
        #
        'GetGuestPhysicalMemoryChunks': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeRef("GPA_MEMORY_CHUNK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "memoryChunkPageSize", "memoryChunks", "memoryChunkCount"]),
        #
        'GuestPhysicalAddressToRawSavedMemoryOffset': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "physicalAddress", "rawSavedMemoryOffset"]),
        #
        'ReadGuestRawSavedMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "rawSavedMemoryOffset", "buffer", "bufferSize", "bytesRead"]),
        #
        'GetGuestRawSavedMemorySize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "guestRawSavedMemorySize"]),
        #
        'SetMemoryBlockCacheLimit': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "memoryBlockCacheLimit"]),
        #
        'GetMemoryBlockCacheLimit': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "memoryBlockCacheLimit"]),
        #
        'ApplyGuestMemoryFix': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "virtualAddress", "fixBuffer", "fixBufferSize"]),
        #
        'LoadSavedStateSymbolProvider': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "userSymbols", "force"]),
        #
        'ReleaseSavedStateSymbolProvider': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle"]),
        #
        'GetSavedStateSymbolProviderHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["vmSavedStateDumpHandle"]),
        #
        'SetSavedStateSymbolProviderDebugInfoCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["InfoMessage"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "Callback"]),
        #
        'LoadSavedStateModuleSymbols': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "imageName", "moduleName", "baseAddress", "sizeOfBase"]),
        #
        'LoadSavedStateModuleSymbolsEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "imageName", "imageTimestamp", "moduleName", "baseAddress", "sizeOfBase"]),
        #
        'ResolveSavedStateGlobalVariableAddress': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "globalName", "virtualAddress", "size"]),
        #
        'ReadSavedStateGlobalVariable': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "globalName", "buffer", "bufferSize"]),
        #
        'GetSavedStateSymbolTypeSize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "typeName", "size"]),
        #
        'FindSavedStateSymbolFieldInType': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "typeName", "fieldName", "offset", "found"]),
        #
        'GetSavedStateSymbolFieldInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "typeName", "typeFieldInfoMap"]),
        #
        'ScanMemoryForDosImages': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("DOS_IMAGE_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Context", "ImageInfo"]), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "startAddress", "endAddress", "callbackContext", "foundImageCallback", "standaloneAddress", "standaloneAddressCount"]),
        #
        'CallStackUnwind': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MODULE_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vmSavedStateDumpHandle", "vpId", "imageInfo", "imageInfoCount", "frameCount", "callStack"]),
    }

lib.set_prototypes(prototypes)
