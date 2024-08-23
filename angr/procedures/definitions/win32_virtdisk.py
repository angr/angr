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
lib.set_library_names("virtdisk.dll")
prototypes = \
    {
        #
        'OpenVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeRef("VIRTUAL_STORAGE_TYPE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="VIRTUAL_DISK_ACCESS_MASK"), SimTypeInt(signed=False, label="OPEN_VIRTUAL_DISK_FLAG"), SimTypePointer(SimTypeRef("OPEN_VIRTUAL_DISK_PARAMETERS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualStorageType", "Path", "VirtualDiskAccessMask", "Flags", "Parameters", "Handle"]),
        #
        'CreateVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeRef("VIRTUAL_STORAGE_TYPE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="VIRTUAL_DISK_ACCESS_MASK"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="CREATE_VIRTUAL_DISK_FLAG"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CREATE_VIRTUAL_DISK_PARAMETERS", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualStorageType", "Path", "VirtualDiskAccessMask", "SecurityDescriptor", "Flags", "ProviderSpecificFlags", "Parameters", "Overlapped", "Handle"]),
        #
        'AttachVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="ATTACH_VIRTUAL_DISK_FLAG"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ATTACH_VIRTUAL_DISK_PARAMETERS", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "SecurityDescriptor", "Flags", "ProviderSpecificFlags", "Parameters", "Overlapped"]),
        #
        'DetachVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DETACH_VIRTUAL_DISK_FLAG"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Flags", "ProviderSpecificFlags"]),
        #
        'GetVirtualDiskPhysicalPath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "DiskPathSizeInBytes", "DiskPath"]),
        #
        'GetAllAttachedVirtualDiskPhysicalPaths': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["PathsBufferSizeInBytes", "PathsBuffer"]),
        #
        'GetStorageDependencyInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_STORAGE_DEPENDENCY_FLAG"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("STORAGE_DEPENDENCY_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["ObjectHandle", "Flags", "StorageDependencyInfoSize", "StorageDependencyInfo", "SizeUsed"]),
        #
        'GetVirtualDiskInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("GET_VIRTUAL_DISK_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "VirtualDiskInfoSize", "VirtualDiskInfo", "SizeUsed"]),
        #
        'SetVirtualDiskInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SET_VIRTUAL_DISK_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "VirtualDiskInfo"]),
        #
        'EnumerateVirtualDiskMetadata': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "NumberOfItems", "Items"]),
        #
        'GetVirtualDiskMetadata': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Item", "MetaDataSize", "MetaData"]),
        #
        'SetVirtualDiskMetadata': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Item", "MetaDataSize", "MetaData"]),
        #
        'DeleteVirtualDiskMetadata': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Item"]),
        #
        'GetVirtualDiskOperationProgress': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeRef("VIRTUAL_DISK_PROGRESS", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Overlapped", "Progress"]),
        #
        'CompactVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="COMPACT_VIRTUAL_DISK_FLAG"), SimTypePointer(SimTypeRef("COMPACT_VIRTUAL_DISK_PARAMETERS", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Flags", "Parameters", "Overlapped"]),
        #
        'MergeVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MERGE_VIRTUAL_DISK_FLAG"), SimTypePointer(SimTypeRef("MERGE_VIRTUAL_DISK_PARAMETERS", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Flags", "Parameters", "Overlapped"]),
        #
        'ExpandVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="EXPAND_VIRTUAL_DISK_FLAG"), SimTypePointer(SimTypeRef("EXPAND_VIRTUAL_DISK_PARAMETERS", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Flags", "Parameters", "Overlapped"]),
        #
        'ResizeVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="RESIZE_VIRTUAL_DISK_FLAG"), SimTypePointer(SimTypeRef("RESIZE_VIRTUAL_DISK_PARAMETERS", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Flags", "Parameters", "Overlapped"]),
        #
        'MirrorVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MIRROR_VIRTUAL_DISK_FLAG"), SimTypePointer(SimTypeRef("MIRROR_VIRTUAL_DISK_PARAMETERS", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Flags", "Parameters", "Overlapped"]),
        #
        'BreakMirrorVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle"]),
        #
        'AddVirtualDiskParent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "ParentPath"]),
        #
        'QueryChangesVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="QUERY_CHANGES_VIRTUAL_DISK_FLAG"), SimTypePointer(SimTypeRef("QUERY_CHANGES_VIRTUAL_DISK_RANGE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "ChangeTrackingId", "ByteOffset", "ByteLength", "Flags", "Ranges", "RangeCount", "ProcessedLength"]),
        #
        'TakeSnapshotVhdSet': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TAKE_SNAPSHOT_VHDSET_PARAMETERS", SimStruct), offset=0), SimTypeInt(signed=False, label="TAKE_SNAPSHOT_VHDSET_FLAG")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Parameters", "Flags"]),
        #
        'DeleteSnapshotVhdSet': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DELETE_SNAPSHOT_VHDSET_PARAMETERS", SimStruct), offset=0), SimTypeInt(signed=False, label="DELETE_SNAPSHOT_VHDSET_FLAG")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Parameters", "Flags"]),
        #
        'ModifyVhdSet': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MODIFY_VHDSET_PARAMETERS", SimStruct), offset=0), SimTypeInt(signed=False, label="MODIFY_VHDSET_FLAG")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Parameters", "Flags"]),
        #
        'ApplySnapshotVhdSet': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("APPLY_SNAPSHOT_VHDSET_PARAMETERS", SimStruct), offset=0), SimTypeInt(signed=False, label="APPLY_SNAPSHOT_VHDSET_FLAG")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Parameters", "Flags"]),
        #
        'RawSCSIVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RAW_SCSI_VIRTUAL_DISK_PARAMETERS", SimStruct), offset=0), SimTypeInt(signed=False, label="RAW_SCSI_VIRTUAL_DISK_FLAG"), SimTypePointer(SimTypeRef("RAW_SCSI_VIRTUAL_DISK_RESPONSE", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Parameters", "Flags", "Response"]),
        #
        'ForkVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="FORK_VIRTUAL_DISK_FLAG"), SimTypePointer(SimTypeRef("FORK_VIRTUAL_DISK_PARAMETERS", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle", "Flags", "Parameters", "Overlapped"]),
        #
        'CompleteForkVirtualDisk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["VirtualDiskHandle"]),
    }

lib.set_prototypes(prototypes)
