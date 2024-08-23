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
lib.set_library_names("fltmgr.sys")
prototypes = \
    {
        #
        'FltSetCallbackDataDirty': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Data"]),
        #
        'FltClearCallbackDataDirty': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Data"]),
        #
        'FltIsCallbackDataDirty': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Data"]),
        #
        'FltDoCompletionProcessingWhenSafe': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_RELATED_OBJECTS", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_RELATED_OBJECTS", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="FLT_POSTOP_CALLBACK_STATUS"), arg_names=["Data", "FltObjects", "CompletionContext", "Flags"]), offset=0), SimTypePointer(SimTypeInt(signed=False, label="FLT_POSTOP_CALLBACK_STATUS"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Data", "FltObjects", "CompletionContext", "Flags", "SafePostCallback", "RetPostOperationStatus"]),
        #
        'FltCheckAndGrowNameControl': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_NAME_CONTROL", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["NameCtrl", "NewSize"]),
        #
        'FltPurgeFileNameInformationCache': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject"]),
        #
        'FltRegisterForDataScan': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance"]),
        #
        'FltCreateSectionForDataScan': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "SectionContext", "DesiredAccess", "ObjectAttributes", "MaximumSize", "SectionPageProtection", "AllocationAttributes", "Flags", "SectionHandle", "SectionObject", "SectionFileSize"]),
        #
        'FltCloseSectionForDataScan': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SectionContext"]),
        #
        'FltRegisterFilter': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_REGISTRATION", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Driver", "Registration", "RetFilter"]),
        #
        'FltUnregisterFilter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Filter"]),
        #
        'FltStartFiltering': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter"]),
        #
        'FltGetRoutineAddress': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["FltMgrRoutineName"]),
        #
        'FltCompletePendedPreOperation': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="FLT_PREOP_CALLBACK_STATUS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "CallbackStatus", "Context"]),
        #
        'FltCompletePendedPostOperation': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData"]),
        #
        'FltRequestOperationStatusCallback': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_RELATED_OBJECTS", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_IO_PARAMETER_BLOCK", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["FltObjects", "IopbSnapshot", "OperationStatus", "RequesterContext"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Data", "CallbackRoutine", "RequesterContext"]),
        #
        'FltAllocatePoolAlignedWithTag': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Instance", "PoolType", "NumberOfBytes", "Tag"]),
        #
        'FltFreePoolAlignedWithTag': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Instance", "Buffer", "Tag"]),
        #
        'FltGetFileNameInformation': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("FLT_FILE_NAME_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackData", "NameOptions", "FileNameInformation"]),
        #
        'FltGetFileNameInformationUnsafe': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("FLT_FILE_NAME_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "Instance", "NameOptions", "FileNameInformation"]),
        #
        'FltReleaseFileNameInformation': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_FILE_NAME_INFORMATION", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileNameInformation"]),
        #
        'FltReferenceFileNameInformation': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_FILE_NAME_INFORMATION", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileNameInformation"]),
        #
        'FltParseFileName': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileName", "Extension", "Stream", "FinalComponent"]),
        #
        'FltParseFileNameInformation': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_FILE_NAME_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileNameInformation"]),
        #
        'FltGetTunneledName': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_FILE_NAME_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FLT_FILE_NAME_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackData", "FileNameInformation", "RetTunneledFileNameInformation"]),
        #
        'FltGetVolumeName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Volume", "VolumeName", "BufferSizeNeeded"]),
        #
        'FltGetDestinationFileNameInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("FLT_FILE_NAME_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "RootDirectory", "FileName", "FileNameLength", "NameOptions", "RetFileNameInformation"]),
        #
        'FltIsDirectory': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "Instance", "IsDirectory"]),
        #
        'FltLoadFilter': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FilterName"]),
        #
        'FltUnloadFilter': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FilterName"]),
        #
        'FltAttachVolume': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Volume", "InstanceName", "RetInstance"]),
        #
        'FltAttachVolumeAtAltitude': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Volume", "Altitude", "InstanceName", "RetInstance"]),
        #
        'FltDetachVolume': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Volume", "InstanceName"]),
        #
        'FltAllocateCallbackData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "RetNewCallbackData"]),
        #
        'FltAllocateCallbackDataEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "Flags", "RetNewCallbackData"]),
        #
        'FltFreeCallbackData': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData"]),
        #
        'FltReuseCallbackData': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData"]),
        #
        'FltPerformSynchronousIo': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData"]),
        #
        'FltPerformAsynchronousIo': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackData", "CallbackRoutine", "CallbackContext"]),
        #
        'FltpTraceRedirectedFileIo': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OriginatingFileObject", "ChildCallbackData"]),
        #
        'FltCreateNamedPipeFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("IO_DRIVER_CREATE_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Instance", "FileHandle", "FileObject", "DesiredAccess", "ObjectAttributes", "IoStatusBlock", "ShareAccess", "CreateDisposition", "CreateOptions", "NamedPipeType", "ReadMode", "CompletionMode", "MaximumInstances", "InboundQuota", "OutboundQuota", "DefaultTimeout", "DriverContext"]),
        #
        'FltCreateMailslotFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("IO_DRIVER_CREATE_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Instance", "FileHandle", "FileObject", "DesiredAccess", "ObjectAttributes", "IoStatusBlock", "CreateOptions", "MailslotQuota", "MaximumMessageSize", "ReadTimeout", "DriverContext"]),
        #
        'FltCreateFileEx2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IO_DRIVER_CREATE_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Instance", "FileHandle", "FileObject", "DesiredAccess", "ObjectAttributes", "IoStatusBlock", "AllocationSize", "FileAttributes", "ShareAccess", "CreateDisposition", "CreateOptions", "EaBuffer", "EaLength", "Flags", "DriverContext"]),
        #
        'FltCreateFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Instance", "FileHandle", "FileObject", "DesiredAccess", "ObjectAttributes", "IoStatusBlock", "AllocationSize", "FileAttributes", "ShareAccess", "CreateDisposition", "CreateOptions", "EaBuffer", "EaLength", "Flags"]),
        #
        'FltCreateFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Instance", "FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock", "AllocationSize", "FileAttributes", "ShareAccess", "CreateDisposition", "CreateOptions", "EaBuffer", "EaLength", "Flags"]),
        #
        'FltOpenVolume': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "VolumeHandle", "VolumeFileObject"]),
        #
        'FltReadFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InitiatingInstance", "FileObject", "ByteOffset", "Length", "Buffer", "Flags", "BytesRead", "CallbackRoutine", "CallbackContext"]),
        #
        'FltReadFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InitiatingInstance", "FileObject", "ByteOffset", "Length", "Buffer", "Flags", "BytesRead", "CallbackRoutine", "CallbackContext", "Key", "Mdl"]),
        #
        'FltTagFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["InitiatingInstance", "FileObject", "FileTag", "Guid", "DataBuffer", "DataBufferLength"]),
        #
        'FltTagFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["InitiatingInstance", "FileObject", "FileTag", "Guid", "DataBuffer", "DataBufferLength", "ExistingFileTag", "ExistingGuid", "Flags"]),
        #
        'FltUntagFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InitiatingInstance", "FileObject", "FileTag", "Guid"]),
        #
        'FltWriteFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InitiatingInstance", "FileObject", "ByteOffset", "Length", "Buffer", "Flags", "BytesWritten", "CallbackRoutine", "CallbackContext"]),
        #
        'FltWriteFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InitiatingInstance", "FileObject", "ByteOffset", "Length", "Buffer", "Flags", "BytesWritten", "CallbackRoutine", "CallbackContext", "Key", "Mdl"]),
        #
        'FltFastIoMdlRead': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["InitiatingInstance", "FileObject", "FileOffset", "Length", "LockKey", "MdlChain", "IoStatus"]),
        #
        'FltFastIoMdlReadComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["InitiatingInstance", "FileObject", "MdlChain"]),
        #
        'FltFastIoPrepareMdlWrite': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["InitiatingInstance", "FileObject", "FileOffset", "Length", "LockKey", "MdlChain", "IoStatus"]),
        #
        'FltFastIoMdlWriteComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["InitiatingInstance", "FileObject", "FileOffset", "MdlChain"]),
        #
        'FltQueryInformationByName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypePointer(SimTypeRef("IO_DRIVER_CREATE_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Instance", "ObjectAttributes", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass", "DriverContext"]),
        #
        'FltQueryInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "FileInformation", "Length", "FileInformationClass", "LengthReturned"]),
        #
        'FltSetInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "FileInformation", "Length", "FileInformationClass"]),
        #
        'FltQueryDirectoryFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "FileInformation", "Length", "FileInformationClass", "ReturnSingleEntry", "FileName", "RestartScan", "LengthReturned"]),
        #
        'FltQueryDirectoryFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "FileInformation", "Length", "FileInformationClass", "QueryFlags", "FileName", "LengthReturned"]),
        #
        'FltQueryQuotaInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "IoStatusBlock", "Buffer", "Length", "ReturnSingleEntry", "SidList", "SidListLength", "StartSid", "RestartScan", "LengthReturned"]),
        #
        'FltSetQuotaInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "Buffer", "Length"]),
        #
        'FltQueryEaFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "ReturnedEaData", "Length", "ReturnSingleEntry", "EaList", "EaListLength", "EaIndex", "RestartScan", "LengthReturned"]),
        #
        'FltSetEaFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "EaBuffer", "Length"]),
        #
        'FltQueryVolumeInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FS_INFORMATION_CLASS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "FsInformation", "Length", "FsInformationClass", "LengthReturned"]),
        #
        'FltQuerySecurityObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "SecurityInformation", "SecurityDescriptor", "Length", "LengthNeeded"]),
        #
        'FltSetSecurityObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "SecurityInformation", "SecurityDescriptor"]),
        #
        'FltFlushBuffers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject"]),
        #
        'FltFlushBuffers2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "FlushType", "CallbackData"]),
        #
        'FltFsControlFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "FsControlCode", "InputBuffer", "InputBufferLength", "OutputBuffer", "OutputBufferLength", "LengthReturned"]),
        #
        'FltDeviceIoControlFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "IoControlCode", "InputBuffer", "InputBufferLength", "OutputBuffer", "OutputBufferLength", "LengthReturned"]),
        #
        'FltReissueSynchronousIo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["InitiatingInstance", "CallbackData"]),
        #
        'FltClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle"]),
        #
        'FltCancelFileOpen': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Instance", "FileObject"]),
        #
        'FltCreateSystemVolumeInformationFolder': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance"]),
        #
        'FltSupportsFileContextsEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "Instance"]),
        #
        'FltSupportsFileContexts': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject"]),
        #
        'FltSupportsStreamContexts': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject"]),
        #
        'FltSupportsStreamHandleContexts': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject"]),
        #
        'FltAllocateContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "ContextType", "ContextSize", "PoolType", "ReturnedContext"]),
        #
        'FltGetContexts': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_RELATED_OBJECTS", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("FLT_RELATED_CONTEXTS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FltObjects", "DesiredContexts", "Contexts"]),
        #
        'FltReleaseContexts': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_RELATED_CONTEXTS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Contexts"]),
        #
        'FltGetContextsEx': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_RELATED_OBJECTS", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_RELATED_CONTEXTS_EX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FltObjects", "DesiredContexts", "ContextsSize", "Contexts"]),
        #
        'FltReleaseContextsEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_RELATED_CONTEXTS_EX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ContextsSize", "Contexts"]),
        #
        'FltSetVolumeContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="FLT_SET_CONTEXT_OPERATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Volume", "Operation", "NewContext", "OldContext"]),
        #
        'FltSetInstanceContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="FLT_SET_CONTEXT_OPERATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Operation", "NewContext", "OldContext"]),
        #
        'FltSetFileContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="FLT_SET_CONTEXT_OPERATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "Operation", "NewContext", "OldContext"]),
        #
        'FltSetStreamContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="FLT_SET_CONTEXT_OPERATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "Operation", "NewContext", "OldContext"]),
        #
        'FltSetStreamHandleContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="FLT_SET_CONTEXT_OPERATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "Operation", "NewContext", "OldContext"]),
        #
        'FltSetTransactionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="FLT_SET_CONTEXT_OPERATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Transaction", "Operation", "NewContext", "OldContext"]),
        #
        'FltDeleteContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context"]),
        #
        'FltDeleteVolumeContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Volume", "OldContext"]),
        #
        'FltDeleteInstanceContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "OldContext"]),
        #
        'FltDeleteFileContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "OldContext"]),
        #
        'FltDeleteStreamContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "OldContext"]),
        #
        'FltDeleteStreamHandleContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "OldContext"]),
        #
        'FltDeleteTransactionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Transaction", "OldContext"]),
        #
        'FltGetVolumeContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Volume", "Context"]),
        #
        'FltGetInstanceContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Context"]),
        #
        'FltGetFileContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "Context"]),
        #
        'FltGetStreamContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "Context"]),
        #
        'FltGetStreamHandleContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "Context"]),
        #
        'FltGetTransactionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Transaction", "Context"]),
        #
        'FltGetSectionContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "FileObject", "Context"]),
        #
        'FltReferenceContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context"]),
        #
        'FltReleaseContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context"]),
        #
        'FltGetFilterFromName': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FilterName", "RetFilter"]),
        #
        'FltGetVolumeFromName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "VolumeName", "RetVolume"]),
        #
        'FltGetVolumeInstanceFromName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Volume", "InstanceName", "RetInstance"]),
        #
        'FltGetVolumeFromInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "RetVolume"]),
        #
        'FltGetFilterFromInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "RetFilter"]),
        #
        'FltGetVolumeFromFileObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "FileObject", "RetVolume"]),
        #
        'FltGetVolumeFromDeviceObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "DeviceObject", "RetVolume"]),
        #
        'FltIsFltMgrVolumeDeviceObject': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["DeviceObject"]),
        #
        'FltGetDeviceObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Volume", "DeviceObject"]),
        #
        'FltGetDiskDeviceObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Volume", "DiskDeviceObject"]),
        #
        'FltGetLowerInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CurrentInstance", "LowerInstance"]),
        #
        'FltGetUpperInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CurrentInstance", "UpperInstance"]),
        #
        'FltGetTopInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Volume", "Instance"]),
        #
        'FltGetBottomInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Volume", "Instance"]),
        #
        'FltCompareInstanceAltitudes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance1", "Instance2"]),
        #
        'FltGetFilterInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="FILTER_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "InformationClass", "Buffer", "BufferSize", "BytesReturned"]),
        #
        'FltGetInstanceInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="INSTANCE_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "InformationClass", "Buffer", "BufferSize", "BytesReturned"]),
        #
        'FltGetVolumeInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="FILTER_VOLUME_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Volume", "InformationClass", "Buffer", "BufferSize", "BytesReturned"]),
        #
        'FltGetVolumeProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_VOLUME_PROPERTIES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Volume", "VolumeProperties", "VolumePropertiesLength", "LengthReturned"]),
        #
        'FltIsVolumeWritable': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FltObject", "IsWritable"]),
        #
        'FltGetFileSystemType': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="FLT_FILESYSTEM_TYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FltObject", "FileSystemType"]),
        #
        'FltIsVolumeSnapshot': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FltObject", "IsSnapshotVolume"]),
        #
        'FltGetVolumeGuidName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Volume", "VolumeGuidName", "BufferSizeNeeded"]),
        #
        'FltQueryVolumeInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FS_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Iosb", "FsInformation", "Length", "FsInformationClass"]),
        #
        'FltSetVolumeInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FS_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Iosb", "FsInformation", "Length", "FsInformationClass"]),
        #
        'FltEnumerateFilters': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FilterList", "FilterListSize", "NumberFiltersReturned"]),
        #
        'FltEnumerateVolumes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "VolumeList", "VolumeListSize", "NumberVolumesReturned"]),
        #
        'FltEnumerateInstances': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Volume", "Filter", "InstanceList", "InstanceListSize", "NumberInstancesReturned"]),
        #
        'FltEnumerateFilterInformation': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILTER_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Index", "InformationClass", "Buffer", "BufferSize", "BytesReturned"]),
        #
        'FltEnumerateInstanceInformationByFilter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="INSTANCE_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Index", "InformationClass", "Buffer", "BufferSize", "BytesReturned"]),
        #
        'FltEnumerateInstanceInformationByVolume': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="INSTANCE_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Volume", "Index", "InformationClass", "Buffer", "BufferSize", "BytesReturned"]),
        #
        'FltEnumerateInstanceInformationByVolumeName': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="INSTANCE_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeName", "Index", "InformationClass", "Buffer", "BufferSize", "BytesReturned"]),
        #
        'FltEnumerateInstanceInformationByDeviceObject': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="INSTANCE_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "Index", "InformationClass", "Buffer", "BufferSize", "BytesReturned"]),
        #
        'FltEnumerateVolumeInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILTER_VOLUME_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Index", "InformationClass", "Buffer", "BufferSize", "BytesReturned"]),
        #
        'FltObjectReference': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FltObject"]),
        #
        'FltObjectDereference': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["FltObject"]),
        #
        'FltCreateCommunicationPort': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ClientPort", "ServerPortCookie", "ConnectionContext", "SizeOfContext", "ConnectionPortCookie"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ConnectionCookie"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PortCookie", "InputBuffer", "InputBufferLength", "OutputBuffer", "OutputBufferLength", "ReturnOutputBufferLength"]), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "ServerPort", "ObjectAttributes", "ServerPortCookie", "ConnectNotifyCallback", "DisconnectNotifyCallback", "MessageNotifyCallback", "MaxConnections"]),
        #
        'FltCloseCommunicationPort': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["ServerPort"]),
        #
        'FltCloseClientPort': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Filter", "ClientPort"]),
        #
        'FltSendMessage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "ClientPort", "SenderBuffer", "SenderBufferLength", "ReplyBuffer", "ReplyLength", "Timeout"]),
        #
        'FltBuildDefaultSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityDescriptor", "DesiredAccess"]),
        #
        'FltFreeSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["SecurityDescriptor"]),
        #
        'FltCancelIo': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["CallbackData"]),
        #
        'FltSetCancelCompletion': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackData", "CanceledCallback"]),
        #
        'FltClearCancelCompletion': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackData"]),
        #
        'FltIsIoCanceled': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["CallbackData"]),
        #
        'FltAllocateDeferredIoWorkItem': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'FltFreeDeferredIoWorkItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["FltWorkItem"]),
        #
        'FltAllocateGenericWorkItem': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'FltFreeGenericWorkItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["FltWorkItem"]),
        #
        'FltQueueDeferredIoWorkItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["FltWorkItem", "CallbackData", "Context"]), offset=0), SimTypeInt(signed=False, label="WORK_QUEUE_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FltWorkItem", "Data", "WorkerRoutine", "QueueType", "Context"]),
        #
        'FltQueueGenericWorkItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["FltWorkItem", "FltObject", "Context"]), offset=0), SimTypeInt(signed=False, label="WORK_QUEUE_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FltWorkItem", "FltObject", "WorkerRoutine", "QueueType", "Context"]),
        #
        'FltLockUserBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackData"]),
        #
        'FltDecodeParameters': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="LOCK_OPERATION"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackData", "MdlAddressPointer", "Buffer", "Length", "DesiredAccess"]),
        #
        'FltGetSwappedBufferMdlAddress': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), arg_names=["CallbackData"]),
        #
        'FltRetainSwappedBufferMdlAddress': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData"]),
        #
        'FltGetNewSystemBufferAddress': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["CallbackData"]),
        #
        'FltCbdqInitialize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA_QUEUE", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA_QUEUE", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Cbdq", "Cbd", "InsertContext"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA_QUEUE", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Cbdq", "Cbd"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA_QUEUE", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), arg_names=["Cbdq", "Cbd", "PeekContext"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA_QUEUE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Cbdq", "Irql"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA_QUEUE", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["Cbdq", "Irql"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA_QUEUE", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Cbdq", "Cbd"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Cbdq", "CbdqInsertIo", "CbdqRemoveIo", "CbdqPeekNextIo", "CbdqAcquire", "CbdqRelease", "CbdqCompleteCanceledIo"]),
        #
        'FltCbdqEnable': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA_QUEUE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Cbdq"]),
        #
        'FltCbdqDisable': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA_QUEUE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Cbdq"]),
        #
        'FltCbdqInsertIo': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA_QUEUE", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_CSQ_IRP_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Cbdq", "Cbd", "Context", "InsertContext"]),
        #
        'FltCbdqRemoveIo': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA_QUEUE", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_CSQ_IRP_CONTEXT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), arg_names=["Cbdq", "Context"]),
        #
        'FltCbdqRemoveNextIo': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA_QUEUE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), arg_names=["Cbdq", "PeekContext"]),
        #
        'FltInitializeOplock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Oplock"]),
        #
        'FltUninitializeOplock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Oplock"]),
        #
        'FltOplockFsctrl': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="FLT_PREOP_CALLBACK_STATUS"), arg_names=["Oplock", "CallbackData", "OpenCount"]),
        #
        'FltCheckOplock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0)], SimTypeInt(signed=False, label="FLT_PREOP_CALLBACK_STATUS"), arg_names=["Oplock", "CallbackData", "Context", "WaitCompletionRoutine", "PrePostCallbackDataRoutine"]),
        #
        'FltOplockIsFastIoPossible': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["Oplock"]),
        #
        'FltCurrentBatchOplock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["Oplock"]),
        #
        'FltCheckOplockEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0)], SimTypeInt(signed=False, label="FLT_PREOP_CALLBACK_STATUS"), arg_names=["Oplock", "CallbackData", "Flags", "Context", "WaitCompletionRoutine", "PrePostCallbackDataRoutine"]),
        #
        'FltCurrentOplock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["Oplock"]),
        #
        'FltCurrentOplockH': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["Oplock"]),
        #
        'FltOplockBreakH': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0)], SimTypeInt(signed=False, label="FLT_PREOP_CALLBACK_STATUS"), arg_names=["Oplock", "CallbackData", "Flags", "Context", "WaitCompletionRoutine", "PrePostCallbackDataRoutine"]),
        #
        'FltOplockBreakToNone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0)], SimTypeInt(signed=False, label="FLT_PREOP_CALLBACK_STATUS"), arg_names=["Oplock", "CallbackData", "Context", "WaitCompletionRoutine", "PrePostCallbackDataRoutine"]),
        #
        'FltOplockBreakToNoneEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackData", "Context"]), offset=0)], SimTypeInt(signed=False, label="FLT_PREOP_CALLBACK_STATUS"), arg_names=["Oplock", "CallbackData", "Flags", "Context", "WaitCompletionRoutine", "PrePostCallbackDataRoutine"]),
        #
        'FltOplockIsSharedRequest': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["CallbackData"]),
        #
        'FltOplockFsctrlEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="FLT_PREOP_CALLBACK_STATUS"), arg_names=["Oplock", "CallbackData", "OpenCount", "Flags"]),
        #
        'FltOplockKeysEqual': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Fo1", "Fo2"]),
        #
        'FltInitializeFileLock': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileLock"]),
        #
        'FltUninitializeFileLock': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileLock"]),
        #
        'FltAllocateFileLock': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Context", "CallbackData"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("FILE_LOCK_INFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "FileLockInfo"]), offset=0)], SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), arg_names=["CompleteLockCallbackDataRoutine", "UnlockRoutine"]),
        #
        'FltFreeFileLock': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileLock"]),
        #
        'FltProcessFileLock': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="FLT_PREOP_CALLBACK_STATUS"), arg_names=["FileLock", "CallbackData", "Context"]),
        #
        'FltCheckLockForReadAccess': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileLock", "CallbackData"]),
        #
        'FltCheckLockForWriteAccess': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileLock", "CallbackData"]),
        #
        'FltAcquireResourceExclusive': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Resource"]),
        #
        'FltAcquireResourceShared': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Resource"]),
        #
        'FltReleaseResource': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Resource"]),
        #
        'FltInitializePushLock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["PushLock"]),
        #
        'FltDeletePushLock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["PushLock"]),
        #
        'FltAcquirePushLockExclusive': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["PushLock"]),
        #
        'FltAcquirePushLockShared': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["PushLock"]),
        #
        'FltReleasePushLock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["PushLock"]),
        #
        'FltAcquirePushLockExclusiveEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["PushLock", "Flags"]),
        #
        'FltAcquirePushLockSharedEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["PushLock", "Flags"]),
        #
        'FltReleasePushLockEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["PushLock", "Flags"]),
        #
        'FltCancellableWaitForSingleObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "Timeout", "CallbackData"]),
        #
        'FltCancellableWaitForMultipleObjects': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="WAIT_TYPE"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("KWAIT_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Count", "ObjectArray", "WaitType", "Timeout", "WaitBlockArray", "CallbackData"]),
        #
        'FltIsOperationSynchronous': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["CallbackData"]),
        #
        'FltIs32bitProcess': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["CallbackData"]),
        #
        'FltGetRequestorProcess': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["CallbackData"]),
        #
        'FltGetRequestorProcessId': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["CallbackData"]),
        #
        'FltGetRequestorProcessIdEx': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["CallbackData"]),
        #
        'FltNotifyFilterChangeDirectory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LIST_ENTRY", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["NotifyContext", "TargetContext", "SubjectContext"]), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["NotifyContext", "FilterContext"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["NotifySync", "NotifyList", "FsContext", "FullDirectoryName", "WatchTree", "IgnoreBuffer", "CompletionFilter", "NotifyCallbackData", "TraverseCallback", "SubjectContext", "FilterCallback"]),
        #
        'FltGetRequestorSessionId': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackData", "SessionId"]),
        #
        'FltAdjustDeviceStackSizeForIoRedirection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceInstance", "TargetInstance", "SourceDeviceStackSizeModified"]),
        #
        'FltIsIoRedirectionAllowed': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceInstance", "TargetInstance", "RedirectionAllowed"]),
        #
        'FltIsIoRedirectionAllowedForOperation': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Data", "TargetInstance", "RedirectionAllowedThisIo", "RedirectionAllowedAllIo"]),
        #
        'FltVetoBypassIo': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_RELATED_OBJECTS", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackData", "FltObjects", "OperationStatus", "FailureReason"]),
        #
        'FltEnlistInTransaction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Transaction", "TransactionContext", "NotificationMask"]),
        #
        'FltRollbackEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Transaction", "TransactionContext"]),
        #
        'FltPrePrepareComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Transaction", "TransactionContext"]),
        #
        'FltPrepareComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Transaction", "TransactionContext"]),
        #
        'FltCommitComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Transaction", "TransactionContext"]),
        #
        'FltCommitFinalizeComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Transaction", "TransactionContext"]),
        #
        'FltRollbackComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Transaction", "TransactionContext"]),
        #
        'FltAllocateExtraCreateParameterList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Flags", "EcpList"]),
        #
        'FltAllocateExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeBottom(label="Void"), arg_names=["EcpContext", "EcpType"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "EcpType", "SizeOfContext", "Flags", "CleanupCallback", "PoolTag", "EcpContext"]),
        #
        'FltInitExtraCreateParameterLookasideList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Filter", "Lookaside", "Flags", "Size", "Tag"]),
        #
        'FltDeleteExtraCreateParameterLookasideList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Filter", "Lookaside", "Flags"]),
        #
        'FltAllocateExtraCreateParameterFromLookasideList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeBottom(label="Void"), arg_names=["EcpContext", "EcpType"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "EcpType", "SizeOfContext", "Flags", "CleanupCallback", "LookasideList", "EcpContext"]),
        #
        'FltInsertExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "EcpList", "EcpContext"]),
        #
        'FltFindExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "EcpList", "EcpType", "EcpContext", "EcpContextSize"]),
        #
        'FltRemoveExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "EcpList", "EcpType", "EcpContext", "EcpContextSize"]),
        #
        'FltFreeExtraCreateParameterList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Filter", "EcpList"]),
        #
        'FltFreeExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Filter", "EcpContext"]),
        #
        'FltGetEcpListFromCallbackData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "CallbackData", "EcpList"]),
        #
        'FltSetEcpListIntoCallbackData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "CallbackData", "EcpList"]),
        #
        'FltGetNextExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "EcpList", "CurrentEcpContext", "NextEcpType", "NextEcpContext", "NextEcpContextSize"]),
        #
        'FltAcknowledgeEcp': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Filter", "EcpContext"]),
        #
        'FltIsEcpAcknowledged': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Filter", "EcpContext"]),
        #
        'FltIsEcpFromUserMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Filter", "EcpContext"]),
        #
        'FltPrepareToReuseEcp': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Filter", "EcpContext"]),
        #
        'FltAddOpenReparseEntry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("OPEN_REPARSE_LIST_ENTRY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Data", "OpenReparseEntry"]),
        #
        'FltRemoveOpenReparseEntry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("OPEN_REPARSE_LIST_ENTRY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Filter", "Data", "OpenReparseEntry"]),
        #
        'FltCopyOpenReparseList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Data", "EcpList"]),
        #
        'FltFreeOpenReparseList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Filter", "EcpList"]),
        #
        'FltRequestFileInfoOnCreateCompletion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Data", "InfoClassFlags"]),
        #
        'FltRetrieveFileInfoOnCreateCompletion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Filter", "Data", "InfoClass", "Size"]),
        #
        'FltRetrieveFileInfoOnCreateCompletionEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Filter", "Data", "InfoClass", "RetInfoSize", "RetInfoBuffer"]),
        #
        'FltRetrieveIoPriorityInfo': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_PRIORITY_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Data", "FileObject", "Thread", "PriorityInfo"]),
        #
        'FltApplyPriorityInfoThread': SimTypeFunction([SimTypePointer(SimTypeRef("IO_PRIORITY_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_PRIORITY_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InputPriorityInfo", "OutputPriorityInfo", "Thread"]),
        #
        'FltGetIoPriorityHint': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="IO_PRIORITY_HINT"), arg_names=["Data"]),
        #
        'FltGetIoPriorityHintFromCallbackData': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="IO_PRIORITY_HINT"), arg_names=["Data"]),
        #
        'FltSetIoPriorityHintIntoCallbackData': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="IO_PRIORITY_HINT")], SimTypeInt(signed=True, label="Int32"), arg_names=["Data", "PriorityHint"]),
        #
        'FltGetIoPriorityHintFromFileObject': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=False, label="IO_PRIORITY_HINT"), arg_names=["FileObject"]),
        #
        'FltSetIoPriorityHintIntoFileObject': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="IO_PRIORITY_HINT")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "PriorityHint"]),
        #
        'FltGetIoPriorityHintFromThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="IO_PRIORITY_HINT"), arg_names=["Thread"]),
        #
        'FltSetIoPriorityHintIntoThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="IO_PRIORITY_HINT")], SimTypeInt(signed=True, label="Int32"), arg_names=["Thread", "PriorityHint"]),
        #
        'FltGetActivityIdCallbackData': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackData", "Guid"]),
        #
        'FltSetActivityIdCallbackData': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackData", "Guid"]),
        #
        'FltPropagateActivityIdToThread': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Guid"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackData", "PropagateId", "OriginalId"]),
        #
        'FltGetFsZeroingOffset': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Data", "ZeroingOffset"]),
        #
        'FltSetFsZeroingOffsetRequired': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Data"]),
        #
        'FltSetFsZeroingOffset': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Data", "ZeroingOffset"]),
        #
        'FltGetIoAttributionHandleFromCallbackData': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Data"]),
        #
        'FltPropagateIrpExtension': SimTypeFunction([SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("FLT_CALLBACK_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceData", "TargetData", "Flags"]),
        #
        'FltGetIrpName': SimTypeFunction([SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["IrpMajorCode"]),
    }

lib.set_prototypes(prototypes)
