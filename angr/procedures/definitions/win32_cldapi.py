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
lib.set_library_names("cldapi.dll")
prototypes = \
    {
        #
        'CfGetPlatformInfo': SimTypeFunction([SimTypePointer(SimTypeRef("CF_PLATFORM_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PlatformVersion"]),
        #
        'CfRegisterSyncRoot': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CF_SYNC_REGISTRATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("CF_SYNC_POLICIES", SimStruct), offset=0), SimTypeInt(signed=False, label="CF_REGISTER_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["SyncRootPath", "Registration", "Policies", "RegisterFlags"]),
        #
        'CfUnregisterSyncRoot': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SyncRootPath"]),
        #
        'CfConnectSyncRoot': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CF_CALLBACK_REGISTRATION", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="CF_CONNECT_FLAGS"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SyncRootPath", "CallbackTable", "CallbackContext", "ConnectFlags", "ConnectionKey"]),
        #
        'CfDisconnectSyncRoot': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64")], SimTypeInt(signed=True, label="Int32"), arg_names=["ConnectionKey"]),
        #
        'CfGetTransferKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "TransferKey"]),
        #
        'CfReleaseTransferKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileHandle", "TransferKey"]),
        #
        'CfExecute': SimTypeFunction([SimTypePointer(SimTypeRef("CF_OPERATION_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("CF_OPERATION_PARAMETERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OpInfo", "OpParams"]),
        #
        'CfUpdateSyncProviderStatus': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="CF_SYNC_PROVIDER_STATUS")], SimTypeInt(signed=True, label="Int32"), arg_names=["ConnectionKey", "ProviderStatus"]),
        #
        'CfQuerySyncProviderStatus': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="CF_SYNC_PROVIDER_STATUS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ConnectionKey", "ProviderStatus"]),
        #
        'CfReportSyncStatus': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CF_SYNC_STATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SyncRootPath", "SyncStatus"]),
        #
        'CfCreatePlaceholders': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CF_PLACEHOLDER_CREATE_INFO", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="CF_CREATE_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["BaseDirectoryPath", "PlaceholderArray", "PlaceholderCount", "CreateFlags", "EntriesProcessed"]),
        #
        'CfOpenFileWithOplock': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="CF_OPEN_FILE_FLAGS"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FilePath", "Flags", "ProtectedHandle"]),
        #
        'CfReferenceProtectedHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["ProtectedHandle"]),
        #
        'CfGetWin32HandleFromProtectedHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["ProtectedHandle"]),
        #
        'CfReleaseProtectedHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["ProtectedHandle"]),
        #
        'CfCloseHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["FileHandle"]),
        #
        'CfConvertToPlaceholder': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="CF_CONVERT_FLAGS"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "FileIdentity", "FileIdentityLength", "ConvertFlags", "ConvertUsn", "Overlapped"]),
        #
        'CfUpdatePlaceholder': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CF_FS_METADATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CF_FILE_RANGE", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="CF_UPDATE_FLAGS"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "FsMetadata", "FileIdentity", "FileIdentityLength", "DehydrateRangeArray", "DehydrateRangeCount", "UpdateFlags", "UpdateUsn", "Overlapped"]),
        #
        'CfRevertPlaceholder': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CF_REVERT_FLAGS"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "RevertFlags", "Overlapped"]),
        #
        'CfHydratePlaceholder': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="CF_HYDRATE_FLAGS"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "StartingOffset", "Length", "HydrateFlags", "Overlapped"]),
        #
        'CfDehydratePlaceholder': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="CF_DEHYDRATE_FLAGS"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "StartingOffset", "Length", "DehydrateFlags", "Overlapped"]),
        #
        'CfSetPinState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CF_PIN_STATE"), SimTypeInt(signed=False, label="CF_SET_PIN_FLAGS"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "PinState", "PinFlags", "Overlapped"]),
        #
        'CfSetInSyncState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CF_IN_SYNC_STATE"), SimTypeInt(signed=False, label="CF_SET_IN_SYNC_FLAGS"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "InSyncState", "InSyncFlags", "InSyncUsn"]),
        #
        'CfSetCorrelationVector': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CORRELATION_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "CorrelationVector"]),
        #
        'CfGetCorrelationVector': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CORRELATION_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "CorrelationVector"]),
        #
        'CfGetPlaceholderStateFromAttributeTag': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="CF_PLACEHOLDER_STATE"), arg_names=["FileAttributes", "ReparseTag"]),
        #
        'CfGetPlaceholderStateFromFileInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="FILE_INFO_BY_HANDLE_CLASS")], SimTypeInt(signed=False, label="CF_PLACEHOLDER_STATE"), arg_names=["InfoBuffer", "InfoClass"]),
        #
        'CfGetPlaceholderStateFromFindData': SimTypeFunction([SimTypePointer(SimTypeRef("WIN32_FIND_DATAA", SimStruct), offset=0)], SimTypeInt(signed=False, label="CF_PLACEHOLDER_STATE"), arg_names=["FindData"]),
        #
        'CfGetPlaceholderInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CF_PLACEHOLDER_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "InfoClass", "InfoBuffer", "InfoBufferLength", "ReturnedLength"]),
        #
        'CfGetSyncRootInfoByPath': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="CF_SYNC_ROOT_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FilePath", "InfoClass", "InfoBuffer", "InfoBufferLength", "ReturnedLength"]),
        #
        'CfGetSyncRootInfoByHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CF_SYNC_ROOT_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "InfoClass", "InfoBuffer", "InfoBufferLength", "ReturnedLength"]),
        #
        'CfGetPlaceholderRangeInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CF_PLACEHOLDER_RANGE_INFO_CLASS"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "InfoClass", "StartingOffset", "Length", "InfoBuffer", "InfoBufferLength", "ReturnedLength"]),
        #
        'CfGetPlaceholderRangeInfoForHydration': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="CF_PLACEHOLDER_RANGE_INFO_CLASS"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ConnectionKey", "TransferKey", "FileId", "InfoClass", "StartingOffset", "RangeLength", "InfoBuffer", "InfoBufferSize", "InfoBufferWritten"]),
        #
        'CfReportProviderProgress': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64")], SimTypeInt(signed=True, label="Int32"), arg_names=["ConnectionKey", "TransferKey", "ProviderProgressTotal", "ProviderProgressCompleted"]),
        #
        'CfReportProviderProgress2': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ConnectionKey", "TransferKey", "RequestKey", "ProviderProgressTotal", "ProviderProgressCompleted", "TargetSessionId"]),
    }

lib.set_prototypes(prototypes)
