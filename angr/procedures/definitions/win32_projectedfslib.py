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
lib.set_library_names("projectedfslib.dll")
prototypes = \
    {
        #
        'PrjStartVirtualizing': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PRJ_CALLBACKS", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("PRJ_STARTVIRTUALIZING_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["virtualizationRootPath", "callbacks", "instanceContext", "options", "namespaceVirtualizationContext"]),
        #
        'PrjStopVirtualizing': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["namespaceVirtualizationContext"]),
        #
        'PrjClearNegativePathCache': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "totalEntryNumber"]),
        #
        'PrjGetVirtualizationInstanceInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PRJ_VIRTUALIZATION_INSTANCE_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "virtualizationInstanceInfo"]),
        #
        'PrjMarkDirectoryAsPlaceholder': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PRJ_PLACEHOLDER_VERSION_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rootPathName", "targetPathName", "versionInfo", "virtualizationInstanceID"]),
        #
        'PrjWritePlaceholderInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PRJ_PLACEHOLDER_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "destinationFileName", "placeholderInfo", "placeholderInfoSize"]),
        #
        'PrjWritePlaceholderInfo2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PRJ_PLACEHOLDER_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PRJ_EXTENDED_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "destinationFileName", "placeholderInfo", "placeholderInfoSize", "ExtendedInfo"]),
        #
        'PrjUpdateFileIfNeeded': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PRJ_PLACEHOLDER_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="PRJ_UPDATE_TYPES"), SimTypePointer(SimTypeInt(signed=False, label="PRJ_UPDATE_FAILURE_CAUSES"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "destinationFileName", "placeholderInfo", "placeholderInfoSize", "updateFlags", "failureReason"]),
        #
        'PrjDeleteFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="PRJ_UPDATE_TYPES"), SimTypePointer(SimTypeInt(signed=False, label="PRJ_UPDATE_FAILURE_CAUSES"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "destinationFileName", "updateFlags", "failureReason"]),
        #
        'PrjWriteFileData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "dataStreamId", "buffer", "byteOffset", "length"]),
        #
        'PrjGetOnDiskFileState': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="PRJ_FILE_STATE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["destinationFileName", "fileState"]),
        #
        'PrjAllocateAlignedBuffer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["namespaceVirtualizationContext", "size"]),
        #
        'PrjFreeAlignedBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["buffer"]),
        #
        'PrjCompleteCommand': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("PRJ_COMPLETE_COMMAND_EXTENDED_PARAMETERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "commandId", "completionResult", "extendedParameters"]),
        #
        'PrjFillDirEntryBuffer': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PRJ_FILE_BASIC_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fileName", "fileBasicInfo", "dirEntryBufferHandle"]),
        #
        'PrjFillDirEntryBuffer2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PRJ_FILE_BASIC_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("PRJ_EXTENDED_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dirEntryBufferHandle", "fileName", "fileBasicInfo", "extendedInfo"]),
        #
        'PrjFileNameMatch': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeChar(label="Byte"), arg_names=["fileNameToCheck", "pattern"]),
        #
        'PrjFileNameCompare': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fileName1", "fileName2"]),
        #
        'PrjDoesNameContainWildCards': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeChar(label="Byte"), arg_names=["fileName"]),
    }

lib.set_prototypes(prototypes)
