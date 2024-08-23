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
lib.set_library_names("mspatchc.dll")
prototypes = \
    {
        #
        'CreatePatchFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PATCH_OPTION_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OldFileName", "NewFileName", "PatchFileName", "OptionFlags", "OptionData"]),
        #
        'CreatePatchFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PATCH_OPTION_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OldFileName", "NewFileName", "PatchFileName", "OptionFlags", "OptionData"]),
        #
        'CreatePatchFileByHandles': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PATCH_OPTION_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OldFileHandle", "NewFileHandle", "PatchFileHandle", "OptionFlags", "OptionData"]),
        #
        'CreatePatchFileExA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PATCH_OLD_FILE_INFO_A", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PATCH_OPTION_DATA", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackContext", "CurrentPosition", "MaximumPosition"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OldFileCount", "OldFileInfoArray", "NewFileName", "PatchFileName", "OptionFlags", "OptionData", "ProgressCallback", "CallbackContext"]),
        #
        'CreatePatchFileExW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PATCH_OLD_FILE_INFO_W", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PATCH_OPTION_DATA", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackContext", "CurrentPosition", "MaximumPosition"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OldFileCount", "OldFileInfoArray", "NewFileName", "PatchFileName", "OptionFlags", "OptionData", "ProgressCallback", "CallbackContext"]),
        #
        'CreatePatchFileByHandlesEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PATCH_OLD_FILE_INFO_H", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PATCH_OPTION_DATA", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackContext", "CurrentPosition", "MaximumPosition"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OldFileCount", "OldFileInfoArray", "NewFileHandle", "PatchFileHandle", "OptionFlags", "OptionData", "ProgressCallback", "CallbackContext"]),
        #
        'ExtractPatchHeaderToFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PatchFileName", "PatchHeaderFileName"]),
        #
        'ExtractPatchHeaderToFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PatchFileName", "PatchHeaderFileName"]),
        #
        'ExtractPatchHeaderToFileByHandles': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PatchFileHandle", "PatchHeaderFileHandle"]),
    }

lib.set_prototypes(prototypes)
