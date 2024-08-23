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
lib.set_library_names("msdelta.dll")
prototypes = \
    {
        #
        'GetDeltaInfoB': SimTypeFunction([SimTypeRef("DELTA_INPUT", SimStruct), SimTypePointer(SimTypeRef("DELTA_HEADER_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Delta", "lpHeaderInfo"]),
        #
        'GetDeltaInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("DELTA_HEADER_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDeltaName", "lpHeaderInfo"]),
        #
        'GetDeltaInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DELTA_HEADER_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDeltaName", "lpHeaderInfo"]),
        #
        'ApplyDeltaGetReverseB': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeRef("DELTA_INPUT", SimStruct), SimTypeRef("DELTA_INPUT", SimStruct), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("DELTA_OUTPUT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DELTA_OUTPUT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ApplyFlags", "Source", "Delta", "lpReverseFileTime", "lpTarget", "lpTargetReverse"]),
        #
        'ApplyDeltaB': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeRef("DELTA_INPUT", SimStruct), SimTypeRef("DELTA_INPUT", SimStruct), SimTypePointer(SimTypeRef("DELTA_OUTPUT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ApplyFlags", "Source", "Delta", "lpTarget"]),
        #
        'ApplyDeltaProvidedB': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeRef("DELTA_INPUT", SimStruct), SimTypeRef("DELTA_INPUT", SimStruct), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ApplyFlags", "Source", "Delta", "lpTarget", "uTargetSize"]),
        #
        'ApplyDeltaA': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ApplyFlags", "lpSourceName", "lpDeltaName", "lpTargetName"]),
        #
        'ApplyDeltaW': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ApplyFlags", "lpSourceName", "lpDeltaName", "lpTargetName"]),
        #
        'CreateDeltaB': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeRef("DELTA_INPUT", SimStruct), SimTypeRef("DELTA_INPUT", SimStruct), SimTypeRef("DELTA_INPUT", SimStruct), SimTypeRef("DELTA_INPUT", SimStruct), SimTypeRef("DELTA_INPUT", SimStruct), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypeInt(signed=False, label="ALG_ID"), SimTypePointer(SimTypeRef("DELTA_OUTPUT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileTypeSet", "SetFlags", "ResetFlags", "Source", "Target", "SourceOptions", "TargetOptions", "GlobalOptions", "lpTargetFileTime", "HashAlgId", "lpDelta"]),
        #
        'CreateDeltaA': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeRef("DELTA_INPUT", SimStruct), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypeInt(signed=False, label="ALG_ID"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileTypeSet", "SetFlags", "ResetFlags", "lpSourceName", "lpTargetName", "lpSourceOptionsName", "lpTargetOptionsName", "GlobalOptions", "lpTargetFileTime", "HashAlgId", "lpDeltaName"]),
        #
        'CreateDeltaW': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("DELTA_INPUT", SimStruct), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypeInt(signed=False, label="ALG_ID"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileTypeSet", "SetFlags", "ResetFlags", "lpSourceName", "lpTargetName", "lpSourceOptionsName", "lpTargetOptionsName", "GlobalOptions", "lpTargetFileTime", "HashAlgId", "lpDeltaName"]),
        #
        'GetDeltaSignatureB': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="ALG_ID"), SimTypeRef("DELTA_INPUT", SimStruct), SimTypePointer(SimTypeRef("DELTA_HASH", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileTypeSet", "HashAlgId", "Source", "lpHash"]),
        #
        'GetDeltaSignatureA': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="ALG_ID"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("DELTA_HASH", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileTypeSet", "HashAlgId", "lpSourceName", "lpHash"]),
        #
        'GetDeltaSignatureW': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="ALG_ID"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DELTA_HASH", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileTypeSet", "HashAlgId", "lpSourceName", "lpHash"]),
        #
        'DeltaNormalizeProvidedB': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeRef("DELTA_INPUT", SimStruct), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileTypeSet", "NormalizeFlags", "NormalizeOptions", "lpSource", "uSourceSize"]),
        #
        'DeltaFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMemory"]),
    }

lib.set_prototypes(prototypes)
