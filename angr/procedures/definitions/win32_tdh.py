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
lib.set_library_names("tdh.dll")
prototypes = \
    {
        #
        'TdhCreatePayloadFilter': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("EVENT_DESCRIPTOR", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PAYLOAD_FILTER_PREDICATE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProviderGuid", "EventDescriptor", "EventMatchANY", "PayloadPredicateCount", "PayloadPredicates", "PayloadFilter"]),
        #
        'TdhDeletePayloadFilter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PayloadFilter"]),
        #
        'TdhAggregatePayloadFilters': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("EVENT_FILTER_DESCRIPTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PayloadFilterCount", "PayloadFilterPtrs", "EventMatchALLFlags", "EventFilterDescriptor"]),
        #
        'TdhCleanupPayloadEventFilterDescriptor': SimTypeFunction([SimTypePointer(SimTypeRef("EVENT_FILTER_DESCRIPTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["EventFilterDescriptor"]),
        #
        'TdhGetEventInformation': SimTypeFunction([SimTypePointer(SimTypeRef("EVENT_RECORD", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TDH_CONTEXT", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("TRACE_EVENT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Event", "TdhContextCount", "TdhContext", "Buffer", "BufferSize"]),
        #
        'TdhGetEventMapInformation': SimTypeFunction([SimTypePointer(SimTypeRef("EVENT_RECORD", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("EVENT_MAP_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pEvent", "pMapName", "pBuffer", "pBufferSize"]),
        #
        'TdhGetPropertySize': SimTypeFunction([SimTypePointer(SimTypeRef("EVENT_RECORD", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TDH_CONTEXT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPERTY_DATA_DESCRIPTOR", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pEvent", "TdhContextCount", "pTdhContext", "PropertyDataCount", "pPropertyData", "pPropertySize"]),
        #
        'TdhGetProperty': SimTypeFunction([SimTypePointer(SimTypeRef("EVENT_RECORD", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TDH_CONTEXT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPERTY_DATA_DESCRIPTOR", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pEvent", "TdhContextCount", "pTdhContext", "PropertyDataCount", "pPropertyData", "BufferSize", "pBuffer"]),
        #
        'TdhEnumerateProviders': SimTypeFunction([SimTypePointer(SimTypeRef("PROVIDER_ENUMERATION_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pBuffer", "pBufferSize"]),
        #
        'TdhEnumerateProvidersForDecodingSource': SimTypeFunction([SimTypeInt(signed=False, label="DECODING_SOURCE"), SimTypePointer(SimTypeRef("PROVIDER_ENUMERATION_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["filter", "buffer", "bufferSize", "bufferRequired"]),
        #
        'TdhQueryProviderFieldInformation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="EVENT_FIELD_TYPE"), SimTypePointer(SimTypeRef("PROVIDER_FIELD_INFOARRAY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pGuid", "EventFieldValue", "EventFieldType", "pBuffer", "pBufferSize"]),
        #
        'TdhEnumerateProviderFieldInformation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="EVENT_FIELD_TYPE"), SimTypePointer(SimTypeRef("PROVIDER_FIELD_INFOARRAY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pGuid", "EventFieldType", "pBuffer", "pBufferSize"]),
        #
        'TdhEnumerateProviderFilters': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TDH_CONTEXT", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PROVIDER_FILTER_INFO", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Guid", "TdhContextCount", "TdhContext", "FilterCount", "Buffer", "BufferSize"]),
        #
        'TdhLoadManifest': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Manifest"]),
        #
        'TdhLoadManifestFromMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pData", "cbData"]),
        #
        'TdhUnloadManifest': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Manifest"]),
        #
        'TdhUnloadManifestFromMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pData", "cbData"]),
        #
        'TdhFormatProperty': SimTypeFunction([SimTypePointer(SimTypeRef("TRACE_EVENT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("EVENT_MAP_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["EventInfo", "MapInfo", "PointerSize", "PropertyInType", "PropertyOutType", "PropertyLength", "UserDataLength", "UserData", "BufferSize", "Buffer", "UserDataConsumed"]),
        #
        'TdhOpenDecodingHandle': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Handle"]),
        #
        'TdhSetDecodingParameter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TDH_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Handle", "TdhContext"]),
        #
        'TdhGetDecodingParameter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TDH_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Handle", "TdhContext"]),
        #
        'TdhGetWppProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("EVENT_RECORD", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Handle", "EventRecord", "PropertyName", "BufferSize", "Buffer"]),
        #
        'TdhGetWppMessage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("EVENT_RECORD", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Handle", "EventRecord", "BufferSize", "Buffer"]),
        #
        'TdhCloseDecodingHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Handle"]),
        #
        'TdhLoadManifestFromBinary': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BinaryPath"]),
        #
        'TdhEnumerateManifestProviderEvents': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("PROVIDER_EVENT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProviderGuid", "Buffer", "BufferSize"]),
        #
        'TdhGetManifestEventInformation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("EVENT_DESCRIPTOR", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRACE_EVENT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProviderGuid", "EventDescriptor", "Buffer", "BufferSize"]),
    }

lib.set_prototypes(prototypes)
