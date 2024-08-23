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
lib.set_library_names("sensorsutilsv2.dll")
prototypes = \
    {
        #
        'GetPerformanceTime': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TimeMs"]),
        #
        'InitPropVariantFromFloat': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltVal", "ppropvar"]),
        #
        'PropKeyFindKeyGetPropVariant': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "TypeCheck", "pValue"]),
        #
        'PropKeyFindKeySetPropVariant': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "TypeCheck", "pValue"]),
        #
        'PropKeyFindKeyGetFileTime': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "pRetValue"]),
        #
        'PropKeyFindKeyGetGuid': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "pRetValue"]),
        #
        'PropKeyFindKeyGetBool': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "pRetValue"]),
        #
        'PropKeyFindKeyGetUlong': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "pRetValue"]),
        #
        'PropKeyFindKeyGetUshort': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "pRetValue"]),
        #
        'PropKeyFindKeyGetFloat': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "pRetValue"]),
        #
        'PropKeyFindKeyGetDouble': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "pRetValue"]),
        #
        'PropKeyFindKeyGetInt32': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "pRetValue"]),
        #
        'PropKeyFindKeyGetInt64': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "pRetValue"]),
        #
        'PropKeyFindKeyGetNthUlong': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "Occurrence", "pRetValue"]),
        #
        'PropKeyFindKeyGetNthUshort': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "Occurrence", "pRetValue"]),
        #
        'PropKeyFindKeyGetNthInt64': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pList", "pKey", "Occurrence", "pRetValue"]),
        #
        'IsKeyPresentInPropertyList': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_PROPERTY_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["pList", "pKey"]),
        #
        'IsKeyPresentInCollectionList': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["pList", "pKey"]),
        #
        'IsCollectionListSame': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["ListA", "ListB"]),
        #
        'PropVariantGetInformation': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="DEVPROPTYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PropVariantValue", "PropVariantOffset", "PropVariantSize", "PropVariantPointer", "RemappedType"]),
        #
        'PropertiesListCopy': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_PROPERTY_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("SENSOR_PROPERTY_LIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Target", "Source"]),
        #
        'PropertiesListGetFillableCount': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSizeBytes"]),
        #
        'CollectionsListGetMarshalledSize': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Collection"]),
        #
        'CollectionsListCopyAndMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Target", "Source"]),
        #
        'CollectionsListMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Target"]),
        #
        'CollectionsListGetMarshalledSizeWithoutSerialization': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Collection"]),
        #
        'CollectionsListUpdateMarshalledPointer': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Collection"]),
        #
        'SerializationBufferAllocate': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SizeInBytes", "pBuffer"]),
        #
        'SerializationBufferFree': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Buffer"]),
        #
        'CollectionsListGetSerializedSize': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Collection"]),
        #
        'CollectionsListSerializeToBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceCollection", "TargetBufferSizeInBytes", "TargetBuffer"]),
        #
        'CollectionsListAllocateBufferAndSerialize': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceCollection", "pTargetBufferSizeInBytes", "pTargetBuffer"]),
        #
        'CollectionsListDeserializeFromBuffer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceBufferSizeInBytes", "SourceBuffer", "TargetCollection"]),
        #
        'SensorCollectionGetAt': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Index", "pSensorsList", "pKey", "pValue"]),
        #
        'CollectionsListGetFillableCount': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferSizeBytes"]),
        #
        'EvaluateActivityThresholds': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["newSample", "oldSample", "thresholds"]),
        #
        'CollectionsListSortSubscribedActivitiesByConfidence': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["thresholds", "pCollection"]),
        #
        'InitPropVariantFromCLSIDArray': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["members", "size", "ppropvar"]),
        #
        'IsSensorSubscribed': SimTypeFunction([SimTypePointer(SimTypeRef("SENSOR_COLLECTION_LIST", SimStruct), offset=0), SimTypeBottom(label="Guid")], SimTypeChar(label="Byte"), arg_names=["subscriptionList", "currentType"]),
        #
        'IsGUIDPresentInList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeChar(label="Byte"), arg_names=["guidArray", "arrayLength", "guidElem"]),
    }

lib.set_prototypes(prototypes)
