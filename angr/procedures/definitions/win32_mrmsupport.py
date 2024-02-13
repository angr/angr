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
lib.set_library_names("mrmsupport.dll")
prototypes = \
    {
        #
        'CreateResourceIndexer': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["projectRoot", "extensionDllPath", "ppResourceIndexer"]),
        #
        'DestroyResourceIndexer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["resourceIndexer"]),
        #
        'IndexFilePath': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("IndexedResourceQualifier", SimStruct), offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["resourceIndexer", "filePath", "ppResourceUri", "pQualifierCount", "ppQualifiers"]),
        #
        'DestroyIndexedResults': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IndexedResourceQualifier", SimStruct), label="LPArray", offset=0)], SimTypeBottom(label="Void"), arg_names=["resourceUri", "qualifierCount", "qualifiers"]),
        #
        'MrmCreateResourceIndexer': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmPlatformVersion"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("MrmResourceIndexerHandle", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageFamilyName", "projectRoot", "platformVersion", "defaultQualifiers", "indexer"]),
        #
        'MrmCreateResourceIndexerFromPreviousSchemaFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmPlatformVersion"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("MrmResourceIndexerHandle", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["projectRoot", "platformVersion", "defaultQualifiers", "schemaFile", "indexer"]),
        #
        'MrmCreateResourceIndexerFromPreviousPriFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmPlatformVersion"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("MrmResourceIndexerHandle", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["projectRoot", "platformVersion", "defaultQualifiers", "priFile", "indexer"]),
        #
        'MrmCreateResourceIndexerFromPreviousSchemaData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmPlatformVersion"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MrmResourceIndexerHandle", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["projectRoot", "platformVersion", "defaultQualifiers", "schemaXmlData", "schemaXmlSize", "indexer"]),
        #
        'MrmCreateResourceIndexerFromPreviousPriData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmPlatformVersion"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MrmResourceIndexerHandle", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["projectRoot", "platformVersion", "defaultQualifiers", "priData", "priSize", "indexer"]),
        #
        'MrmCreateResourceIndexerWithFlags': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmPlatformVersion"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmIndexerFlags"), SimTypePointer(SimTypeRef("MrmResourceIndexerHandle", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageFamilyName", "projectRoot", "platformVersion", "defaultQualifiers", "flags", "indexer"]),
        #
        'MrmIndexString': SimTypeFunction([SimTypeRef("MrmResourceIndexerHandle", SimStruct), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "resourceUri", "resourceString", "qualifiers"]),
        #
        'MrmIndexEmbeddedData': SimTypeFunction([SimTypeRef("MrmResourceIndexerHandle", SimStruct), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "resourceUri", "embeddedData", "embeddedDataSize", "qualifiers"]),
        #
        'MrmIndexFile': SimTypeFunction([SimTypeRef("MrmResourceIndexerHandle", SimStruct), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "resourceUri", "filePath", "qualifiers"]),
        #
        'MrmIndexFileAutoQualifiers': SimTypeFunction([SimTypeRef("MrmResourceIndexerHandle", SimStruct), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "filePath"]),
        #
        'MrmIndexResourceContainerAutoQualifiers': SimTypeFunction([SimTypeRef("MrmResourceIndexerHandle", SimStruct), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "containerPath"]),
        #
        'MrmCreateResourceFile': SimTypeFunction([SimTypeRef("MrmResourceIndexerHandle", SimStruct), SimTypeInt(signed=False, label="MrmPackagingMode"), SimTypeInt(signed=False, label="MrmPackagingOptions"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "packagingMode", "packagingOptions", "outputDirectory"]),
        #
        'MrmCreateResourceFileWithChecksum': SimTypeFunction([SimTypeRef("MrmResourceIndexerHandle", SimStruct), SimTypeInt(signed=False, label="MrmPackagingMode"), SimTypeInt(signed=False, label="MrmPackagingOptions"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "packagingMode", "packagingOptions", "checksum", "outputDirectory"]),
        #
        'MrmCreateResourceFileInMemory': SimTypeFunction([SimTypeRef("MrmResourceIndexerHandle", SimStruct), SimTypeInt(signed=False, label="MrmPackagingMode"), SimTypeInt(signed=False, label="MrmPackagingOptions"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "packagingMode", "packagingOptions", "outputPriData", "outputPriSize"]),
        #
        'MrmPeekResourceIndexerMessages': SimTypeFunction([SimTypeRef("MrmResourceIndexerHandle", SimStruct), SimTypePointer(SimTypePointer(SimTypeRef("MrmResourceIndexerMessage", SimStruct), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["handle", "messages", "numMsgs"]),
        #
        'MrmDestroyIndexerAndMessages': SimTypeFunction([SimTypeRef("MrmResourceIndexerHandle", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer"]),
        #
        'MrmFreeMemory': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["data"]),
        #
        'MrmDumpPriFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmDumpType"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexFileName", "schemaPriFile", "dumpType", "outputXmlFile"]),
        #
        'MrmDumpPriFileInMemory': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmDumpType"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexFileName", "schemaPriFile", "dumpType", "outputXmlData", "outputXmlSize"]),
        #
        'MrmDumpPriDataInMemory': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MrmDumpType"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["inputPriData", "inputPriSize", "schemaPriData", "schemaPriSize", "dumpType", "outputXmlData", "outputXmlSize"]),
        #
        'MrmCreateConfig': SimTypeFunction([SimTypeInt(signed=False, label="MrmPlatformVersion"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["platformVersion", "defaultQualifiers", "outputXmlFile"]),
        #
        'MrmCreateConfigInMemory': SimTypeFunction([SimTypeInt(signed=False, label="MrmPlatformVersion"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["platformVersion", "defaultQualifiers", "outputXmlData", "outputXmlSize"]),
        #
        'MrmGetPriFileContentChecksum': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["priFile", "checksum"]),
    }

lib.set_prototypes(prototypes)
