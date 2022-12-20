# pylint:disable=line-too-long
import logging

from ...sim_type import SimTypeFunction,     SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat,     SimTypePointer,     SimTypeChar,     SimStruct,     SimTypeFixedSizeArray,     SimTypeBottom,     SimUnion,     SimTypeBool
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
lib.set_library_names("mrmsupport.dll")
prototypes = \
    {
        #
        'CreateResourceIndexer': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["projectRoot", "extensionDllPath", "ppResourceIndexer"]),
        #
        'DestroyResourceIndexer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["resourceIndexer"]),
        #
        'IndexFilePath': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimStruct({"name": SimTypePointer(SimTypeChar(label="Char"), offset=0), "value": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="IndexedResourceQualifier", pack=False, align=None), offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["resourceIndexer", "filePath", "ppResourceUri", "pQualifierCount", "ppQualifiers"]),
        #
        'DestroyIndexedResults': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"name": SimTypePointer(SimTypeChar(label="Char"), offset=0), "value": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="IndexedResourceQualifier", pack=False, align=None), label="LPArray", offset=0)], SimTypeBottom(label="Void"), arg_names=["resourceUri", "qualifierCount", "qualifiers"]),
        #
        'MrmCreateResourceIndexer': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmPlatformVersion"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageFamilyName", "projectRoot", "platformVersion", "defaultQualifiers", "indexer"]),
        #
        'MrmCreateResourceIndexerFromPreviousSchemaFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmPlatformVersion"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["projectRoot", "platformVersion", "defaultQualifiers", "schemaFile", "indexer"]),
        #
        'MrmCreateResourceIndexerFromPreviousPriFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmPlatformVersion"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["projectRoot", "platformVersion", "defaultQualifiers", "priFile", "indexer"]),
        #
        'MrmCreateResourceIndexerFromPreviousSchemaData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmPlatformVersion"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["projectRoot", "platformVersion", "defaultQualifiers", "schemaXmlData", "schemaXmlSize", "indexer"]),
        #
        'MrmCreateResourceIndexerFromPreviousPriData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MrmPlatformVersion"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["projectRoot", "platformVersion", "defaultQualifiers", "priData", "priSize", "indexer"]),
        #
        'MrmIndexString': SimTypeFunction([SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "resourceUri", "resourceString", "qualifiers"]),
        #
        'MrmIndexEmbeddedData': SimTypeFunction([SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "resourceUri", "embeddedData", "embeddedDataSize", "qualifiers"]),
        #
        'MrmIndexFile': SimTypeFunction([SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "resourceUri", "filePath", "qualifiers"]),
        #
        'MrmIndexFileAutoQualifiers': SimTypeFunction([SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "filePath"]),
        #
        'MrmIndexResourceContainerAutoQualifiers': SimTypeFunction([SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "containerPath"]),
        #
        'MrmCreateResourceFile': SimTypeFunction([SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None), SimTypeInt(signed=False, label="MrmPackagingMode"), SimTypeInt(signed=False, label="MrmPackagingOptions"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "packagingMode", "packagingOptions", "outputDirectory"]),
        #
        'MrmCreateResourceFileInMemory': SimTypeFunction([SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None), SimTypeInt(signed=False, label="MrmPackagingMode"), SimTypeInt(signed=False, label="MrmPackagingOptions"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer", "packagingMode", "packagingOptions", "outputPriData", "outputPriSize"]),
        #
        'MrmPeekResourceIndexerMessages': SimTypeFunction([SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None), SimTypePointer(SimTypePointer(SimStruct({"severity": SimTypeInt(signed=False, label="MrmResourceIndexerMessageSeverity"), "id": SimTypeInt(signed=False, label="UInt32"), "text": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="MrmResourceIndexerMessage", pack=False, align=None), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["handle", "messages", "numMsgs"]),
        #
        'MrmDestroyIndexerAndMessages': SimTypeFunction([SimStruct({"handle": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="MrmResourceIndexerHandle", pack=False, align=None)], SimTypeInt(signed=True, label="Int32"), arg_names=["indexer"]),
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
    }

lib.set_prototypes(prototypes)
