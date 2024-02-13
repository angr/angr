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
lib.set_library_names("diagnosticdataquery.dll")
prototypes = \
    {
        #
        'DdqCreateSession': SimTypeFunction([SimTypeInt(signed=False, label="DdqAccessLevel"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["accessLevel", "hSession"]),
        #
        'DdqCloseSession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession"]),
        #
        'DdqGetSessionAccessLevel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="DdqAccessLevel"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "accessLevel"]),
        #
        'DdqGetDiagnosticDataAccessLevelAllowed': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="DdqAccessLevel"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["accessLevel"]),
        #
        'DdqGetDiagnosticRecordStats': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DIAGNOSTIC_DATA_SEARCH_CRITERIA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "searchCriteria", "recordCount", "minRowId", "maxRowId"]),
        #
        'DdqGetDiagnosticRecordPayload': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "rowId", "payload"]),
        #
        'DdqGetDiagnosticRecordLocaleTags': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "locale", "hTagDescription"]),
        #
        'DdqFreeDiagnosticRecordLocaleTags': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTagDescription"]),
        #
        'DdqGetDiagnosticRecordLocaleTagAtIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DIAGNOSTIC_DATA_EVENT_TAG_DESCRIPTION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTagDescription", "index", "tagDescription"]),
        #
        'DdqGetDiagnosticRecordLocaleTagCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTagDescription", "tagDescriptionCount"]),
        #
        'DdqGetDiagnosticRecordProducers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "hProducerDescription"]),
        #
        'DdqFreeDiagnosticRecordProducers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProducerDescription"]),
        #
        'DdqGetDiagnosticRecordProducerAtIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DIAGNOSTIC_DATA_EVENT_PRODUCER_DESCRIPTION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProducerDescription", "index", "producerDescription"]),
        #
        'DdqGetDiagnosticRecordProducerCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProducerDescription", "producerDescriptionCount"]),
        #
        'DdqGetDiagnosticRecordProducerCategories': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "producerName", "hCategoryDescription"]),
        #
        'DdqFreeDiagnosticRecordProducerCategories': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCategoryDescription"]),
        #
        'DdqGetDiagnosticRecordCategoryAtIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DIAGNOSTIC_DATA_EVENT_CATEGORY_DESCRIPTION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCategoryDescription", "index", "categoryDescription"]),
        #
        'DdqGetDiagnosticRecordCategoryCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCategoryDescription", "categoryDescriptionCount"]),
        #
        'DdqIsDiagnosticRecordSampledIn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "providerGroup", "providerId", "providerName", "eventId", "eventName", "eventVersion", "eventKeywords", "isSampledIn"]),
        #
        'DdqGetDiagnosticRecordPage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DIAGNOSTIC_DATA_SEARCH_CRITERIA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "searchCriteria", "offset", "pageRecordCount", "baseRowId", "hRecord"]),
        #
        'DdqFreeDiagnosticRecordPage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRecord"]),
        #
        'DdqGetDiagnosticRecordAtIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DIAGNOSTIC_DATA_RECORD", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRecord", "index", "record"]),
        #
        'DdqGetDiagnosticRecordCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRecord", "recordCount"]),
        #
        'DdqGetDiagnosticReportStoreReportCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "reportStoreType", "reportCount"]),
        #
        'DdqCancelDiagnosticRecordOperation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession"]),
        #
        'DdqGetDiagnosticReport': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "reportStoreType", "hReport"]),
        #
        'DdqFreeDiagnosticReport': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReport"]),
        #
        'DdqGetDiagnosticReportAtIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DIAGNOSTIC_REPORT_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReport", "index", "report"]),
        #
        'DdqGetDiagnosticReportCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReport", "reportCount"]),
        #
        'DdqExtractDiagnosticReport': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "reportStoreType", "reportKey", "destinationPath"]),
        #
        'DdqGetDiagnosticRecordTagDistribution': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DIAGNOSTIC_DATA_EVENT_TAG_STATS", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "producerNames", "producerNameCount", "tagStats", "statCount"]),
        #
        'DdqGetDiagnosticRecordBinaryDistribution': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DIAGNOSTIC_DATA_EVENT_BINARY_STATS", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "producerNames", "producerNameCount", "topNBinaries", "binaryStats", "statCount"]),
        #
        'DdqGetDiagnosticRecordSummary': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DIAGNOSTIC_DATA_GENERAL_STATS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "producerNames", "producerNameCount", "generalStats"]),
        #
        'DdqSetTranscriptConfiguration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DIAGNOSTIC_DATA_EVENT_TRANSCRIPT_CONFIGURATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "desiredConfig"]),
        #
        'DdqGetTranscriptConfiguration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DIAGNOSTIC_DATA_EVENT_TRANSCRIPT_CONFIGURATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "currentConfig"]),
    }

lib.set_prototypes(prototypes)
