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
lib.set_library_names("wer.dll")
prototypes = \
    {
        #
        'WerReportCreate': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="WER_REPORT_TYPE"), SimTypePointer(SimTypeRef("WER_REPORT_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzEventType", "repType", "pReportInformation", "phReportHandle"]),
        #
        'WerReportSetParameter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportHandle", "dwparamID", "pwzName", "pwzValue"]),
        #
        'WerReportAddFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="WER_FILE_TYPE"), SimTypeInt(signed=False, label="WER_FILE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportHandle", "pwzPath", "repFileType", "dwFileFlags"]),
        #
        'WerReportSetUIOption': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WER_REPORT_UI"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportHandle", "repUITypeID", "pwzValue"]),
        #
        'WerReportSubmit': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WER_CONSENT"), SimTypeInt(signed=False, label="WER_SUBMIT_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="WER_SUBMIT_RESULT"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportHandle", "consent", "dwFlags", "pSubmitResult"]),
        #
        'WerReportAddDump': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WER_DUMP_TYPE"), SimTypePointer(SimTypeRef("WER_EXCEPTION_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("WER_DUMP_CUSTOM_OPTIONS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportHandle", "hProcess", "hThread", "dumpType", "pExceptionParam", "pDumpCustomOptions", "dwFlags"]),
        #
        'WerReportCloseHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportHandle"]),
        #
        'WerAddExcludedApplication': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzExeName", "bAllUsers"]),
        #
        'WerRemoveExcludedApplication': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzExeName", "bAllUsers"]),
        #
        'WerStoreOpen': SimTypeFunction([SimTypeInt(signed=False, label="REPORT_STORE_TYPES"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["repStoreType", "phReportStore"]),
        #
        'WerStoreClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hReportStore"]),
        #
        'WerStoreGetFirstReportKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportStore", "ppszReportKey"]),
        #
        'WerStoreGetNextReportKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportStore", "ppszReportKey"]),
        #
        'WerStoreQueryReportMetadataV2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WER_REPORT_METADATA_V2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportStore", "pszReportKey", "pReportMetadata"]),
        #
        'WerStoreQueryReportMetadataV3': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WER_REPORT_METADATA_V3", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportStore", "pszReportKey", "pReportMetadata"]),
        #
        'WerFreeString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pwszStr"]),
        #
        'WerStorePurge': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'WerStoreGetReportCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportStore", "pdwReportCount"]),
        #
        'WerStoreGetSizeOnDisk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportStore", "pqwSizeInBytes"]),
        #
        'WerStoreQueryReportMetadataV1': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WER_REPORT_METADATA_V1", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportStore", "pszReportKey", "pReportMetadata"]),
        #
        'WerStoreUploadReport': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="WER_SUBMIT_RESULT"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReportStore", "pszReportKey", "dwFlags", "pSubmitResult"]),
    }

lib.set_prototypes(prototypes)
