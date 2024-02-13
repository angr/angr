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
lib.set_library_names("clfsw32.dll")
prototypes = \
    {
        #
        'LsnEqual': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["plsn1", "plsn2"]),
        #
        'LsnLess': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["plsn1", "plsn2"]),
        #
        'LsnGreater': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["plsn1", "plsn2"]),
        #
        'LsnNull': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["plsn"]),
        #
        'LsnContainer': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["plsn"]),
        #
        'LsnCreate': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeRef("CLS_LSN", SimStruct), arg_names=["cidContainer", "offBlock", "cRecord"]),
        #
        'LsnBlockOffset': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["plsn"]),
        #
        'LsnRecordSequence': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["plsn"]),
        #
        'LsnInvalid': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["plsn"]),
        #
        'LsnIncrement': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeRef("CLS_LSN", SimStruct), arg_names=["plsn"]),
        #
        'CreateLogFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_SHARE_MODE"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="FILE_CREATION_DISPOSITION"), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pszLogFileName", "fDesiredAccess", "dwShareMode", "psaLogFile", "fCreateDisposition", "fFlagsAndAttributes"]),
        #
        'DeleteLogByHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog"]),
        #
        'DeleteLogFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszLogFileName", "pvReserved"]),
        #
        'AddLogContainer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "pcbContainer", "pwszContainerPath", "pReserved"]),
        #
        'AddLogContainerSet': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "cContainer", "pcbContainer", "rgwszContainerPath", "pReserved"]),
        #
        'RemoveLogContainer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "pwszContainerPath", "fForce", "pReserved"]),
        #
        'RemoveLogContainerSet': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "cContainer", "rgwszContainerPath", "fForce", "pReserved"]),
        #
        'SetLogArchiveTail': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "plsnArchiveTail", "pReserved"]),
        #
        'SetEndOfLog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "plsnEnd", "lpOverlapped"]),
        #
        'TruncateLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshal", "plsnEnd", "lpOverlapped"]),
        #
        'CreateLogContainerScanContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("CLS_SCAN_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "cFromContainer", "cContainers", "eScanMode", "pcxScan", "pOverlapped"]),
        #
        'ScanLogContainers': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_SCAN_CONTEXT", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcxScan", "eScanMode", "pReserved"]),
        #
        'AlignReservedLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshal", "cReservedRecords", "rgcbReservation", "pcbAlignReservation"]),
        #
        'AllocReservedLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshal", "cReservedRecords", "pcbAdjustment"]),
        #
        'FreeReservedLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshal", "cReservedRecords", "pcbAdjustment"]),
        #
        'GetLogFileInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CLS_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "pinfoBuffer", "cbBuffer"]),
        #
        'SetLogArchiveMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CLFS_LOG_ARCHIVE_MODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "eMode"]),
        #
        'ReadLogRestartArea': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshal", "ppvRestartBuffer", "pcbRestartBuffer", "plsn", "ppvContext", "pOverlapped"]),
        #
        'ReadPreviousLogRestartArea': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvReadContext", "ppvRestartBuffer", "pcbRestartBuffer", "plsnRestart", "pOverlapped"]),
        #
        'WriteLogRestartArea': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypeInt(signed=False, label="CLFS_FLAG"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshal", "pvRestartBuffer", "cbRestartBuffer", "plsnBase", "fFlags", "pcbWritten", "plsnNext", "pOverlapped"]),
        #
        'GetLogReservationInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshal", "pcbRecordNumber", "pcbUserReservation", "pcbCommitReservation"]),
        #
        'AdvanceLogBase': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshal", "plsnBase", "fFlags", "pOverlapped"]),
        #
        'CloseAndResetLogFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog"]),
        #
        'CreateLogMarshallingArea': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["cbBufferLength", "pvUserContext"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pvBuffer", "pvUserContext"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "pfnAllocBuffer", "pfnFreeBuffer", "pvBlockAllocContext", "cbMarshallingBuffer", "cMaxWriteBuffers", "cMaxReadBuffers", "ppvMarshal"]),
        #
        'DeleteLogMarshallingArea': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshal"]),
        #
        'ReserveAndAppendLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CLS_WRITE_ENTRY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="CLFS_FLAG"), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshal", "rgWriteEntries", "cWriteEntries", "plsnUndoNext", "plsnPrevious", "cReserveRecords", "rgcbReservation", "fFlags", "plsn", "pOverlapped"]),
        #
        'ReserveAndAppendLogAligned': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CLS_WRITE_ENTRY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="CLFS_FLAG"), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshal", "rgWriteEntries", "cWriteEntries", "cbEntryAlignment", "plsnUndoNext", "plsnPrevious", "cReserveRecords", "rgcbReservation", "fFlags", "plsn", "pOverlapped"]),
        #
        'FlushLogBuffers': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshal", "pOverlapped"]),
        #
        'FlushLogToLsn': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshalContext", "plsnFlush", "plsnLastFlushed", "pOverlapped"]),
        #
        'ReadLogRecord': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypeInt(signed=False, label="CLFS_CONTEXT_MODE"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshal", "plsnFirst", "eContextMode", "ppvReadBuffer", "pcbReadBuffer", "peRecordType", "plsnUndoNext", "plsnPrevious", "ppvReadContext", "pOverlapped"]),
        #
        'ReadNextLogRecord': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvReadContext", "ppvBuffer", "pcbBuffer", "peRecordType", "plsnUser", "plsnUndoNext", "plsnPrevious", "plsnRecord", "pOverlapped"]),
        #
        'TerminateReadLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvCursorContext"]),
        #
        'PrepareLogArchive': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "pszBaseLogFileName", "cLen", "plsnLow", "plsnHigh", "pcActualLength", "poffBaseLogFileData", "pcbBaseLogFileLength", "plsnBase", "plsnLast", "plsnCurrentArchiveTail", "ppvArchiveContext"]),
        #
        'ReadLogArchiveMetadata': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvArchiveContext", "cbOffset", "cbBytesToRead", "pbReadBuffer", "pcbBytesRead"]),
        #
        'GetNextLogArchiveExtent': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CLS_ARCHIVE_DESCRIPTOR", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvArchiveContext", "rgadExtent", "cDescriptors", "pcDescriptorsReturned"]),
        #
        'TerminateLogArchive': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvArchiveContext"]),
        #
        'ValidateLog': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszLogFileName", "psaLogFile", "pinfoBuffer", "pcbBuffer"]),
        #
        'GetLogContainerName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "cidLogicalContainer", "pwstrContainerName", "cLenContainerName", "pcActualLenContainerName"]),
        #
        'GetLogIoStatistics': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="CLFS_IOSTATS_CLASS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "pvStatsBuffer", "cbStatsBuffer", "eStatsClass", "pcbStatsWritten"]),
        #
        'RegisterManageableLogClient': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LOG_MANAGEMENT_CALLBACKS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "pCallbacks"]),
        #
        'DeregisterManageableLogClient': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog"]),
        #
        'ReadLogNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CLFS_MGMT_NOTIFICATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "pNotification", "lpOverlapped"]),
        #
        'InstallLogPolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CLFS_MGMT_POLICY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "pPolicy"]),
        #
        'RemoveLogPolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CLFS_MGMT_POLICY_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "ePolicyType"]),
        #
        'QueryLogPolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CLFS_MGMT_POLICY_TYPE"), SimTypePointer(SimTypeRef("CLFS_MGMT_POLICY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "ePolicyType", "pPolicyBuffer", "pcbPolicyBuffer"]),
        #
        'SetLogFileSizeWithPolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "pDesiredSize", "pResultingSize"]),
        #
        'HandleLogFull': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog"]),
        #
        'LogTailAdvanceFailure': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "dwReason"]),
        #
        'RegisterForLogWriteNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLog", "cbThreshold", "fEnable"]),
    }

lib.set_prototypes(prototypes)
