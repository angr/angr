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
lib.set_library_names("clfs.sys")
prototypes = \
    {
        #
        'ClfsLsnEqual': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["plsn1", "plsn2"]),
        #
        'ClfsLsnLess': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["plsn1", "plsn2"]),
        #
        'ClfsLsnGreater': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["plsn1", "plsn2"]),
        #
        'ClfsLsnNull': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["plsn"]),
        #
        'ClfsLsnContainer': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["plsn"]),
        #
        'ClfsLsnCreate': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeRef("CLS_LSN", SimStruct), arg_names=["cidContainer", "offBlock", "cRecord"]),
        #
        'ClfsLsnBlockOffset': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["plsn"]),
        #
        'ClfsLsnRecordSequence': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["plsn"]),
        #
        'ClfsLsnInvalid': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["plsn"]),
        #
        'ClfsMgmtRegisterManagedClient': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLFS_MGMT_CLIENT_REGISTRATION", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogFile", "RegistrationData", "ClientCookie"]),
        #
        'ClfsMgmtDeregisterManagedClient': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ClientCookie"]),
        #
        'ClfsMgmtTailAdvanceFailure': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Client", "Reason"]),
        #
        'ClfsMgmtHandleLogFileFull': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Client"]),
        #
        'ClfsMgmtInstallPolicy': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLFS_MGMT_POLICY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["LogFile", "Policy", "PolicyLength"]),
        #
        'ClfsMgmtQueryPolicy': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="CLFS_MGMT_POLICY_TYPE"), SimTypePointer(SimTypeRef("CLFS_MGMT_POLICY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogFile", "PolicyType", "Policy", "PolicyLength"]),
        #
        'ClfsMgmtRemovePolicy': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="CLFS_MGMT_POLICY_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["LogFile", "PolicyType"]),
        #
        'ClfsMgmtSetLogFileSize': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["LogFile", "OperationStatus", "ClientData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogFile", "NewSizeInContainers", "ResultingSizeInContainers", "CompletionRoutine", "CompletionRoutineData"]),
        #
        'ClfsMgmtSetLogFileSizeAsClient': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["LogFile", "OperationStatus", "ClientData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogFile", "ClientCookie", "NewSizeInContainers", "ResultingSizeInContainers", "CompletionRoutine", "CompletionRoutineData"]),
        #
        'ClfsInitialize': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'ClfsFinalize': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'ClfsCreateLogFile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pplfoLog", "puszLogFileName", "fDesiredAccess", "dwShareMode", "psdLogFile", "fCreateDisposition", "fCreateOptions", "fFlagsAndAttributes", "fLogOptionFlag", "pvContext", "cbContext"]),
        #
        'ClfsDeleteLogByPointer': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog"]),
        #
        'ClfsDeleteLogFile': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["puszLogFileName", "pvReserved", "fLogOptionFlag", "pvContext", "cbContext"]),
        #
        'ClfsAddLogContainer': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "pcbContainer", "puszContainerPath"]),
        #
        'ClfsAddLogContainerSet': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "cContainers", "pcbContainer", "rguszContainerPath"]),
        #
        'ClfsRemoveLogContainer': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "puszContainerPath", "fForce"]),
        #
        'ClfsRemoveLogContainerSet': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), label="LPArray", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "cContainers", "rgwszContainerPath", "fForce"]),
        #
        'ClfsSetArchiveTail': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "plsnArchiveTail"]),
        #
        'ClfsSetEndOfLog': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "plsnEnd"]),
        #
        'ClfsCreateScanContext': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("CLS_SCAN_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "cFromContainer", "cContainers", "eScanMode", "pcxScan"]),
        #
        'ClfsScanLogContainers': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_SCAN_CONTEXT", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["pcxScan", "eScanMode"]),
        #
        'ClfsGetContainerName': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "cidLogicalContainer", "puszContainerName", "pcActualLenContainerName"]),
        #
        'ClfsGetLogFileInformation': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "pinfoBuffer", "pcbInfoBuffer"]),
        #
        'ClfsQueryLogFileInformation': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="CLS_LOG_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "eInformationClass", "pinfoInputBuffer", "cbinfoInputBuffer", "pinfoBuffer", "pcbInfoBuffer"]),
        #
        'ClfsSetLogFileInformation': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="CLS_LOG_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "eInformationClass", "pinfoBuffer", "cbBuffer"]),
        #
        'ClfsReadRestartArea': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshalContext", "ppvRestartBuffer", "pcbRestartBuffer", "plsn", "ppvReadContext"]),
        #
        'ClfsReadPreviousRestartArea': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvReadContext", "ppvRestartBuffer", "pcbRestartBuffer", "plsnRestart"]),
        #
        'ClfsWriteRestartArea': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshalContext", "pvRestartBuffer", "cbRestartBuffer", "plsnBase", "fFlags", "pcbWritten", "plsnNext"]),
        #
        'ClfsAdvanceLogBase': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshalContext", "plsnBase", "fFlags"]),
        #
        'ClfsCloseAndResetLogFile': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog"]),
        #
        'ClfsCloseLogFileObject': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog"]),
        #
        'ClfsCreateMarshallingArea': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeFunction([], SimTypePointer(SimTypeBottom(label="Void"), offset=0)), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "ePoolType", "pfnAllocBuffer", "pfnFreeBuffer", "cbMarshallingBuffer", "cMaxWriteBuffers", "cMaxReadBuffers", "ppvMarshalContext"]),
        #
        'ClfsCreateMarshallingAreaEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeFunction([], SimTypePointer(SimTypeBottom(label="Void"), offset=0)), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "ePoolType", "pfnAllocBuffer", "pfnFreeBuffer", "cbMarshallingBuffer", "cMaxWriteBuffers", "cMaxReadBuffers", "cAlignmentSize", "fFlags", "ppvMarshalContext"]),
        #
        'ClfsDeleteMarshallingArea': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshalContext"]),
        #
        'ClfsReserveAndAppendLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CLS_WRITE_ENTRY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshalContext", "rgWriteEntries", "cWriteEntries", "plsnUndoNext", "plsnPrevious", "cReserveRecords", "rgcbReservation", "fFlags", "plsn"]),
        #
        'ClfsReserveAndAppendLogAligned': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CLS_WRITE_ENTRY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshalContext", "rgWriteEntries", "cWriteEntries", "cbEntryAlignment", "plsnUndoNext", "plsnPrevious", "cReserveRecords", "rgcbReservation", "fFlags", "plsn"]),
        #
        'ClfsAlignReservedLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), label="LPArray", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshalContext", "cRecords", "rgcbReservation", "pcbAlignReservation"]),
        #
        'ClfsAllocReservedLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshalContext", "cRecords", "pcbAdjustment"]),
        #
        'ClfsFreeReservedLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshalContext", "cRecords", "pcbAdjustment"]),
        #
        'ClfsFlushBuffers': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshalContext"]),
        #
        'ClfsFlushToLsn': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshalContext", "plsnFlush", "plsnLastFlushed"]),
        #
        'ClfsReadLogRecord': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypeInt(signed=False, label="CLFS_CONTEXT_MODE"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvMarshalContext", "plsnFirst", "peContextMode", "ppvReadBuffer", "pcbReadBuffer", "peRecordType", "plsnUndoNext", "plsnPrevious", "ppvReadContext"]),
        #
        'ClfsReadNextLogRecord': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvReadContext", "ppvBuffer", "pcbBuffer", "peRecordType", "plsnUser", "plsnUndoNext", "plsnPrevious", "plsnRecord"]),
        #
        'ClfsTerminateReadLog': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvCursorContext"]),
        #
        'ClfsGetIoStatistics': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="CLFS_IOSTATS_CLASS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plfoLog", "pvStatsBuffer", "cbStatsBuffer", "eStatsClass", "pcbStatsWritten"]),
        #
        'ClfsLaterLsn': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeRef("CLS_LSN", SimStruct), arg_names=["plsn"]),
        #
        'ClfsEarlierLsn': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0)], SimTypeRef("CLS_LSN", SimStruct), arg_names=["plsn"]),
        #
        'ClfsLsnDifference': SimTypeFunction([SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLS_LSN", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plsnStart", "plsnFinish", "cbContainer", "cbMaxBlock", "pcbDifference"]),
    }

lib.set_prototypes(prototypes)
