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
lib.set_library_names("mqrt.dll")
prototypes = \
    {
        #
        'MQCreateQueue': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MQQUEUEPROPS", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "pQueueProps", "lpwcsFormatName", "lpdwFormatNameLength"]),
        #
        'MQDeleteQueue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpwcsFormatName"]),
        #
        'MQLocateBegin': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("MQRESTRICTION", SimStruct), offset=0), SimTypePointer(SimTypeRef("MQCOLUMNSET", SimStruct), offset=0), SimTypePointer(SimTypeRef("MQSORTSET", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpwcsContext", "pRestriction", "pColumns", "pSort", "phEnum"]),
        #
        'MQLocateNext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEnum", "pcProps", "aPropVar"]),
        #
        'MQLocateEnd': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEnum"]),
        #
        'MQOpenQueue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpwcsFormatName", "dwAccess", "dwShareMode", "phQueue"]),
        #
        'MQSendMessage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MQMSGPROPS", SimStruct), offset=0), SimTypeBottom(label="ITransaction")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDestinationQueue", "pMessageProps", "pTransaction"]),
        #
        'MQReceiveMessage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MQMSGPROPS", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MQMSGPROPS", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hrStatus", "hSource", "dwTimeout", "dwAction", "pMessageProps", "lpOverlapped", "hCursor"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="ITransaction")], SimTypeInt(signed=True, label="Int32"), arg_names=["hSource", "dwTimeout", "dwAction", "pMessageProps", "lpOverlapped", "fnReceiveCallback", "hCursor", "pTransaction"]),
        #
        'MQReceiveMessageByLookupId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MQMSGPROPS", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MQMSGPROPS", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hrStatus", "hSource", "dwTimeout", "dwAction", "pMessageProps", "lpOverlapped", "hCursor"]), offset=0), SimTypeBottom(label="ITransaction")], SimTypeInt(signed=True, label="Int32"), arg_names=["hSource", "ullLookupId", "dwLookupAction", "pMessageProps", "lpOverlapped", "fnReceiveCallback", "pTransaction"]),
        #
        'MQCreateCursor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hQueue", "phCursor"]),
        #
        'MQCloseCursor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCursor"]),
        #
        'MQCloseQueue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hQueue"]),
        #
        'MQSetQueueProperties': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("MQQUEUEPROPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpwcsFormatName", "pQueueProps"]),
        #
        'MQGetQueueProperties': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("MQQUEUEPROPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpwcsFormatName", "pQueueProps"]),
        #
        'MQGetQueueSecurity': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpwcsFormatName", "RequestedInformation", "pSecurityDescriptor", "nLength", "lpnLengthNeeded"]),
        #
        'MQSetQueueSecurity': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpwcsFormatName", "SecurityInformation", "pSecurityDescriptor"]),
        #
        'MQPathNameToFormatName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpwcsPathName", "lpwcsFormatName", "lpdwFormatNameLength"]),
        #
        'MQHandleToFormatName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hQueue", "lpwcsFormatName", "lpdwFormatNameLength"]),
        #
        'MQInstanceToFormatName': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pGuid", "lpwcsFormatName", "lpdwFormatNameLength"]),
        #
        'MQADsPathToFormatName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpwcsADsPath", "lpwcsFormatName", "lpdwFormatNameLength"]),
        #
        'MQFreeMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pvMemory"]),
        #
        'MQGetMachineProperties': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("MQQMPROPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpwcsMachineName", "pguidMachineId", "pQMProps"]),
        #
        'MQGetSecurityContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCertBuffer", "dwCertBufferLength", "phSecurityContext"]),
        #
        'MQGetSecurityContextEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCertBuffer", "dwCertBufferLength", "phSecurityContext"]),
        #
        'MQFreeSecurityContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hSecurityContext"]),
        #
        'MQRegisterCertificate': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "lpCertBuffer", "dwCertBufferLength"]),
        #
        'MQBeginTransaction': SimTypeFunction([SimTypePointer(SimTypeBottom(label="ITransaction"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppTransaction"]),
        #
        'MQGetOverlappedResult': SimTypeFunction([SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpOverlapped"]),
        #
        'MQGetPrivateComputerInformation': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("MQPRIVATEPROPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpwcsComputerName", "pPrivateProps"]),
        #
        'MQPurgeQueue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hQueue"]),
        #
        'MQMgmtGetInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("MQMGMTPROPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pComputerName", "pObjectName", "pMgmtProps"]),
        #
        'MQMgmtAction': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pComputerName", "pObjectName", "pAction"]),
        #
        'MQMarkMessageRejected': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["hQueue", "ullLookupId"]),
        #
        'MQMoveMessage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeBottom(label="ITransaction")], SimTypeInt(signed=True, label="Int32"), arg_names=["hSourceQueue", "hDestinationQueue", "ullLookupId", "pTransaction"]),
    }

lib.set_prototypes(prototypes)
