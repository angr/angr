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
lib.set_library_names("rtworkq.dll")
prototypes = \
    {
        #
        'RtwqStartup': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'RtwqShutdown': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'RtwqLockWorkQueue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["workQueueId"]),
        #
        'RtwqUnlockWorkQueue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["workQueueId"]),
        #
        'RtwqLockSharedWorkQueue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["usageClass", "basePriority", "taskId", "id"]),
        #
        'RtwqJoinWorkQueue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["workQueueId", "hFile", "out"]),
        #
        'RtwqUnjoinWorkQueue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["workQueueId", "hFile"]),
        #
        'RtwqCreateAsyncResult': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IRtwqAsyncCallback"), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IRtwqAsyncResult"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["appObject", "callback", "appState", "asyncResult"]),
        #
        'RtwqInvokeCallback': SimTypeFunction([SimTypeBottom(label="IRtwqAsyncResult")], SimTypeInt(signed=True, label="Int32"), arg_names=["result"]),
        #
        'RtwqLockPlatform': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'RtwqUnlockPlatform': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'RtwqRegisterPlatformWithMMCSS': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["usageClass", "taskId", "lPriority"]),
        #
        'RtwqUnregisterPlatformFromMMCSS': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'RtwqPutWorkItem': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeBottom(label="IRtwqAsyncResult")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwQueue", "lPriority", "result"]),
        #
        'RtwqPutWaitingWorkItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeBottom(label="IRtwqAsyncResult"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent", "lPriority", "result", "key"]),
        #
        'RtwqAllocateSerialWorkQueue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["workQueueIdIn", "workQueueIdOut"]),
        #
        'RtwqScheduleWorkItem': SimTypeFunction([SimTypeBottom(label="IRtwqAsyncResult"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["result", "Timeout", "key"]),
        #
        'RtwqAddPeriodicCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Callback", "context", "key"]),
        #
        'RtwqRemovePeriodicCallback': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwKey"]),
        #
        'RtwqCancelWorkItem': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["Key"]),
        #
        'RtwqAllocateWorkQueue': SimTypeFunction([SimTypeInt(signed=False, label="RTWQ_WORKQUEUE_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["WorkQueueType", "workQueueId"]),
        #
        'RtwqBeginRegisterWorkQueueWithMMCSS': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeBottom(label="IRtwqAsyncCallback"), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["workQueueId", "usageClass", "dwTaskId", "lPriority", "doneCallback", "doneState"]),
        #
        'RtwqBeginUnregisterWorkQueueWithMMCSS': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IRtwqAsyncCallback"), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["workQueueId", "doneCallback", "doneState"]),
        #
        'RtwqEndRegisterWorkQueueWithMMCSS': SimTypeFunction([SimTypeBottom(label="IRtwqAsyncResult"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["result", "taskId"]),
        #
        'RtwqGetWorkQueueMMCSSClass': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["workQueueId", "usageClass", "usageClassLength"]),
        #
        'RtwqGetWorkQueueMMCSSTaskId': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["workQueueId", "taskId"]),
        #
        'RtwqGetWorkQueueMMCSSPriority': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["workQueueId", "priority"]),
        #
        'RtwqRegisterPlatformEvents': SimTypeFunction([SimTypeBottom(label="IRtwqPlatformEvents")], SimTypeInt(signed=True, label="Int32"), arg_names=["platformEvents"]),
        #
        'RtwqUnregisterPlatformEvents': SimTypeFunction([SimTypeBottom(label="IRtwqPlatformEvents")], SimTypeInt(signed=True, label="Int32"), arg_names=["platformEvents"]),
        #
        'RtwqSetLongRunning': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["workQueueId", "enable"]),
        #
        'RtwqSetDeadline': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["workQueueId", "deadlineInHNS", "pRequest"]),
        #
        'RtwqSetDeadline2': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["workQueueId", "deadlineInHNS", "preDeadlineInHNS", "pRequest"]),
        #
        'RtwqCancelDeadline': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRequest"]),
    }

lib.set_prototypes(prototypes)
