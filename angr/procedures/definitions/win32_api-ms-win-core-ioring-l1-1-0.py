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
lib.set_library_names("api-ms-win-core-ioring-l1-1-0.dll")
prototypes = \
    {
        #
        'QueryIoRingCapabilities': SimTypeFunction([SimTypePointer(SimTypeRef("IORING_CAPABILITIES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["capabilities"]),
        #
        'IsIoRingOpSupported': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="IORING_OP_CODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["ioRing", "op"]),
        #
        'CreateIoRing': SimTypeFunction([SimTypeInt(signed=False, label="IORING_VERSION"), SimTypeRef("IORING_CREATE_FLAGS", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ioringVersion", "flags", "submissionQueueSize", "completionQueueSize", "h"]),
        #
        'GetIoRingInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IORING_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ioRing", "info"]),
        #
        'SubmitIoRing': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ioRing", "waitOperations", "milliseconds", "submittedEntries"]),
        #
        'CloseIoRing': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ioRing"]),
        #
        'PopIoRingCompletion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IORING_CQE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ioRing", "cqe"]),
        #
        'SetIoRingCompletionEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ioRing", "hEvent"]),
        #
        'BuildIoRingCancelRequest': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("IORING_HANDLE_REF", SimStruct), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ioRing", "file", "opToCancel", "userData"]),
        #
        'BuildIoRingReadFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("IORING_HANDLE_REF", SimStruct), SimTypeRef("IORING_BUFFER_REF", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="IORING_SQE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["ioRing", "fileRef", "dataRef", "numberOfBytesToRead", "fileOffset", "userData", "sqeFlags"]),
        #
        'BuildIoRingRegisterFileHandles': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ioRing", "count", "handles", "userData"]),
        #
        'BuildIoRingRegisterBuffers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IORING_BUFFER_INFO", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ioRing", "count", "buffers", "userData"]),
    }

lib.set_prototypes(prototypes)
