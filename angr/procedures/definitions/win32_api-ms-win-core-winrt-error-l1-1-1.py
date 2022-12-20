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
lib.set_library_names("api-ms-win-core-winrt-error-l1-1-1.dll")
prototypes = \
    {
        #
        'RoOriginateLanguageException': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["error", "message", "languageException"]),
        #
        'RoClearError': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'RoReportUnhandledError': SimTypeFunction([SimTypeBottom(label="IRestrictedErrorInfo")], SimTypeInt(signed=True, label="Int32"), arg_names=["pRestrictedErrorInfo"]),
        #
        'RoInspectThreadErrorInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["context", "readAddress", "length", "buffer"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["targetTebAddress", "machine", "readMemoryCallback", "context", "targetErrorInfoAddress"]),
        #
        'RoInspectCapturedStackBackTrace': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["context", "readAddress", "length", "buffer"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["targetErrorInfoAddress", "machine", "readMemoryCallback", "context", "frameCount", "targetBackTraceAddress"]),
        #
        'RoGetMatchingRestrictedErrorInfo': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="IRestrictedErrorInfo"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrIn", "ppRestrictedErrorInfo"]),
        #
        'RoReportFailedDelegate': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IRestrictedErrorInfo")], SimTypeInt(signed=True, label="Int32"), arg_names=["punkDelegate", "pRestrictedErrorInfo"]),
        #
        'IsErrorPropagationEnabled': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
    }

lib.set_prototypes(prototypes)
