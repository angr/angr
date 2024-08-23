# pylint:disable=line-too-long
from __future__ import annotations
import logging

from ...sim_type import SimTypeFunction,     SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat,     SimTypePointer,     SimTypeChar,     SimStruct,     SimTypeFixedSizeArray,     SimTypeBottom,     SimUnion,     SimTypeBool
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
lib.set_library_names("api-ms-win-core-winrt-error-l1-1-0.dll")
prototypes = \
    {
        #
        'RoGetErrorReportingFlags': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pflags"]),
        #
        'RoSetErrorReportingFlags': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["flags"]),
        #
        'RoResolveRestrictedErrorInfoReference': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IRestrictedErrorInfo"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["reference", "ppRestrictedErrorInfo"]),
        #
        'SetRestrictedErrorInfo': SimTypeFunction([SimTypeBottom(label="IRestrictedErrorInfo")], SimTypeInt(signed=True, label="Int32"), arg_names=["pRestrictedErrorInfo"]),
        #
        'GetRestrictedErrorInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IRestrictedErrorInfo"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppRestrictedErrorInfo"]),
        #
        'RoOriginateErrorW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["error", "cchMax", "message"]),
        #
        'RoOriginateError': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["error", "message"]),
        #
        'RoTransformErrorW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["oldError", "newError", "cchMax", "message"]),
        #
        'RoTransformError': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["oldError", "newError", "message"]),
        #
        'RoCaptureErrorContext': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hr"]),
        #
        'RoFailFastWithErrorContext': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["hrError"]),
    }

lib.set_prototypes(prototypes)
