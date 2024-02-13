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
lib.set_library_names("api-ms-win-core-realtime-l1-1-2.dll")
prototypes = \
    {
        #
        'QueryAuxiliaryCounterFrequency': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAuxiliaryCounterFrequency"]),
        #
        'ConvertAuxiliaryCounterToPerformanceCounter': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ullAuxiliaryCounterValue", "lpPerformanceCounterValue", "lpConversionError"]),
        #
        'ConvertPerformanceCounterToAuxiliaryCounter': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ullPerformanceCounterValue", "lpAuxiliaryCounterValue", "lpConversionError"]),
    }

lib.set_prototypes(prototypes)
