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
lib.set_library_names("api-ms-win-core-realtime-l1-1-1.dll")
prototypes = \
    {
        # 
        'QueryInterruptTimePrecise': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpInterruptTimePrecise"]),
        # 
        'QueryUnbiasedInterruptTimePrecise': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpUnbiasedInterruptTimePrecise"]),
        # 
        'QueryInterruptTime': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpInterruptTime"]),
    }

lib.set_prototypes(prototypes)
