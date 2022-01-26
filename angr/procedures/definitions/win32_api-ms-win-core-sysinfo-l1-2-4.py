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
lib.set_library_names("api-ms-win-core-sysinfo-l1-2-4.dll")
prototypes = \
    {
        # 
        'GetSystemTimeAdjustmentPrecise': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTimeAdjustment", "lpTimeIncrement", "lpTimeAdjustmentDisabled"]),
        # 
        'SetSystemTimeAdjustmentPrecise': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTimeAdjustment", "bTimeAdjustmentDisabled"]),
    }

lib.set_prototypes(prototypes)
