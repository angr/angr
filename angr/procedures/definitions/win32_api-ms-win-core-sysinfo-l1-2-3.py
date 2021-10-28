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
lib.set_library_names("api-ms-win-core-sysinfo-l1-2-3.dll")
prototypes = \
    {
        # 
        'GetOsManufacturingMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbEnabled"]),
        # 
        'GetIntegratedDisplaySize': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sizeInInches"]),
    }

lib.set_prototypes(prototypes)
