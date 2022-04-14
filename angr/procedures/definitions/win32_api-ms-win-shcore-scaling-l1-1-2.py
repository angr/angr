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
lib.set_library_names("api-ms-win-shcore-scaling-l1-1-2.dll")
prototypes = \
    {
        # 
        'GetDpiForShellUIComponent': SimTypeFunction([SimTypeInt(signed=False, label="SHELL_UI_COMPONENT")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
    }

lib.set_prototypes(prototypes)
