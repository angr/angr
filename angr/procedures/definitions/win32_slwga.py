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
lib.set_library_names("slwga.dll")
prototypes = \
    {
        # 
        'SLIsGenuineLocal': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SL_GENUINE_STATE"), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "pComponentId": SimTypePointer(SimTypeBottom(label="Guid"), offset=0), "hResultUI": SimTypeInt(signed=True, label="Int32")}, name="SL_NONGENUINE_UI_OPTIONS", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAppId", "pGenuineState", "pUIOptions"]),
    }

lib.set_prototypes(prototypes)
