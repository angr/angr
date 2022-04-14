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
lib.set_library_names("sensapi.dll")
prototypes = \
    {
        # 
        'IsDestinationReachableA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwInSpeed": SimTypeInt(signed=False, label="UInt32"), "dwOutSpeed": SimTypeInt(signed=False, label="UInt32")}, name="QOCINFO", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszDestination", "lpQOCInfo"]),
        # 
        'IsDestinationReachableW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwInSpeed": SimTypeInt(signed=False, label="UInt32"), "dwOutSpeed": SimTypeInt(signed=False, label="UInt32")}, name="QOCINFO", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszDestination", "lpQOCInfo"]),
        # 
        'IsNetworkAlive': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwFlags"]),
    }

lib.set_prototypes(prototypes)
