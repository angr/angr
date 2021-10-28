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
lib.set_library_names("api-ms-win-shcore-scaling-l1-1-0.dll")
prototypes = \
    {
        # 
        'GetScaleFactorForDevice': SimTypeFunction([SimTypeInt(signed=False, label="DISPLAY_DEVICE_TYPE")], SimTypeInt(signed=False, label="DEVICE_SCALE_FACTOR"), arg_names=["deviceType"]),
        # 
        'RegisterScaleChangeNotifications': SimTypeFunction([SimTypeInt(signed=False, label="DISPLAY_DEVICE_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["displayDevice", "hwndNotify", "uMsgNotify", "pdwCookie"]),
        # 
        'RevokeScaleChangeNotifications': SimTypeFunction([SimTypeInt(signed=False, label="DISPLAY_DEVICE_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["displayDevice", "dwCookie"]),
    }

lib.set_prototypes(prototypes)
