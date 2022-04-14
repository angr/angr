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
lib.set_library_names("wnvapi.dll")
prototypes = \
    {
        # 
        'WnvOpen': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        # 
        'WnvRequestNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"Header": SimStruct({"MajorVersion": SimTypeChar(label="Byte"), "MinorVersion": SimTypeChar(label="Byte"), "Size": SimTypeInt(signed=False, label="UInt32")}, name="WNV_OBJECT_HEADER", pack=False, align=None), "NotificationType": SimTypeInt(signed=False, label="WNV_NOTIFICATION_TYPE"), "PendingNotifications": SimTypeInt(signed=False, label="UInt32"), "Buffer": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="WNV_NOTIFICATION_PARAM", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"Internal": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "InternalHigh": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "Anonymous": SimUnion({"Anonymous": SimStruct({"Offset": SimTypeInt(signed=False, label="UInt32"), "OffsetHigh": SimTypeInt(signed=False, label="UInt32")}, name="_Anonymous_e__Struct", pack=False, align=None), "Pointer": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), "hEvent": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="OVERLAPPED", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["WnvHandle", "NotificationParam", "Overlapped", "BytesTransferred"]),
    }

lib.set_prototypes(prototypes)
