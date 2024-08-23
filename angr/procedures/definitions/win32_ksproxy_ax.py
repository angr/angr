# pylint:disable=line-too-long
from __future__ import annotations
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
lib.set_library_names("ksproxy.ax")
prototypes = \
    {
        #
        'KsResolveRequiredAttributes': SimTypeFunction([SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("FormatSize", SimTypeInt(signed=False, label="UInt32")), ("Flags", SimTypeInt(signed=False, label="UInt32")), ("SampleSize", SimTypeInt(signed=False, label="UInt32")), ("Reserved", SimTypeInt(signed=False, label="UInt32")), ("MajorFormat", SimTypeBottom(label="Guid")), ("SubFormat", SimTypeBottom(label="Guid")), ("Specifier", SimTypeBottom(label="Guid")),)), name="_Anonymous_e__Struct", pack=False, align=None), "Alignment": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeRef("KSMULTIPLE_ITEM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DataRange", "Attributes"]),
        #
        'KsOpenDefaultDevice': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Category", "Access", "DeviceHandle"]),
        #
        'KsSynchronousDeviceControl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "IoControl", "InBuffer", "InLength", "OutBuffer", "OutLength", "BytesReturned"]),
        #
        'KsGetMultiplePinFactoryItems': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FilterHandle", "PinFactoryId", "PropertyId", "Items"]),
        #
        'KsGetMediaTypeCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FilterHandle", "PinFactoryId", "MediaTypeCount"]),
        #
        'KsGetMediaType': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("AM_MEDIA_TYPE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Position", "AmMediaType", "FilterHandle", "PinFactoryId"]),
    }

lib.set_prototypes(prototypes)
