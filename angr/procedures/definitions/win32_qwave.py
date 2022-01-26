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
lib.set_library_names("qwave.dll")
prototypes = \
    {
        # 
        'QOSCreateHandle': SimTypeFunction([SimTypePointer(SimStruct({"MajorVersion": SimTypeShort(signed=False, label="UInt16"), "MinorVersion": SimTypeShort(signed=False, label="UInt16")}, name="QOS_VERSION", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Version", "QOSHandle"]),
        # 
        'QOSCloseHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["QOSHandle"]),
        # 
        'QOSStartTrackingClient': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"sa_family": SimTypeShort(signed=False, label="UInt16"), "sa_data": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 14)}, name="SOCKADDR", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["QOSHandle", "DestAddr", "Flags"]),
        # 
        'QOSStopTrackingClient': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"sa_family": SimTypeShort(signed=False, label="UInt16"), "sa_data": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 14)}, name="SOCKADDR", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["QOSHandle", "DestAddr", "Flags"]),
        # 
        'QOSEnumerateFlows': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["QOSHandle", "Size", "Buffer"]),
        # 
        'QOSAddSocketToFlow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimStruct({"sa_family": SimTypeShort(signed=False, label="UInt16"), "sa_data": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 14)}, name="SOCKADDR", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="QOS_TRAFFIC_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["QOSHandle", "Socket", "DestAddr", "TrafficType", "Flags", "FlowId"]),
        # 
        'QOSRemoveSocketFromFlow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["QOSHandle", "Socket", "FlowId", "Flags"]),
        # 
        'QOSSetFlow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="QOS_SET_FLOW"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Internal": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "InternalHigh": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "Anonymous": SimUnion({"Anonymous": SimStruct({"Offset": SimTypeInt(signed=False, label="UInt32"), "OffsetHigh": SimTypeInt(signed=False, label="UInt32")}, name="_Anonymous_e__Struct", pack=False, align=None), "Pointer": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), "hEvent": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="OVERLAPPED", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["QOSHandle", "FlowId", "Operation", "Size", "Buffer", "Flags", "Overlapped"]),
        # 
        'QOSQueryFlow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="QOS_QUERY_FLOW"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Internal": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "InternalHigh": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "Anonymous": SimUnion({"Anonymous": SimStruct({"Offset": SimTypeInt(signed=False, label="UInt32"), "OffsetHigh": SimTypeInt(signed=False, label="UInt32")}, name="_Anonymous_e__Struct", pack=False, align=None), "Pointer": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), "hEvent": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="OVERLAPPED", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["QOSHandle", "FlowId", "Operation", "Size", "Buffer", "Flags", "Overlapped"]),
        # 
        'QOSNotifyFlow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="QOS_NOTIFY_FLOW"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Internal": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "InternalHigh": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "Anonymous": SimUnion({"Anonymous": SimStruct({"Offset": SimTypeInt(signed=False, label="UInt32"), "OffsetHigh": SimTypeInt(signed=False, label="UInt32")}, name="_Anonymous_e__Struct", pack=False, align=None), "Pointer": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), "hEvent": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="OVERLAPPED", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["QOSHandle", "FlowId", "Operation", "Size", "Buffer", "Flags", "Overlapped"]),
        # 
        'QOSCancel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"Internal": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "InternalHigh": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "Anonymous": SimUnion({"Anonymous": SimStruct({"Offset": SimTypeInt(signed=False, label="UInt32"), "OffsetHigh": SimTypeInt(signed=False, label="UInt32")}, name="_Anonymous_e__Struct", pack=False, align=None), "Pointer": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), "hEvent": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="OVERLAPPED", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["QOSHandle", "Overlapped"]),
    }

lib.set_prototypes(prototypes)
