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
lib.set_library_names("api-ms-win-shcore-scaling-l1-1-1.dll")
prototypes = \
    {
        #
        'SetProcessDpiAwareness': SimTypeFunction([SimTypeInt(signed=False, label="PROCESS_DPI_AWARENESS")], SimTypeInt(signed=True, label="Int32"), arg_names=["value"]),
        #
        'GetProcessDpiAwareness': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="PROCESS_DPI_AWARENESS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hprocess", "value"]),
        #
        'GetDpiForMonitor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MONITOR_DPI_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hmonitor", "dpiType", "dpiX", "dpiY"]),
        #
        'GetScaleFactorForMonitor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="DEVICE_SCALE_FACTOR"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMon", "pScale"]),
        #
        'RegisterScaleChangeEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent", "pdwCookie"]),
        #
        'UnregisterScaleChangeEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwCookie"]),
    }

lib.set_prototypes(prototypes)
