# pylint:disable=line-too-long
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
lib.set_library_names("dciman32.dll")
prototypes = \
    {
        #
        'DCIOpenProvider': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'DCICloseProvider': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hdc"]),
        #
        'DCICreatePrimary': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DCISURFACEINFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lplpSurface"]),
        #
        'DCICreateOffscreen': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DCIOFFSCREEN", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "dwCompression", "dwRedMask", "dwGreenMask", "dwBlueMask", "dwWidth", "dwHeight", "dwDCICaps", "dwBitCount", "lplpSurface"]),
        #
        'DCICreateOverlay': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DCIOVERLAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpOffscreenSurf", "lplpSurface"]),
        #
        'DCIEnum': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lprDst", "lprSrc", "lpFnCallback", "lpContext"]),
        #
        'DCISetSrcDestClip': SimTypeFunction([SimTypePointer(SimTypeRef("DCIOFFSCREEN", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RGNDATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdci", "srcrc", "destrc", "prd"]),
        #
        'WinWatchOpen': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd"]),
        #
        'WinWatchClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hWW"]),
        #
        'WinWatchGetClipList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RGNDATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWW", "prc", "size", "prd"]),
        #
        'WinWatchDidStatusChange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWW"]),
        #
        'GetWindowRegionData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RGNDATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwnd", "size", "prd"]),
        #
        'GetDCRegionData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RGNDATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "size", "prd"]),
        #
        'WinWatchNotify': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hww", "hwnd", "code", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWW", "NotifyCallback", "NotifyParam"]),
        #
        'DCIEndAccess': SimTypeFunction([SimTypePointer(SimTypeRef("DCISURFACEINFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pdci"]),
        #
        'DCIBeginAccess': SimTypeFunction([SimTypePointer(SimTypeRef("DCISURFACEINFO", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pdci", "x", "y", "dx", "dy"]),
        #
        'DCIDestroy': SimTypeFunction([SimTypePointer(SimTypeRef("DCISURFACEINFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pdci"]),
        #
        'DCIDraw': SimTypeFunction([SimTypePointer(SimTypeRef("DCIOFFSCREEN", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdci"]),
        #
        'DCISetClipList': SimTypeFunction([SimTypePointer(SimTypeRef("DCIOFFSCREEN", SimStruct), offset=0), SimTypePointer(SimTypeRef("RGNDATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdci", "prd"]),
        #
        'DCISetDestination': SimTypeFunction([SimTypePointer(SimTypeRef("DCIOFFSCREEN", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdci", "dst", "src"]),
    }

lib.set_prototypes(prototypes)
