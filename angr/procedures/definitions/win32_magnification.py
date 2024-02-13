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
lib.set_library_names("magnification.dll")
prototypes = \
    {
        #
        'MagInitialize': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'MagUninitialize': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'MagSetWindowSource': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("RECT", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "rect"]),
        #
        'MagGetWindowSource': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pRect"]),
        #
        'MagSetWindowTransform': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MAGTRANSFORM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pTransform"]),
        #
        'MagGetWindowTransform': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MAGTRANSFORM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pTransform"]),
        #
        'MagSetWindowFilterList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MW_FILTERMODE"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "dwFilterMode", "count", "pHWND"]),
        #
        'MagGetWindowFilterList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="MW_FILTERMODE"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pdwFilterMode", "count", "pHWND"]),
        #
        'MagSetImageScalingCallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeRef("MAGIMAGEHEADER", SimStruct), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeRef("MAGIMAGEHEADER", SimStruct), SimTypeRef("RECT", SimStruct), SimTypeRef("RECT", SimStruct), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "srcdata", "srcheader", "destdata", "destheader", "unclipped", "clipped", "dirty"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "callback"]),
        #
        'MagGetImageScalingCallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeRef("MAGIMAGEHEADER", SimStruct), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeRef("MAGIMAGEHEADER", SimStruct), SimTypeRef("RECT", SimStruct), SimTypeRef("RECT", SimStruct), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "srcdata", "srcheader", "destdata", "destheader", "unclipped", "clipped", "dirty"]), offset=0), arg_names=["hwnd"]),
        #
        'MagSetColorEffect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MAGCOLOREFFECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pEffect"]),
        #
        'MagGetColorEffect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MAGCOLOREFFECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pEffect"]),
        #
        'MagSetFullscreenTransform': SimTypeFunction([SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["magLevel", "xOffset", "yOffset"]),
        #
        'MagGetFullscreenTransform': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMagLevel", "pxOffset", "pyOffset"]),
        #
        'MagSetFullscreenColorEffect': SimTypeFunction([SimTypePointer(SimTypeRef("MAGCOLOREFFECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pEffect"]),
        #
        'MagGetFullscreenColorEffect': SimTypeFunction([SimTypePointer(SimTypeRef("MAGCOLOREFFECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pEffect"]),
        #
        'MagSetInputTransform': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fEnabled", "pRectSource", "pRectDest"]),
        #
        'MagGetInputTransform': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfEnabled", "pRectSource", "pRectDest"]),
        #
        'MagShowSystemCursor': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fShowCursor"]),
    }

lib.set_prototypes(prototypes)
