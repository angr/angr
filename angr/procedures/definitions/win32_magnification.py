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
lib.set_library_names("magnification.dll")
prototypes = \
    {
        #
        'MagInitialize': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'MagUninitialize': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'MagSetWindowSource': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "rect"]),
        #
        'MagGetWindowSource': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pRect"]),
        #
        'MagSetWindowTransform': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"v": SimTypeFixedSizeArray(SimTypeFloat(size=32), 9)}, name="MAGTRANSFORM", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pTransform"]),
        #
        'MagGetWindowTransform': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"v": SimTypeFixedSizeArray(SimTypeFloat(size=32), 9)}, name="MAGTRANSFORM", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pTransform"]),
        #
        'MagSetWindowFilterList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "dwFilterMode", "count", "pHWND"]),
        #
        'MagGetWindowFilterList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pdwFilterMode", "count", "pHWND"]),
        #
        'MagSetImageScalingCallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimStruct({"width": SimTypeInt(signed=False, label="UInt32"), "height": SimTypeInt(signed=False, label="UInt32"), "format": SimTypeBottom(label="Guid"), "stride": SimTypeInt(signed=False, label="UInt32"), "offset": SimTypeInt(signed=False, label="UInt32"), "cbSize": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="MAGIMAGEHEADER", pack=False, align=None), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimStruct({"width": SimTypeInt(signed=False, label="UInt32"), "height": SimTypeInt(signed=False, label="UInt32"), "format": SimTypeBottom(label="Guid"), "stride": SimTypeInt(signed=False, label="UInt32"), "offset": SimTypeInt(signed=False, label="UInt32"), "cbSize": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="MAGIMAGEHEADER", pack=False, align=None), SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "srcdata", "srcheader", "destdata", "destheader", "unclipped", "clipped", "dirty"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "callback"]),
        #
        'MagGetImageScalingCallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimStruct({"width": SimTypeInt(signed=False, label="UInt32"), "height": SimTypeInt(signed=False, label="UInt32"), "format": SimTypeBottom(label="Guid"), "stride": SimTypeInt(signed=False, label="UInt32"), "offset": SimTypeInt(signed=False, label="UInt32"), "cbSize": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="MAGIMAGEHEADER", pack=False, align=None), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimStruct({"width": SimTypeInt(signed=False, label="UInt32"), "height": SimTypeInt(signed=False, label="UInt32"), "format": SimTypeBottom(label="Guid"), "stride": SimTypeInt(signed=False, label="UInt32"), "offset": SimTypeInt(signed=False, label="UInt32"), "cbSize": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="MAGIMAGEHEADER", pack=False, align=None), SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "srcdata", "srcheader", "destdata", "destheader", "unclipped", "clipped", "dirty"]), offset=0), arg_names=["hwnd"]),
        #
        'MagSetColorEffect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"transform": SimTypeFixedSizeArray(SimTypeFloat(size=32), 25)}, name="MAGCOLOREFFECT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pEffect"]),
        #
        'MagGetColorEffect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"transform": SimTypeFixedSizeArray(SimTypeFloat(size=32), 25)}, name="MAGCOLOREFFECT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pEffect"]),
        #
        'MagSetFullscreenTransform': SimTypeFunction([SimTypeFloat(size=32), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["magLevel", "xOffset", "yOffset"]),
        #
        'MagGetFullscreenTransform': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMagLevel", "pxOffset", "pyOffset"]),
        #
        'MagSetFullscreenColorEffect': SimTypeFunction([SimTypePointer(SimStruct({"transform": SimTypeFixedSizeArray(SimTypeFloat(size=32), 25)}, name="MAGCOLOREFFECT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pEffect"]),
        #
        'MagGetFullscreenColorEffect': SimTypeFunction([SimTypePointer(SimStruct({"transform": SimTypeFixedSizeArray(SimTypeFloat(size=32), 25)}, name="MAGCOLOREFFECT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pEffect"]),
        #
        'MagSetInputTransform': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fEnabled", "pRectSource", "pRectDest"]),
        #
        'MagGetInputTransform': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfEnabled", "pRectSource", "pRectDest"]),
        #
        'MagShowSystemCursor': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fShowCursor"]),
    }

lib.set_prototypes(prototypes)
