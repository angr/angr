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
lib.set_library_names("msvfw32.dll")
prototypes = \
    {
        #
        'VideoForWindowsVersion': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'ICInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ICINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fccType", "fccHandler", "lpicinfo"]),
        #
        'ICInstall': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fccType", "fccHandler", "lParam", "szDesc", "wFlags"]),
        #
        'ICRemove': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fccType", "fccHandler", "wFlags"]),
        #
        'ICGetInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("ICINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hic", "picinfo", "cb"]),
        #
        'ICOpen': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["fccType", "fccHandler", "wMode"]),
        #
        'ICOpenFunction': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["fccType", "fccHandler", "wMode", "lpfnHandler"]),
        #
        'ICClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hic"]),
        #
        'ICSendMessage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hic", "msg", "dw1", "dw2"]),
        #
        'ICCompress': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hic", "dwFlags", "lpbiOutput", "lpData", "lpbiInput", "lpBits", "lpckid", "lpdwFlags", "lFrameNum", "dwFrameSize", "dwQuality", "lpbiPrev", "lpPrev"]),
        #
        'ICDecompress': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hic", "dwFlags", "lpbiFormat", "lpData", "lpbi", "lpBits"]),
        #
        'ICDrawBegin': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hic", "dwFlags", "hpal", "hwnd", "hdc", "xDst", "yDst", "dxDst", "dyDst", "lpbi", "xSrc", "ySrc", "dxSrc", "dySrc", "dwRate", "dwScale"]),
        #
        'ICDraw': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hic", "dwFlags", "lpFormat", "lpData", "cbData", "lTime"]),
        #
        'ICLocate': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["fccType", "fccHandler", "lpbiIn", "lpbiOut", "wFlags"]),
        #
        'ICGetDisplayFormat': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hic", "lpbiIn", "lpbiOut", "BitDepth", "dx", "dy"]),
        #
        'ICImageCompress': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BITMAPINFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("BITMAPINFO", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hic", "uiFlags", "lpbiIn", "lpBits", "lpbiOut", "lQuality", "plSize"]),
        #
        'ICImageDecompress': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BITMAPINFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("BITMAPINFO", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hic", "uiFlags", "lpbiIn", "lpBits", "lpbiOut"]),
        #
        'ICCompressorChoose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("COMPVARS", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "uiFlags", "pvIn", "lpData", "pc", "lpszTitle"]),
        #
        'ICSeqCompressFrameStart': SimTypeFunction([SimTypePointer(SimTypeRef("COMPVARS", SimStruct), offset=0), SimTypePointer(SimTypeRef("BITMAPINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pc", "lpbiIn"]),
        #
        'ICSeqCompressFrameEnd': SimTypeFunction([SimTypePointer(SimTypeRef("COMPVARS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pc"]),
        #
        'ICSeqCompressFrame': SimTypeFunction([SimTypePointer(SimTypeRef("COMPVARS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pc", "uiFlags", "lpBits", "pfKey", "plSize"]),
        #
        'ICCompressorFree': SimTypeFunction([SimTypePointer(SimTypeRef("COMPVARS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pc"]),
        #
        'DrawDibOpen': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'DrawDibClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdd"]),
        #
        'DrawDibGetBuffer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hdd", "lpbi", "dwSize", "dwFlags"]),
        #
        'DrawDibGetPalette': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdd"]),
        #
        'DrawDibSetPalette': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdd", "hpal"]),
        #
        'DrawDibChangePalette': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("PALETTEENTRY", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdd", "iStart", "iLen", "lppe"]),
        #
        'DrawDibRealize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdd", "hdc", "fBackground"]),
        #
        'DrawDibStart': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdd", "rate"]),
        #
        'DrawDibStop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdd"]),
        #
        'DrawDibBegin': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdd", "hdc", "dxDst", "dyDst", "lpbi", "dxSrc", "dySrc", "wFlags"]),
        #
        'DrawDibDraw': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdd", "hdc", "xDst", "yDst", "dxDst", "dyDst", "lpbi", "lpBits", "xSrc", "ySrc", "dxSrc", "dySrc", "wFlags"]),
        #
        'DrawDibEnd': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdd"]),
        #
        'DrawDibTime': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DRAWDIBTIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdd", "lpddtime"]),
        #
        'DrawDibProfileDisplay': SimTypeFunction([SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpbi"]),
        #
        'MCIWndCreateA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwndParent", "hInstance", "dwStyle", "szFile"]),
        #
        'MCIWndCreateW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwndParent", "hInstance", "dwStyle", "szFile"]),
        #
        'MCIWndRegisterClass': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'GetOpenFileNamePreviewA': SimTypeFunction([SimTypePointer(SimTypeRef("OPENFILENAMEA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpofn"]),
        #
        'GetSaveFileNamePreviewA': SimTypeFunction([SimTypePointer(SimTypeRef("OPENFILENAMEA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpofn"]),
        #
        'GetOpenFileNamePreviewW': SimTypeFunction([SimTypePointer(SimTypeRef("OPENFILENAMEW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpofn"]),
        #
        'GetSaveFileNamePreviewW': SimTypeFunction([SimTypePointer(SimTypeRef("OPENFILENAMEW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpofn"]),
    }

lib.set_prototypes(prototypes)
