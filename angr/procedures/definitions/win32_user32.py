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
import archinfo
from ...calling_conventions import SimCCCdecl

lib.add_all_from_dict(P['win_user32'])
lib.add('wsprintfA', P['libc']['sprintf'], cc=SimCCCdecl(archinfo.ArchX86()))
lib.set_library_names("user32.dll")
prototypes = \
    {
        #
        'GetDisplayConfigBufferSizes': SimTypeFunction([SimTypeInt(signed=False, label="QUERY_DISPLAY_CONFIG_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["flags", "numPathArrayElements", "numModeInfoArrayElements"]),
        #
        'SetDisplayConfig': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DISPLAYCONFIG_PATH_INFO", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DISPLAYCONFIG_MODE_INFO", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="SET_DISPLAY_CONFIG_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["numPathArrayElements", "pathArray", "numModeInfoArrayElements", "modeInfoArray", "flags"]),
        #
        'QueryDisplayConfig': SimTypeFunction([SimTypeInt(signed=False, label="QUERY_DISPLAY_CONFIG_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("DISPLAYCONFIG_PATH_INFO", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("DISPLAYCONFIG_MODE_INFO", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="DISPLAYCONFIG_TOPOLOGY_ID"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["flags", "numPathArrayElements", "pathArray", "numModeInfoArrayElements", "modeInfoArray", "currentTopologyId"]),
        #
        'DisplayConfigGetDeviceInfo': SimTypeFunction([SimTypePointer(SimTypeRef("DISPLAYCONFIG_DEVICE_INFO_HEADER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["requestPacket"]),
        #
        'DisplayConfigSetDeviceInfo': SimTypeFunction([SimTypePointer(SimTypeRef("DISPLAYCONFIG_DEVICE_INFO_HEADER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["setPacket"]),
        #
        'GetAutoRotationState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="AR_STATE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pState"]),
        #
        'GetDisplayAutoRotationPreferences': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="ORIENTATION_PREFERENCE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pOrientation"]),
        #
        'SetDisplayAutoRotationPreferences': SimTypeFunction([SimTypeInt(signed=False, label="ORIENTATION_PREFERENCE")], SimTypeInt(signed=True, label="Int32"), arg_names=["orientation"]),
        #
        'SetLastErrorEx': SimTypeFunction([SimTypeInt(signed=False, label="WIN32_ERROR"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwErrCode", "dwType"]),
        #
        'DrawEdge': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="DRAWEDGE_FLAGS"), SimTypeInt(signed=False, label="DRAW_EDGE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "qrc", "edge", "grfFlags"]),
        #
        'DrawFrameControl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="DFC_TYPE"), SimTypeInt(signed=False, label="DFCS_STATE")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'DrawCaption': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="DRAW_CAPTION_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "hdc", "lprect", "flags"]),
        #
        'DrawAnimatedRects': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "idAni", "lprcFrom", "lprcTo"]),
        #
        'DrawTextA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="DRAW_TEXT_FORMAT")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpchText", "cchText", "lprc", "format"]),
        #
        'DrawTextW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="DRAW_TEXT_FORMAT")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpchText", "cchText", "lprc", "format"]),
        #
        'DrawTextExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="DRAW_TEXT_FORMAT"), SimTypePointer(SimTypeRef("DRAWTEXTPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpchText", "cchText", "lprc", "format", "lpdtp"]),
        #
        'DrawTextExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="DRAW_TEXT_FORMAT"), SimTypePointer(SimTypeRef("DRAWTEXTPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpchText", "cchText", "lprc", "format", "lpdtp"]),
        #
        'GrayStringA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "hBrush", "lpOutputFunc", "lpData", "nCount", "X", "Y", "nWidth", "nHeight"]),
        #
        'GrayStringW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "hBrush", "lpOutputFunc", "lpData", "nCount", "X", "Y", "nWidth", "nHeight"]),
        #
        'DrawStateA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lData", "wData", "cx", "cy"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="DRAWSTATE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hbrFore", "qfnCallBack", "lData", "wData", "x", "y", "cx", "cy", "uFlags"]),
        #
        'DrawStateW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lData", "wData", "cx", "cy"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="DRAWSTATE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "hbrFore", "qfnCallBack", "lData", "wData", "x", "y", "cx", "cy", "uFlags"]),
        #
        'TabbedTextOutA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "lpString", "chCount", "nTabPositions", "lpnTabStopPositions", "nTabOrigin"]),
        #
        'TabbedTextOutW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "x", "y", "lpString", "chCount", "nTabPositions", "lpnTabStopPositions", "nTabOrigin"]),
        #
        'GetTabbedTextExtentA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "lpString", "chCount", "nTabPositions", "lpnTabStopPositions"]),
        #
        'GetTabbedTextExtentW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "lpString", "chCount", "nTabPositions", "lpnTabStopPositions"]),
        #
        'UpdateWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'PaintDesktop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc"]),
        #
        'WindowFromDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hDC"]),
        #
        'GetDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd"]),
        #
        'GetDCEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_DCX_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "hrgnClip", "flags"]),
        #
        'GetWindowDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd"]),
        #
        'ReleaseDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "hDC"]),
        #
        'BeginPaint': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PAINTSTRUCT", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "lpPaint"]),
        #
        'EndPaint': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PAINTSTRUCT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpPaint"]),
        #
        'GetUpdateRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpRect", "bErase"]),
        #
        'GetUpdateRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="GDI_REGION_TYPE"), arg_names=["hWnd", "hRgn", "bErase"]),
        #
        'SetWindowRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "hRgn", "bRedraw"]),
        #
        'GetWindowRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="GDI_REGION_TYPE"), arg_names=["hWnd", "hRgn"]),
        #
        'GetWindowRgnBox': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=False, label="GDI_REGION_TYPE"), arg_names=["hWnd", "lprc"]),
        #
        'ExcludeUpdateRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "hWnd"]),
        #
        'InvalidateRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpRect", "bErase"]),
        #
        'ValidateRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpRect"]),
        #
        'InvalidateRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "hRgn", "bErase"]),
        #
        'ValidateRgn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "hRgn"]),
        #
        'RedrawWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="REDRAW_WINDOW_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lprcUpdate", "hrgnUpdate", "flags"]),
        #
        'LockWindowUpdate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWndLock"]),
        #
        'ClientToScreen': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpPoint"]),
        #
        'ScreenToClient': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpPoint"]),
        #
        'MapWindowPoints': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWndFrom", "hWndTo", "lpPoints", "cPoints"]),
        #
        'GetSysColor': SimTypeFunction([SimTypeInt(signed=False, label="SYS_COLOR_INDEX")], SimTypeInt(signed=False, label="UInt32"), arg_names=["nIndex"]),
        #
        'GetSysColorBrush': SimTypeFunction([SimTypeInt(signed=False, label="SYS_COLOR_INDEX")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["nIndex"]),
        #
        'SetSysColors': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cElements", "lpaElements", "lpaRgbValues"]),
        #
        'DrawFocusRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "lprc"]),
        #
        'FillRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "lprc", "hbr"]),
        #
        'FrameRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "lprc", "hbr"]),
        #
        'InvertRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "lprc"]),
        #
        'SetRect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lprc", "xLeft", "yTop", "xRight", "yBottom"]),
        #
        'SetRectEmpty': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lprc"]),
        #
        'CopyRect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lprcDst", "lprcSrc"]),
        #
        'InflateRect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lprc", "dx", "dy"]),
        #
        'IntersectRect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lprcDst", "lprcSrc1", "lprcSrc2"]),
        #
        'UnionRect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lprcDst", "lprcSrc1", "lprcSrc2"]),
        #
        'SubtractRect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lprcDst", "lprcSrc1", "lprcSrc2"]),
        #
        'OffsetRect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lprc", "dx", "dy"]),
        #
        'IsRectEmpty': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lprc"]),
        #
        'EqualRect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lprc1", "lprc2"]),
        #
        'PtInRect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeRef("POINT", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["lprc", "pt"]),
        #
        'LoadBitmapA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpBitmapName"]),
        #
        'LoadBitmapW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpBitmapName"]),
        #
        'ChangeDisplaySettingsA': SimTypeFunction([SimTypePointer(SimTypeRef("DEVMODEA", SimStruct), offset=0), SimTypeInt(signed=False, label="CDS_TYPE")], SimTypeInt(signed=False, label="DISP_CHANGE"), arg_names=["lpDevMode", "dwFlags"]),
        #
        'ChangeDisplaySettingsW': SimTypeFunction([SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0), SimTypeInt(signed=False, label="CDS_TYPE")], SimTypeInt(signed=False, label="DISP_CHANGE"), arg_names=["lpDevMode", "dwFlags"]),
        #
        'ChangeDisplaySettingsExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("DEVMODEA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CDS_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="DISP_CHANGE"), arg_names=["lpszDeviceName", "lpDevMode", "hwnd", "dwflags", "lParam"]),
        #
        'ChangeDisplaySettingsExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CDS_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="DISP_CHANGE"), arg_names=["lpszDeviceName", "lpDevMode", "hwnd", "dwflags", "lParam"]),
        #
        'EnumDisplaySettingsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="ENUM_DISPLAY_SETTINGS_MODE"), SimTypePointer(SimTypeRef("DEVMODEA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszDeviceName", "iModeNum", "lpDevMode"]),
        #
        'EnumDisplaySettingsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="ENUM_DISPLAY_SETTINGS_MODE"), SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszDeviceName", "iModeNum", "lpDevMode"]),
        #
        'EnumDisplaySettingsExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="ENUM_DISPLAY_SETTINGS_MODE"), SimTypePointer(SimTypeRef("DEVMODEA", SimStruct), offset=0), SimTypeInt(signed=False, label="ENUM_DISPLAY_SETTINGS_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszDeviceName", "iModeNum", "lpDevMode", "dwFlags"]),
        #
        'EnumDisplaySettingsExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="ENUM_DISPLAY_SETTINGS_MODE"), SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0), SimTypeInt(signed=False, label="ENUM_DISPLAY_SETTINGS_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszDeviceName", "iModeNum", "lpDevMode", "dwFlags"]),
        #
        'EnumDisplayDevicesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DISPLAY_DEVICEA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDevice", "iDevNum", "lpDisplayDevice", "dwFlags"]),
        #
        'EnumDisplayDevicesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DISPLAY_DEVICEW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDevice", "iDevNum", "lpDisplayDevice", "dwFlags"]),
        #
        'MonitorFromPoint': SimTypeFunction([SimTypeRef("POINT", SimStruct), SimTypeInt(signed=False, label="MONITOR_FROM_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pt", "dwFlags"]),
        #
        'MonitorFromRect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="MONITOR_FROM_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lprc", "dwFlags"]),
        #
        'MonitorFromWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MONITOR_FROM_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd", "dwFlags"]),
        #
        'GetMonitorInfoA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MONITORINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "lpmi"]),
        #
        'GetMonitorInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MONITORINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "lpmi"]),
        #
        'EnumDisplayMonitors': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lprcClip", "lpfnEnum", "dwData"]),
        #
        'SetUserObjectSecurity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="OBJECT_SECURITY_INFORMATION"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hObj", "pSIRequested", "pSID"]),
        #
        'GetUserObjectSecurity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hObj", "pSIRequested", "pSID", "nLength", "lpnLengthNeeded"]),
        #
        'PrintWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PRINT_WINDOW_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "hdcBlt", "nFlags"]),
        #
        'ConsoleControl': SimTypeFunction([SimTypeInt(signed=False, label="CONSOLECONTROL"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Command", "ConsoleInformation", "ConsoleInformationLength"]),
        #
        'DdeSetQualityOfService': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SECURITY_QUALITY_OF_SERVICE", SimStruct), offset=0), SimTypePointer(SimTypeRef("SECURITY_QUALITY_OF_SERVICE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndClient", "pqosNew", "pqosPrev"]),
        #
        'ImpersonateDdeClientWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWndClient", "hWndServer"]),
        #
        'PackDDElParam': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["msg", "uiLo", "uiHi"]),
        #
        'UnpackDDElParam': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["msg", "lParam", "puiLo", "puiHi"]),
        #
        'FreeDDElParam': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["msg", "lParam"]),
        #
        'ReuseDDElParam': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lParam", "msgIn", "msgOut", "uiLo", "uiHi"]),
        #
        'DdeInitializeA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["wType", "wFmt", "hConv", "hsz1", "hsz2", "hData", "dwData1", "dwData2"]), offset=0), SimTypeInt(signed=False, label="DDE_INITIALIZE_COMMAND"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pidInst", "pfnCallback", "afCmd", "ulRes"]),
        #
        'DdeInitializeW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["wType", "wFmt", "hConv", "hsz1", "hsz2", "hData", "dwData1", "dwData2"]), offset=0), SimTypeInt(signed=False, label="DDE_INITIALIZE_COMMAND"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pidInst", "pfnCallback", "afCmd", "ulRes"]),
        #
        'DdeUninitialize': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["idInst"]),
        #
        'DdeConnectList': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CONVCONTEXT", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["idInst", "hszService", "hszTopic", "hConvList", "pCC"]),
        #
        'DdeQueryNextServer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hConvList", "hConvPrev"]),
        #
        'DdeDisconnectList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConvList"]),
        #
        'DdeConnect': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CONVCONTEXT", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["idInst", "hszService", "hszTopic", "pCC"]),
        #
        'DdeDisconnect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConv"]),
        #
        'DdeReconnect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hConv"]),
        #
        'DdeQueryConvInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CONVINFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hConv", "idTransaction", "pConvInfo"]),
        #
        'DdeSetUserHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConv", "id", "hUser"]),
        #
        'DdeAbandonTransaction': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["idInst", "hConv", "idTransaction"]),
        #
        'DdePostAdvise': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idInst", "hszTopic", "hszItem"]),
        #
        'DdeEnableCallback': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DDE_ENABLE_CALLBACK_CMD")], SimTypeInt(signed=True, label="Int32"), arg_names=["idInst", "hConv", "wCmd"]),
        #
        'DdeImpersonateClient': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConv"]),
        #
        'DdeNameService': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DDE_NAME_SERVICE_CMD")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["idInst", "hsz1", "hsz2", "afCmd"]),
        #
        'DdeClientTransaction': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DDE_CLIENT_TRANSACTION_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pData", "cbData", "hConv", "hszItem", "wFmt", "wType", "dwTimeout", "pdwResult"]),
        #
        'DdeCreateDataHandle': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["idInst", "pSrc", "cb", "cbOff", "hszItem", "wFmt", "afCmd"]),
        #
        'DdeAddData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hData", "pSrc", "cb", "cbOff"]),
        #
        'DdeGetData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hData", "pDst", "cbMax", "cbOff"]),
        #
        'DdeAccessData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["hData", "pcbDataSize"]),
        #
        'DdeUnaccessData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hData"]),
        #
        'DdeFreeDataHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hData"]),
        #
        'DdeGetLastError': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["idInst"]),
        #
        'DdeCreateStringHandleA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["idInst", "psz", "iCodePage"]),
        #
        'DdeCreateStringHandleW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["idInst", "psz", "iCodePage"]),
        #
        'DdeQueryStringA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["idInst", "hsz", "psz", "cchMax", "iCodePage"]),
        #
        'DdeQueryStringW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["idInst", "hsz", "psz", "cchMax", "iCodePage"]),
        #
        'DdeFreeStringHandle': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idInst", "hsz"]),
        #
        'DdeKeepStringHandle': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idInst", "hsz"]),
        #
        'DdeCmpStringHandles': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hsz1", "hsz2"]),
        #
        'OpenClipboard': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWndNewOwner"]),
        #
        'CloseClipboard': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'GetClipboardSequenceNumber': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'GetClipboardOwner': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'SetClipboardViewer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWndNewViewer"]),
        #
        'GetClipboardViewer': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'ChangeClipboardChain': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWndRemove", "hWndNewNext"]),
        #
        'SetClipboardData': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["uFormat", "hMem"]),
        #
        'GetClipboardData': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["uFormat"]),
        #
        'RegisterClipboardFormatA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszFormat"]),
        #
        'RegisterClipboardFormatW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszFormat"]),
        #
        'CountClipboardFormats': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'EnumClipboardFormats': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["format"]),
        #
        'GetClipboardFormatNameA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["format", "lpszFormatName", "cchMaxCount"]),
        #
        'GetClipboardFormatNameW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["format", "lpszFormatName", "cchMaxCount"]),
        #
        'EmptyClipboard': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'IsClipboardFormatAvailable': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["format"]),
        #
        'GetPriorityClipboardFormat': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["paFormatPriorityList", "cFormats"]),
        #
        'GetOpenClipboardWindow': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'AddClipboardFormatListener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'RemoveClipboardFormatListener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'GetUpdatedClipboardFormats': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpuiFormats", "cFormats", "pcFormatsOut"]),
        #
        'MessageBeep': SimTypeFunction([SimTypeInt(signed=False, label="MESSAGEBOX_STYLE")], SimTypeInt(signed=True, label="Int32"), arg_names=["uType"]),
        #
        'UserHandleGrantAccess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUserHandle", "hJob", "bGrant"]),
        #
        'RegisterPowerSettingNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="REGISTER_NOTIFICATION_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hRecipient", "PowerSettingGuid", "Flags"]),
        #
        'UnregisterPowerSettingNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle"]),
        #
        'RegisterSuspendResumeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="REGISTER_NOTIFICATION_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hRecipient", "Flags"]),
        #
        'UnregisterSuspendResumeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle"]),
        #
        'ExitWindowsEx': SimTypeFunction([SimTypeInt(signed=False, label="EXIT_WINDOWS_FLAGS"), SimTypeInt(signed=False, label="SHUTDOWN_REASON")], SimTypeInt(signed=True, label="Int32"), arg_names=["uFlags", "dwReason"]),
        #
        'LockWorkStation': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'ShutdownBlockReasonCreate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "pwszReason"]),
        #
        'ShutdownBlockReasonQuery': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "pwszBuff", "pcchBuff"]),
        #
        'ShutdownBlockReasonDestroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'CreateDesktopA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("DEVMODEA", SimStruct), offset=0), SimTypeInt(signed=False, label="DESKTOP_CONTROL_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszDesktop", "lpszDevice", "pDevmode", "dwFlags", "dwDesiredAccess", "lpsa"]),
        #
        'CreateDesktopW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0), SimTypeInt(signed=False, label="DESKTOP_CONTROL_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszDesktop", "lpszDevice", "pDevmode", "dwFlags", "dwDesiredAccess", "lpsa"]),
        #
        'CreateDesktopExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("DEVMODEA", SimStruct), offset=0), SimTypeInt(signed=False, label="DESKTOP_CONTROL_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszDesktop", "lpszDevice", "pDevmode", "dwFlags", "dwDesiredAccess", "lpsa", "ulHeapSize", "pvoid"]),
        #
        'CreateDesktopExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0), SimTypeInt(signed=False, label="DESKTOP_CONTROL_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszDesktop", "lpszDevice", "pDevmode", "dwFlags", "dwDesiredAccess", "lpsa", "ulHeapSize", "pvoid"]),
        #
        'OpenDesktopA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="DESKTOP_CONTROL_FLAGS"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszDesktop", "dwFlags", "fInherit", "dwDesiredAccess"]),
        #
        'OpenDesktopW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="DESKTOP_CONTROL_FLAGS"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszDesktop", "dwFlags", "fInherit", "dwDesiredAccess"]),
        #
        'OpenInputDesktop': SimTypeFunction([SimTypeInt(signed=False, label="DESKTOP_CONTROL_FLAGS"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="DESKTOP_ACCESS_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwFlags", "fInherit", "dwDesiredAccess"]),
        #
        'EnumDesktopsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwinsta", "lpEnumFunc", "lParam"]),
        #
        'EnumDesktopsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwinsta", "lpEnumFunc", "lParam"]),
        #
        'EnumDesktopWindows': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDesktop", "lpfn", "lParam"]),
        #
        'SwitchDesktop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDesktop"]),
        #
        'SetThreadDesktop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDesktop"]),
        #
        'CloseDesktop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDesktop"]),
        #
        'GetThreadDesktop': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwThreadId"]),
        #
        'CreateWindowStationA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpwinsta", "dwFlags", "dwDesiredAccess", "lpsa"]),
        #
        'CreateWindowStationW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpwinsta", "dwFlags", "dwDesiredAccess", "lpsa"]),
        #
        'OpenWindowStationA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszWinSta", "fInherit", "dwDesiredAccess"]),
        #
        'OpenWindowStationW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszWinSta", "fInherit", "dwDesiredAccess"]),
        #
        'EnumWindowStationsA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpEnumFunc", "lParam"]),
        #
        'EnumWindowStationsW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpEnumFunc", "lParam"]),
        #
        'CloseWindowStation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWinSta"]),
        #
        'SetProcessWindowStation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWinSta"]),
        #
        'GetProcessWindowStation': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'GetUserObjectInformationA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="USER_OBJECT_INFORMATION_INDEX"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hObj", "nIndex", "pvInfo", "nLength", "lpnLengthNeeded"]),
        #
        'GetUserObjectInformationW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="USER_OBJECT_INFORMATION_INDEX"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hObj", "nIndex", "pvInfo", "nLength", "lpnLengthNeeded"]),
        #
        'SetUserObjectInformationA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hObj", "nIndex", "pvInfo", "nLength"]),
        #
        'SetUserObjectInformationW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hObj", "nIndex", "pvInfo", "nLength"]),
        #
        'BroadcastSystemMessageExA': SimTypeFunction([SimTypeInt(signed=False, label="BROADCAST_SYSTEM_MESSAGE_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="BROADCAST_SYSTEM_MESSAGE_INFO"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BSMINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "lpInfo", "Msg", "wParam", "lParam", "pbsmInfo"]),
        #
        'BroadcastSystemMessageExW': SimTypeFunction([SimTypeInt(signed=False, label="BROADCAST_SYSTEM_MESSAGE_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="BROADCAST_SYSTEM_MESSAGE_INFO"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BSMINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "lpInfo", "Msg", "wParam", "lParam", "pbsmInfo"]),
        #
        'BroadcastSystemMessageA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "lpInfo", "Msg", "wParam", "lParam"]),
        #
        'BroadcastSystemMessageW': SimTypeFunction([SimTypeInt(signed=False, label="BROADCAST_SYSTEM_MESSAGE_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="BROADCAST_SYSTEM_MESSAGE_INFO"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "lpInfo", "Msg", "wParam", "lParam"]),
        #
        'AttachThreadInput': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["idAttach", "idAttachTo", "fAttach"]),
        #
        'WaitForInputIdle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProcess", "dwMilliseconds"]),
        #
        'GetGuiResources': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_GUI_RESOURCES_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProcess", "uiFlags"]),
        #
        'IsImmersiveProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess"]),
        #
        'SetProcessRestrictionExemption': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fEnableExemption"]),
        #
        'SendIMEMessageExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1"]),
        #
        'SendIMEMessageExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1"]),
        #
        'IMPGetIMEA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IMEPROA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'IMPGetIMEW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IMEPROW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'IMPQueryIMEA': SimTypeFunction([SimTypePointer(SimTypeRef("IMEPROA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'IMPQueryIMEW': SimTypeFunction([SimTypePointer(SimTypeRef("IMEPROW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'IMPSetIMEA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IMEPROA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'IMPSetIMEW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IMEPROW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'WINNLSGetIMEHotkey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'WINNLSEnableIME': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'WINNLSGetEnableStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'RegisterPointerInputTarget': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POINTER_INPUT_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pointerType"]),
        #
        'UnregisterPointerInputTarget': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POINTER_INPUT_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pointerType"]),
        #
        'RegisterPointerInputTargetEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POINTER_INPUT_TYPE"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pointerType", "fObserve"]),
        #
        'UnregisterPointerInputTargetEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POINTER_INPUT_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pointerType"]),
        #
        'NotifyWinEvent': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["event", "hwnd", "idObject", "idChild"]),
        #
        'SetWinEventHook': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["hWinEventHook", "event", "hwnd", "idObject", "idChild", "idEventThread", "dwmsEventTime"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["eventMin", "eventMax", "hmodWinEventProc", "pfnWinEventProc", "idProcess", "idThread", "dwFlags"]),
        #
        'IsWinEventHookInstalled': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["event"]),
        #
        'UnhookWinEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWinEventHook"]),
        #
        'CheckDlgButton': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="DLG_BUTTON_CHECK_STATE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "nIDButton", "uCheck"]),
        #
        'CheckRadioButton': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "nIDFirstButton", "nIDLastButton", "nIDCheckButton"]),
        #
        'IsDlgButtonChecked': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDlg", "nIDButton"]),
        #
        'IsCharLowerW': SimTypeFunction([SimTypeChar(label="Char")], SimTypeInt(signed=True, label="Int32"), arg_names=["ch"]),
        #
        'CreateSyntheticPointerDevice': SimTypeFunction([SimTypeInt(signed=False, label="POINTER_INPUT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="POINTER_FEEDBACK_MODE")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pointerType", "maxCount", "mode"]),
        #
        'DestroySyntheticPointerDevice': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["device"]),
        #
        'RegisterTouchHitTestingWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "value"]),
        #
        'EvaluateProximityToRect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("TOUCH_HIT_TESTING_INPUT", SimStruct), offset=0), SimTypePointer(SimTypeRef("TOUCH_HIT_TESTING_PROXIMITY_EVALUATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["controlBoundingBox", "pHitTestingInput", "pProximityEval"]),
        #
        'EvaluateProximityToPolygon': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("TOUCH_HIT_TESTING_INPUT", SimStruct), offset=0), SimTypePointer(SimTypeRef("TOUCH_HIT_TESTING_PROXIMITY_EVALUATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["numVertices", "controlPolygon", "pHitTestingInput", "pProximityEval"]),
        #
        'PackTouchHitTestingProximityEvaluation': SimTypeFunction([SimTypePointer(SimTypeRef("TOUCH_HIT_TESTING_INPUT", SimStruct), offset=0), SimTypePointer(SimTypeRef("TOUCH_HIT_TESTING_PROXIMITY_EVALUATION", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pHitTestingInput", "pProximityEval"]),
        #
        'GetWindowFeedbackSetting': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="FEEDBACK_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "feedback", "dwFlags", "pSize", "config"]),
        #
        'SetWindowFeedbackSetting': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="FEEDBACK_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "feedback", "dwFlags", "size", "configuration"]),
        #
        'SetScrollPos': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SCROLLBAR_CONSTANTS"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "nBar", "nPos", "bRedraw"]),
        #
        'SetScrollRange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SCROLLBAR_CONSTANTS"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "nBar", "nMinPos", "nMaxPos", "bRedraw"]),
        #
        'ShowScrollBar': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SCROLLBAR_CONSTANTS"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "wBar", "bShow"]),
        #
        'EnableScrollBar': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ENABLE_SCROLL_BAR_ARROWS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "wSBflags", "wArrows"]),
        #
        'DlgDirListA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="DLG_DIR_LIST_FILE_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "lpPathSpec", "nIDListBox", "nIDStaticPath", "uFileType"]),
        #
        'DlgDirListW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="DLG_DIR_LIST_FILE_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "lpPathSpec", "nIDListBox", "nIDStaticPath", "uFileType"]),
        #
        'DlgDirSelectExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndDlg", "lpString", "chCount", "idListBox"]),
        #
        'DlgDirSelectExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndDlg", "lpString", "chCount", "idListBox"]),
        #
        'DlgDirListComboBoxA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="DLG_DIR_LIST_FILE_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "lpPathSpec", "nIDComboBox", "nIDStaticPath", "uFiletype"]),
        #
        'DlgDirListComboBoxW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="DLG_DIR_LIST_FILE_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "lpPathSpec", "nIDComboBox", "nIDStaticPath", "uFiletype"]),
        #
        'DlgDirSelectComboBoxExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndDlg", "lpString", "cchOut", "idComboBox"]),
        #
        'DlgDirSelectComboBoxExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndDlg", "lpString", "cchOut", "idComboBox"]),
        #
        'SetScrollInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SCROLLBAR_CONSTANTS"), SimTypePointer(SimTypeRef("SCROLLINFO", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "nBar", "lpsi", "redraw"]),
        #
        'GetComboBoxInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("COMBOBOXINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndCombo", "pcbi"]),
        #
        'GetListBoxInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwnd"]),
        #
        'RegisterPointerDeviceNotifications': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["window", "notifyRange"]),
        #
        'SetDialogControlDpiChangeBehavior': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DIALOG_CONTROL_DPI_CHANGE_BEHAVIORS"), SimTypeInt(signed=False, label="DIALOG_CONTROL_DPI_CHANGE_BEHAVIORS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "mask", "values"]),
        #
        'GetDialogControlDpiChangeBehavior': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="DIALOG_CONTROL_DPI_CHANGE_BEHAVIORS"), arg_names=["hWnd"]),
        #
        'SetDialogDpiChangeBehavior': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DIALOG_DPI_CHANGE_BEHAVIORS"), SimTypeInt(signed=False, label="DIALOG_DPI_CHANGE_BEHAVIORS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "mask", "values"]),
        #
        'GetDialogDpiChangeBehavior': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="DIALOG_DPI_CHANGE_BEHAVIORS"), arg_names=["hDlg"]),
        #
        'GetSystemMetricsForDpi': SimTypeFunction([SimTypeInt(signed=False, label="SYSTEM_METRICS_INDEX"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["nIndex", "dpi"]),
        #
        'AdjustWindowRectExForDpi': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="WINDOW_STYLE"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="WINDOW_EX_STYLE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpRect", "dwStyle", "bMenu", "dwExStyle", "dpi"]),
        #
        'LogicalToPhysicalPointForPerMonitorDPI': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpPoint"]),
        #
        'PhysicalToLogicalPointForPerMonitorDPI': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpPoint"]),
        #
        'SystemParametersInfoForDpi': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["uiAction", "uiParam", "pvParam", "fWinIni", "dpi"]),
        #
        'SetThreadDpiAwarenessContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dpiContext"]),
        #
        'GetThreadDpiAwarenessContext': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'GetWindowDpiAwarenessContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd"]),
        #
        'GetAwarenessFromDpiAwarenessContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="DPI_AWARENESS"), arg_names=["value"]),
        #
        'GetDpiFromDpiAwarenessContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["value"]),
        #
        'AreDpiAwarenessContextsEqual': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dpiContextA", "dpiContextB"]),
        #
        'IsValidDpiAwarenessContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["value"]),
        #
        'GetDpiForWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwnd"]),
        #
        'GetDpiForSystem': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'GetSystemDpiForProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProcess"]),
        #
        'EnableNonClientDpiScaling': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'SetProcessDpiAwarenessContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["value"]),
        #
        'GetDpiAwarenessContextForProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hProcess"]),
        #
        'SetThreadDpiHostingBehavior': SimTypeFunction([SimTypeInt(signed=False, label="DPI_HOSTING_BEHAVIOR")], SimTypeInt(signed=False, label="DPI_HOSTING_BEHAVIOR"), arg_names=["value"]),
        #
        'GetThreadDpiHostingBehavior': SimTypeFunction([], SimTypeInt(signed=False, label="DPI_HOSTING_BEHAVIOR")),
        #
        'GetWindowDpiHostingBehavior': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="DPI_HOSTING_BEHAVIOR"), arg_names=["hwnd"]),
        #
        'GetRawInputData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="RAW_INPUT_DATA_COMMAND_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRawInput", "uiCommand", "pData", "pcbSize", "cbSizeHeader"]),
        #
        'GetRawInputDeviceInfoA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="RAW_INPUT_DEVICE_INFO_COMMAND"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDevice", "uiCommand", "pData", "pcbSize"]),
        #
        'GetRawInputDeviceInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="RAW_INPUT_DEVICE_INFO_COMMAND"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDevice", "uiCommand", "pData", "pcbSize"]),
        #
        'GetRawInputBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("RAWINPUT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pData", "pcbSize", "cbSizeHeader"]),
        #
        'RegisterRawInputDevices': SimTypeFunction([SimTypePointer(SimTypeRef("RAWINPUTDEVICE", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pRawInputDevices", "uiNumDevices", "cbSize"]),
        #
        'GetRegisteredRawInputDevices': SimTypeFunction([SimTypePointer(SimTypeRef("RAWINPUTDEVICE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRawInputDevices", "puiNumDevices", "cbSize"]),
        #
        'GetRawInputDeviceList': SimTypeFunction([SimTypePointer(SimTypeRef("RAWINPUTDEVICELIST", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRawInputDeviceList", "puiNumDevices", "cbSize"]),
        #
        'DefRawInputProc': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("RAWINPUT", SimStruct), offset=0), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["paRawInput", "nInput", "cbSizeHeader"]),
        #
        'GetCurrentInputMessageSource': SimTypeFunction([SimTypePointer(SimTypeRef("INPUT_MESSAGE_SOURCE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["inputMessageSource"]),
        #
        'GetCIMSSM': SimTypeFunction([SimTypePointer(SimTypeRef("INPUT_MESSAGE_SOURCE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["inputMessageSource"]),
        #
        'LoadKeyboardLayoutA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="ACTIVATE_KEYBOARD_LAYOUT_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pwszKLID", "Flags"]),
        #
        'LoadKeyboardLayoutW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="ACTIVATE_KEYBOARD_LAYOUT_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pwszKLID", "Flags"]),
        #
        'ActivateKeyboardLayout': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ACTIVATE_KEYBOARD_LAYOUT_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hkl", "Flags"]),
        #
        'ToUnicodeEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["wVirtKey", "wScanCode", "lpKeyState", "pwszBuff", "cchBuff", "wFlags", "dwhkl"]),
        #
        'UnloadKeyboardLayout': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkl"]),
        #
        'GetKeyboardLayoutNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszKLID"]),
        #
        'GetKeyboardLayoutNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszKLID"]),
        #
        'GetKeyboardLayoutList': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nBuff", "lpList"]),
        #
        'GetKeyboardLayout': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["idThread"]),
        #
        'GetMouseMovePointsEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MOUSEMOVEPOINT", SimStruct), offset=0), SimTypePointer(SimTypeRef("MOUSEMOVEPOINT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="GET_MOUSE_MOVE_POINTS_EX_RESOLUTION")], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lppt", "lpptBuf", "nBufPoints", "resolution"]),
        #
        'TrackMouseEvent': SimTypeFunction([SimTypePointer(SimTypeRef("TRACKMOUSEEVENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpEventTrack"]),
        #
        'RegisterHotKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="HOT_KEY_MODIFIERS"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "id", "fsModifiers", "vk"]),
        #
        'UnregisterHotKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "id"]),
        #
        'SwapMouseButton': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fSwap"]),
        #
        'GetDoubleClickTime': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'SetDoubleClickTime': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'SetFocus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd"]),
        #
        'GetActiveWindow': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'GetFocus': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'GetKBCodePage': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'GetKeyState': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeShort(signed=True, label="Int16"), arg_names=["nVirtKey"]),
        #
        'GetAsyncKeyState': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeShort(signed=True, label="Int16"), arg_names=["vKey"]),
        #
        'GetKeyboardState': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpKeyState"]),
        #
        'SetKeyboardState': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpKeyState"]),
        #
        'GetKeyNameTextA': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lParam", "lpString", "cchSize"]),
        #
        'GetKeyNameTextW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lParam", "lpString", "cchSize"]),
        #
        'GetKeyboardType': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["nTypeFlag"]),
        #
        'ToAscii': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["uVirtKey", "uScanCode", "lpKeyState", "lpChar", "uFlags"]),
        #
        'ToAsciiEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uVirtKey", "uScanCode", "lpKeyState", "lpChar", "uFlags", "dwhkl"]),
        #
        'ToUnicode': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["wVirtKey", "wScanCode", "lpKeyState", "pwszBuff", "cchBuff", "wFlags"]),
        #
        'OemKeyScan': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["wOemChar"]),
        #
        'VkKeyScanA': SimTypeFunction([SimTypeChar(label="SByte")], SimTypeShort(signed=True, label="Int16"), arg_names=["ch"]),
        #
        'VkKeyScanW': SimTypeFunction([SimTypeChar(label="Char")], SimTypeShort(signed=True, label="Int16"), arg_names=["ch"]),
        #
        'VkKeyScanExA': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["ch", "dwhkl"]),
        #
        'VkKeyScanExW': SimTypeFunction([SimTypeChar(label="Char"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["ch", "dwhkl"]),
        #
        'keybd_event': SimTypeFunction([SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="KEYBD_EVENT_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["bVk", "bScan", "dwFlags", "dwExtraInfo"]),
        #
        'mouse_event': SimTypeFunction([SimTypeInt(signed=False, label="MOUSE_EVENT_FLAGS"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["dwFlags", "dx", "dy", "dwData", "dwExtraInfo"]),
        #
        'SendInput': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("INPUT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["cInputs", "pInputs", "cbSize"]),
        #
        'GetLastInputInfo': SimTypeFunction([SimTypePointer(SimTypeRef("LASTINPUTINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plii"]),
        #
        'MapVirtualKeyA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MAP_VIRTUAL_KEY_TYPE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["uCode", "uMapType"]),
        #
        'MapVirtualKeyW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MAP_VIRTUAL_KEY_TYPE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["uCode", "uMapType"]),
        #
        'MapVirtualKeyExA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MAP_VIRTUAL_KEY_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["uCode", "uMapType", "dwhkl"]),
        #
        'MapVirtualKeyExW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MAP_VIRTUAL_KEY_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["uCode", "uMapType", "dwhkl"]),
        #
        'GetCapture': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'SetCapture': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd"]),
        #
        'ReleaseCapture': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'EnableWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "bEnable"]),
        #
        'IsWindowEnabled': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'DragDetect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("POINT", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pt"]),
        #
        'SetActiveWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd"]),
        #
        'BlockInput': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fBlockIt"]),
        #
        'GetUnpredictedMessagePos': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'InitializeTouchInjection': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="TOUCH_FEEDBACK_MODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["maxCount", "dwMode"]),
        #
        'InjectTouchInput': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POINTER_TOUCH_INFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["count", "contacts"]),
        #
        'GetPointerType': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="POINTER_INPUT_TYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "pointerType"]),
        #
        'GetPointerCursorId': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "cursorId"]),
        #
        'GetPointerInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POINTER_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "pointerInfo"]),
        #
        'GetPointerInfoHistory': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("POINTER_INFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "entriesCount", "pointerInfo"]),
        #
        'GetPointerFrameInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("POINTER_INFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "pointerCount", "pointerInfo"]),
        #
        'GetPointerFrameInfoHistory': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("POINTER_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "entriesCount", "pointerCount", "pointerInfo"]),
        #
        'GetPointerTouchInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POINTER_TOUCH_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "touchInfo"]),
        #
        'GetPointerTouchInfoHistory': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("POINTER_TOUCH_INFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "entriesCount", "touchInfo"]),
        #
        'GetPointerFrameTouchInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("POINTER_TOUCH_INFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "pointerCount", "touchInfo"]),
        #
        'GetPointerFrameTouchInfoHistory': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("POINTER_TOUCH_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "entriesCount", "pointerCount", "touchInfo"]),
        #
        'GetPointerPenInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POINTER_PEN_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "penInfo"]),
        #
        'GetPointerPenInfoHistory': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("POINTER_PEN_INFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "entriesCount", "penInfo"]),
        #
        'GetPointerFramePenInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("POINTER_PEN_INFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "pointerCount", "penInfo"]),
        #
        'GetPointerFramePenInfoHistory': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("POINTER_PEN_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "entriesCount", "pointerCount", "penInfo"]),
        #
        'SkipPointerFrameMessages': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId"]),
        #
        'InjectSyntheticPointerInput': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINTER_TYPE_INFO", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["device", "pointerInfo", "count"]),
        #
        'EnableMouseInPointer': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fEnable"]),
        #
        'IsMouseInPointerEnabled': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'GetPointerInputTransform': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("INPUT_TRANSFORM", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "historyCount", "inputTransform"]),
        #
        'GetPointerDevices': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("POINTER_DEVICE_INFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["deviceCount", "pointerDevices"]),
        #
        'GetPointerDevice': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINTER_DEVICE_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["device", "pointerDevice"]),
        #
        'GetPointerDeviceProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("POINTER_DEVICE_PROPERTY", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["device", "propertyCount", "pointerProperties"]),
        #
        'GetPointerDeviceRects': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["device", "pointerDeviceRect", "displayRect"]),
        #
        'GetPointerDeviceCursors': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("POINTER_DEVICE_CURSOR_INFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["device", "cursorCount", "deviceCursors"]),
        #
        'GetRawPointerDeviceData': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POINTER_DEVICE_PROPERTY", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pointerId", "historyCount", "propertiesCount", "pProperties", "pValues"]),
        #
        'GetTouchInputInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TOUCHINPUT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hTouchInput", "cInputs", "pInputs", "cbSize"]),
        #
        'CloseTouchInputHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTouchInput"]),
        #
        'RegisterTouchWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="REGISTER_TOUCH_WINDOW_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "ulFlags"]),
        #
        'UnregisterTouchWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'IsTouchWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pulFlags"]),
        #
        'GetGestureInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("GESTUREINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGestureInfo", "pGestureInfo"]),
        #
        'GetGestureExtraArgs': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGestureInfo", "cbExtraArgs", "pExtraArgs"]),
        #
        'CloseGestureInfoHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGestureInfo"]),
        #
        'SetGestureConfig': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GESTURECONFIG", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "dwReserved", "cIDs", "pGestureConfig", "cbSize"]),
        #
        'GetGestureConfig': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("GESTURECONFIG", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "dwReserved", "dwFlags", "pcIDs", "pGestureConfig", "cbSize"]),
        #
        'SetWindowContextHelpId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'GetWindowContextHelpId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'SetMenuContextHelpId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'GetMenuContextHelpId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'WinHelpA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWndMain", "lpszHelp", "uCommand", "dwData"]),
        #
        'WinHelpW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWndMain", "lpszHelp", "uCommand", "dwData"]),
        #
        'LoadStringA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hInstance", "uID", "lpBuffer", "cchBufferMax"]),
        #
        'LoadStringW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hInstance", "uID", "lpBuffer", "cchBufferMax"]),
        #
        'GetWindowLongPtrA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WINDOW_LONG_PTR_INDEX")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "nIndex"]),
        #
        'GetWindowLongPtrW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WINDOW_LONG_PTR_INDEX")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "nIndex"]),
        #
        'SetWindowLongPtrA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WINDOW_LONG_PTR_INDEX"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "nIndex", "dwNewLong"]),
        #
        'SetWindowLongPtrW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WINDOW_LONG_PTR_INDEX"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "nIndex", "dwNewLong"]),
        #
        'GetClassLongPtrA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_CLASS_LONG_INDEX")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hWnd", "nIndex"]),
        #
        'GetClassLongPtrW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_CLASS_LONG_INDEX")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hWnd", "nIndex"]),
        #
        'SetClassLongPtrA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_CLASS_LONG_INDEX"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hWnd", "nIndex", "dwNewLong"]),
        #
        'SetClassLongPtrW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_CLASS_LONG_INDEX"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hWnd", "nIndex", "dwNewLong"]),
        #
        'wvsprintfA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "arglist"]),
        #
        'wvsprintfW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "arglist"]),
        #
        'wsprintfA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'wsprintfW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'IsHungAppWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'DisableProcessWindowsGhosting': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'RegisterWindowMessageA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpString"]),
        #
        'RegisterWindowMessageW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpString"]),
        #
        'GetMessageA': SimTypeFunction([SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMsg", "hWnd", "wMsgFilterMin", "wMsgFilterMax"]),
        #
        'GetMessageW': SimTypeFunction([SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMsg", "hWnd", "wMsgFilterMin", "wMsgFilterMax"]),
        #
        'TranslateMessage': SimTypeFunction([SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMsg"]),
        #
        'DispatchMessageA': SimTypeFunction([SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpMsg"]),
        #
        'DispatchMessageW': SimTypeFunction([SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpMsg"]),
        #
        'SetMessageQueue': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["cMessagesMax"]),
        #
        'PeekMessageA': SimTypeFunction([SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="PEEK_MESSAGE_REMOVE_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMsg", "hWnd", "wMsgFilterMin", "wMsgFilterMax", "wRemoveMsg"]),
        #
        'PeekMessageW': SimTypeFunction([SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="PEEK_MESSAGE_REMOVE_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMsg", "hWnd", "wMsgFilterMin", "wMsgFilterMax", "wRemoveMsg"]),
        #
        'GetMessagePos': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'GetMessageTime': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'GetMessageExtraInfo': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'IsWow64Message': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'SetMessageExtraInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lParam"]),
        #
        'SendMessageA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "Msg", "wParam", "lParam"]),
        #
        'SendMessageW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "Msg", "wParam", "lParam"]),
        #
        'SendMessageTimeoutA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SEND_MESSAGE_TIMEOUT_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "Msg", "wParam", "lParam", "fuFlags", "uTimeout", "lpdwResult"]),
        #
        'SendMessageTimeoutW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SEND_MESSAGE_TIMEOUT_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "Msg", "wParam", "lParam", "fuFlags", "uTimeout", "lpdwResult"]),
        #
        'SendNotifyMessageA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "Msg", "wParam", "lParam"]),
        #
        'SendNotifyMessageW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "Msg", "wParam", "lParam"]),
        #
        'SendMessageCallbackA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "Msg", "wParam", "lParam", "lpResultCallBack", "dwData"]),
        #
        'SendMessageCallbackW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "Msg", "wParam", "lParam", "lpResultCallBack", "dwData"]),
        #
        'RegisterDeviceNotificationA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="REGISTER_NOTIFICATION_FLAGS")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hRecipient", "NotificationFilter", "Flags"]),
        #
        'RegisterDeviceNotificationW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="REGISTER_NOTIFICATION_FLAGS")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hRecipient", "NotificationFilter", "Flags"]),
        #
        'UnregisterDeviceNotification': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle"]),
        #
        'PostMessageA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "Msg", "wParam", "lParam"]),
        #
        'PostMessageW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "Msg", "wParam", "lParam"]),
        #
        'PostThreadMessageA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idThread", "Msg", "wParam", "lParam"]),
        #
        'PostThreadMessageW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idThread", "Msg", "wParam", "lParam"]),
        #
        'ReplyMessage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lResult"]),
        #
        'WaitMessage': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'DefWindowProcA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "Msg", "wParam", "lParam"]),
        #
        'DefWindowProcW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "Msg", "wParam", "lParam"]),
        #
        'PostQuitMessage': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["nExitCode"]),
        #
        'CallWindowProcA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpPrevWndFunc", "hWnd", "Msg", "wParam", "lParam"]),
        #
        'CallWindowProcW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpPrevWndFunc", "hWnd", "Msg", "wParam", "lParam"]),
        #
        'InSendMessage': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'InSendMessageEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpReserved"]),
        #
        'RegisterClassA': SimTypeFunction([SimTypePointer(SimTypeRef("WNDCLASSA", SimStruct), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["lpWndClass"]),
        #
        'RegisterClassW': SimTypeFunction([SimTypePointer(SimTypeRef("WNDCLASSW", SimStruct), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["lpWndClass"]),
        #
        'UnregisterClassA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpClassName", "hInstance"]),
        #
        'UnregisterClassW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpClassName", "hInstance"]),
        #
        'GetClassInfoA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("WNDCLASSA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hInstance", "lpClassName", "lpWndClass"]),
        #
        'GetClassInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WNDCLASSW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hInstance", "lpClassName", "lpWndClass"]),
        #
        'RegisterClassExA': SimTypeFunction([SimTypePointer(SimTypeRef("WNDCLASSEXA", SimStruct), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["param0"]),
        #
        'RegisterClassExW': SimTypeFunction([SimTypePointer(SimTypeRef("WNDCLASSEXW", SimStruct), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["param0"]),
        #
        'GetClassInfoExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("WNDCLASSEXA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hInstance", "lpszClass", "lpwcx"]),
        #
        'GetClassInfoExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WNDCLASSEXW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hInstance", "lpszClass", "lpwcx"]),
        #
        'CreateWindowExA': SimTypeFunction([SimTypeInt(signed=False, label="WINDOW_EX_STYLE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="WINDOW_STYLE"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwExStyle", "lpClassName", "lpWindowName", "dwStyle", "X", "Y", "nWidth", "nHeight", "hWndParent", "hMenu", "hInstance", "lpParam"]),
        #
        'CreateWindowExW': SimTypeFunction([SimTypeInt(signed=False, label="WINDOW_EX_STYLE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="WINDOW_STYLE"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwExStyle", "lpClassName", "lpWindowName", "dwStyle", "X", "Y", "nWidth", "nHeight", "hWndParent", "hMenu", "hInstance", "lpParam"]),
        #
        'IsWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'IsMenu': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu"]),
        #
        'IsChild': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWndParent", "hWnd"]),
        #
        'DestroyWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'ShowWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SHOW_WINDOW_CMD")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "nCmdShow"]),
        #
        'AnimateWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ANIMATE_WINDOW_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "dwTime", "dwFlags"]),
        #
        'UpdateLayeredWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BLENDFUNCTION", SimStruct), offset=0), SimTypeInt(signed=False, label="UPDATE_LAYERED_WINDOW_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "hdcDst", "pptDst", "psize", "hdcSrc", "pptSrc", "crKey", "pblend", "dwFlags"]),
        #
        'UpdateLayeredWindowIndirect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UPDATELAYEREDWINDOWINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "pULWInfo"]),
        #
        'GetLayeredWindowAttributes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="LAYERED_WINDOW_ATTRIBUTES_FLAGS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pcrKey", "pbAlpha", "pdwFlags"]),
        #
        'SetLayeredWindowAttributes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="LAYERED_WINDOW_ATTRIBUTES_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "crKey", "bAlpha", "dwFlags"]),
        #
        'ShowWindowAsync': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SHOW_WINDOW_CMD")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "nCmdShow"]),
        #
        'FlashWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "bInvert"]),
        #
        'FlashWindowEx': SimTypeFunction([SimTypePointer(SimTypeRef("FLASHWINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfwi"]),
        #
        'ShowOwnedPopups': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "fShow"]),
        #
        'OpenIcon': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'CloseWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'MoveWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "X", "Y", "nWidth", "nHeight", "bRepaint"]),
        #
        'SetWindowPos': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="SET_WINDOW_POS_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "hWndInsertAfter", "X", "Y", "cx", "cy", "uFlags"]),
        #
        'GetWindowPlacement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("WINDOWPLACEMENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpwndpl"]),
        #
        'SetWindowPlacement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("WINDOWPLACEMENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpwndpl"]),
        #
        'GetWindowDisplayAffinity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "pdwAffinity"]),
        #
        'SetWindowDisplayAffinity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WINDOW_DISPLAY_AFFINITY")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "dwAffinity"]),
        #
        'BeginDeferWindowPos': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["nNumWindows"]),
        #
        'DeferWindowPos': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="SET_WINDOW_POS_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWinPosInfo", "hWnd", "hWndInsertAfter", "x", "y", "cx", "cy", "uFlags"]),
        #
        'EndDeferWindowPos': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWinPosInfo"]),
        #
        'IsWindowVisible': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'IsIconic': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'AnyPopup': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'BringWindowToTop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'IsZoomed': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'CreateDialogParamA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpTemplateName", "hWndParent", "lpDialogFunc", "dwInitParam"]),
        #
        'CreateDialogParamW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpTemplateName", "hWndParent", "lpDialogFunc", "dwInitParam"]),
        #
        'CreateDialogIndirectParamA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DLGTEMPLATE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpTemplate", "hWndParent", "lpDialogFunc", "dwInitParam"]),
        #
        'CreateDialogIndirectParamW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DLGTEMPLATE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpTemplate", "hWndParent", "lpDialogFunc", "dwInitParam"]),
        #
        'DialogBoxParamA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpTemplateName", "hWndParent", "lpDialogFunc", "dwInitParam"]),
        #
        'DialogBoxParamW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpTemplateName", "hWndParent", "lpDialogFunc", "dwInitParam"]),
        #
        'DialogBoxIndirectParamA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DLGTEMPLATE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "hDialogTemplate", "hWndParent", "lpDialogFunc", "dwInitParam"]),
        #
        'DialogBoxIndirectParamW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DLGTEMPLATE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "hDialogTemplate", "hWndParent", "lpDialogFunc", "dwInitParam"]),
        #
        'EndDialog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "nResult"]),
        #
        'GetDlgItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hDlg", "nIDDlgItem"]),
        #
        'SetDlgItemInt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "nIDDlgItem", "uValue", "bSigned"]),
        #
        'GetDlgItemInt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDlg", "nIDDlgItem", "lpTranslated", "bSigned"]),
        #
        'SetDlgItemTextA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "nIDDlgItem", "lpString"]),
        #
        'SetDlgItemTextW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "nIDDlgItem", "lpString"]),
        #
        'GetDlgItemTextA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDlg", "nIDDlgItem", "lpString", "cchMax"]),
        #
        'GetDlgItemTextW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDlg", "nIDDlgItem", "lpString", "cchMax"]),
        #
        'SendDlgItemMessageA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hDlg", "nIDDlgItem", "Msg", "wParam", "lParam"]),
        #
        'SendDlgItemMessageW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hDlg", "nIDDlgItem", "Msg", "wParam", "lParam"]),
        #
        'GetNextDlgGroupItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hDlg", "hCtl", "bPrevious"]),
        #
        'GetNextDlgTabItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hDlg", "hCtl", "bPrevious"]),
        #
        'GetDlgCtrlID': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'GetDialogBaseUnits': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'DefDlgProcA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hDlg", "Msg", "wParam", "lParam"]),
        #
        'DefDlgProcW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hDlg", "Msg", "wParam", "lParam"]),
        #
        'CallMsgFilterA': SimTypeFunction([SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMsg", "nCode"]),
        #
        'CallMsgFilterW': SimTypeFunction([SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMsg", "nCode"]),
        #
        'CharToOemA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrc", "pDst"]),
        #
        'CharToOemW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrc", "pDst"]),
        #
        'OemToCharA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrc", "pDst"]),
        #
        'OemToCharW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrc", "pDst"]),
        #
        'CharToOemBuffA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszSrc", "lpszDst", "cchDstLength"]),
        #
        'CharToOemBuffW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszSrc", "lpszDst", "cchDstLength"]),
        #
        'OemToCharBuffA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszSrc", "lpszDst", "cchDstLength"]),
        #
        'OemToCharBuffW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszSrc", "lpszDst", "cchDstLength"]),
        #
        'CharUpperA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["lpsz"]),
        #
        'CharUpperW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["lpsz"]),
        #
        'CharUpperBuffA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpsz", "cchLength"]),
        #
        'CharUpperBuffW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpsz", "cchLength"]),
        #
        'CharLowerA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["lpsz"]),
        #
        'CharLowerW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["lpsz"]),
        #
        'CharLowerBuffA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpsz", "cchLength"]),
        #
        'CharLowerBuffW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpsz", "cchLength"]),
        #
        'CharNextA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["lpsz"]),
        #
        'CharNextW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["lpsz"]),
        #
        'CharPrevA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["lpszStart", "lpszCurrent"]),
        #
        'CharPrevW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["lpszStart", "lpszCurrent"]),
        #
        'CharNextExA': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["CodePage", "lpCurrentChar", "dwFlags"]),
        #
        'CharPrevExA': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["CodePage", "lpStart", "lpCurrentChar", "dwFlags"]),
        #
        'IsCharAlphaA': SimTypeFunction([SimTypeChar(label="SByte")], SimTypeInt(signed=True, label="Int32"), arg_names=["ch"]),
        #
        'IsCharAlphaW': SimTypeFunction([SimTypeChar(label="Char")], SimTypeInt(signed=True, label="Int32"), arg_names=["ch"]),
        #
        'IsCharAlphaNumericA': SimTypeFunction([SimTypeChar(label="SByte")], SimTypeInt(signed=True, label="Int32"), arg_names=["ch"]),
        #
        'IsCharAlphaNumericW': SimTypeFunction([SimTypeChar(label="Char")], SimTypeInt(signed=True, label="Int32"), arg_names=["ch"]),
        #
        'IsCharUpperA': SimTypeFunction([SimTypeChar(label="SByte")], SimTypeInt(signed=True, label="Int32"), arg_names=["ch"]),
        #
        'IsCharUpperW': SimTypeFunction([SimTypeChar(label="Char")], SimTypeInt(signed=True, label="Int32"), arg_names=["ch"]),
        #
        'IsCharLowerA': SimTypeFunction([SimTypeChar(label="SByte")], SimTypeInt(signed=True, label="Int32"), arg_names=["ch"]),
        #
        'GetInputState': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'GetQueueStatus': SimTypeFunction([SimTypeInt(signed=False, label="QUEUE_STATUS_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["flags"]),
        #
        'MsgWaitForMultipleObjects': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="QUEUE_STATUS_FLAGS")], SimTypeInt(signed=False, label="WAIT_EVENT"), arg_names=["nCount", "pHandles", "fWaitAll", "dwMilliseconds", "dwWakeMask"]),
        #
        'MsgWaitForMultipleObjectsEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="QUEUE_STATUS_FLAGS"), SimTypeInt(signed=False, label="MSG_WAIT_FOR_MULTIPLE_OBJECTS_EX_FLAGS")], SimTypeInt(signed=False, label="WAIT_EVENT"), arg_names=["nCount", "pHandles", "dwMilliseconds", "dwWakeMask", "dwFlags"]),
        #
        'SetTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["param0", "param1", "param2", "param3"]), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hWnd", "nIDEvent", "uElapse", "lpTimerFunc"]),
        #
        'SetCoalescableTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hWnd", "nIDEvent", "uElapse", "lpTimerFunc", "uToleranceDelay"]),
        #
        'KillTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "uIDEvent"]),
        #
        'IsWindowUnicode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'LoadAcceleratorsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpTableName"]),
        #
        'LoadAcceleratorsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpTableName"]),
        #
        'CreateAcceleratorTableA': SimTypeFunction([SimTypePointer(SimTypeRef("ACCEL", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["paccel", "cAccel"]),
        #
        'CreateAcceleratorTableW': SimTypeFunction([SimTypePointer(SimTypeRef("ACCEL", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["paccel", "cAccel"]),
        #
        'DestroyAcceleratorTable': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAccel"]),
        #
        'CopyAcceleratorTableA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("ACCEL", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAccelSrc", "lpAccelDst", "cAccelEntries"]),
        #
        'CopyAcceleratorTableW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("ACCEL", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAccelSrc", "lpAccelDst", "cAccelEntries"]),
        #
        'TranslateAcceleratorA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "hAccTable", "lpMsg"]),
        #
        'TranslateAcceleratorW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "hAccTable", "lpMsg"]),
        #
        'GetSystemMetrics': SimTypeFunction([SimTypeInt(signed=False, label="SYSTEM_METRICS_INDEX")], SimTypeInt(signed=True, label="Int32"), arg_names=["nIndex"]),
        #
        'LoadMenuA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpMenuName"]),
        #
        'LoadMenuW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpMenuName"]),
        #
        'LoadMenuIndirectA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpMenuTemplate"]),
        #
        'LoadMenuIndirectW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpMenuTemplate"]),
        #
        'GetMenu': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd"]),
        #
        'SetMenu': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "hMenu"]),
        #
        'ChangeMenuA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "cmd", "lpszNewItem", "cmdInsert", "flags"]),
        #
        'ChangeMenuW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "cmd", "lpszNewItem", "cmdInsert", "flags"]),
        #
        'HiliteMenuItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "hMenu", "uIDHiliteItem", "uHilite"]),
        #
        'GetMenuStringA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="MENU_ITEM_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "uIDItem", "lpString", "cchMax", "flags"]),
        #
        'GetMenuStringW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="MENU_ITEM_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "uIDItem", "lpString", "cchMax", "flags"]),
        #
        'GetMenuState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MENU_ITEM_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hMenu", "uId", "uFlags"]),
        #
        'DrawMenuBar': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'GetSystemMenu': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "bRevert"]),
        #
        'CreateMenu': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'CreatePopupMenu': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'DestroyMenu': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu"]),
        #
        'CheckMenuItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hMenu", "uIDCheckItem", "uCheck"]),
        #
        'EnableMenuItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MENU_ITEM_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "uIDEnableItem", "uEnable"]),
        #
        'GetSubMenu': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hMenu", "nPos"]),
        #
        'GetMenuItemID': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hMenu", "nPos"]),
        #
        'GetMenuItemCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu"]),
        #
        'InsertMenuA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MENU_ITEM_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "uPosition", "uFlags", "uIDNewItem", "lpNewItem"]),
        #
        'InsertMenuW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MENU_ITEM_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "uPosition", "uFlags", "uIDNewItem", "lpNewItem"]),
        #
        'AppendMenuA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MENU_ITEM_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "uFlags", "uIDNewItem", "lpNewItem"]),
        #
        'AppendMenuW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MENU_ITEM_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "uFlags", "uIDNewItem", "lpNewItem"]),
        #
        'ModifyMenuA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MENU_ITEM_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMnu", "uPosition", "uFlags", "uIDNewItem", "lpNewItem"]),
        #
        'ModifyMenuW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MENU_ITEM_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMnu", "uPosition", "uFlags", "uIDNewItem", "lpNewItem"]),
        #
        'RemoveMenu': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MENU_ITEM_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "uPosition", "uFlags"]),
        #
        'DeleteMenu': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MENU_ITEM_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "uPosition", "uFlags"]),
        #
        'SetMenuItemBitmaps': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MENU_ITEM_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "uPosition", "uFlags", "hBitmapUnchecked", "hBitmapChecked"]),
        #
        'GetMenuCheckMarkDimensions': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'TrackPopupMenu': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TRACK_POPUP_MENU_FLAGS"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "uFlags", "x", "y", "nReserved", "hWnd", "prcRect"]),
        #
        'TrackPopupMenuEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TPMPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "uFlags", "x", "y", "hwnd", "lptpm"]),
        #
        'CalculatePopupWindowPosition': SimTypeFunction([SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["anchorPoint", "windowSize", "flags", "excludeRect", "popupWindowPosition"]),
        #
        'GetMenuInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MENUINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'SetMenuInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MENUINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'EndMenu': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'InsertMenuItemA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("MENUITEMINFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hmenu", "item", "fByPosition", "lpmi"]),
        #
        'InsertMenuItemW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("MENUITEMINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hmenu", "item", "fByPosition", "lpmi"]),
        #
        'GetMenuItemInfoA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("MENUITEMINFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hmenu", "item", "fByPosition", "lpmii"]),
        #
        'GetMenuItemInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("MENUITEMINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hmenu", "item", "fByPosition", "lpmii"]),
        #
        'SetMenuItemInfoA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("MENUITEMINFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hmenu", "item", "fByPositon", "lpmii"]),
        #
        'SetMenuItemInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("MENUITEMINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hmenu", "item", "fByPositon", "lpmii"]),
        #
        'GetMenuDefaultItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="GET_MENU_DEFAULT_ITEM_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hMenu", "fByPos", "gmdiFlags"]),
        #
        'SetMenuDefaultItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMenu", "uItem", "fByPos"]),
        #
        'GetMenuItemRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "hMenu", "uItem", "lprcItem"]),
        #
        'MenuItemFromPoint': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("POINT", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "hMenu", "ptScreen"]),
        #
        'DragObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwndParent", "hwndFrom", "fmt", "data", "hcur"]),
        #
        'DrawIcon': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "X", "Y", "hIcon"]),
        #
        'GetForegroundWindow': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'SwitchToThisWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["hwnd", "fUnknown"]),
        #
        'SetForegroundWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'AllowSetForegroundWindow': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwProcessId"]),
        #
        'LockSetForegroundWindow': SimTypeFunction([SimTypeInt(signed=False, label="FOREGROUND_WINDOW_LOCK_CODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["uLockCode"]),
        #
        'ScrollWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "XAmount", "YAmount", "lpRect", "lpClipRect"]),
        #
        'ScrollDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "dx", "dy", "lprcScroll", "lprcClip", "hrgnUpdate", "lprcUpdate"]),
        #
        'ScrollWindowEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="SCROLL_WINDOW_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "dx", "dy", "prcScroll", "prcClip", "hrgnUpdate", "prcUpdate", "flags"]),
        #
        'GetScrollPos': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SCROLLBAR_CONSTANTS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "nBar"]),
        #
        'GetScrollRange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SCROLLBAR_CONSTANTS"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "nBar", "lpMinPos", "lpMaxPos"]),
        #
        'SetPropA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpString", "hData"]),
        #
        'SetPropW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpString", "hData"]),
        #
        'GetPropA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "lpString"]),
        #
        'GetPropW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "lpString"]),
        #
        'RemovePropA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "lpString"]),
        #
        'RemovePropW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "lpString"]),
        #
        'EnumPropsExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpEnumFunc", "lParam"]),
        #
        'EnumPropsExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpEnumFunc", "lParam"]),
        #
        'EnumPropsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpEnumFunc"]),
        #
        'EnumPropsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpEnumFunc"]),
        #
        'SetWindowTextA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpString"]),
        #
        'SetWindowTextW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpString"]),
        #
        'GetWindowTextA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpString", "nMaxCount"]),
        #
        'GetWindowTextW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpString", "nMaxCount"]),
        #
        'GetWindowTextLengthA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'GetWindowTextLengthW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'GetClientRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpRect"]),
        #
        'GetWindowRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpRect"]),
        #
        'AdjustWindowRect': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="WINDOW_STYLE"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpRect", "dwStyle", "bMenu"]),
        #
        'AdjustWindowRectEx': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="WINDOW_STYLE"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="WINDOW_EX_STYLE")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpRect", "dwStyle", "bMenu", "dwExStyle"]),
        #
        'MessageBoxA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MESSAGEBOX_STYLE")], SimTypeInt(signed=False, label="MESSAGEBOX_RESULT"), arg_names=["hWnd", "lpText", "lpCaption", "uType"]),
        #
        'MessageBoxW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MESSAGEBOX_STYLE")], SimTypeInt(signed=False, label="MESSAGEBOX_RESULT"), arg_names=["hWnd", "lpText", "lpCaption", "uType"]),
        #
        'MessageBoxExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MESSAGEBOX_STYLE"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="MESSAGEBOX_RESULT"), arg_names=["hWnd", "lpText", "lpCaption", "uType", "wLanguageId"]),
        #
        'MessageBoxExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MESSAGEBOX_STYLE"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="MESSAGEBOX_RESULT"), arg_names=["hWnd", "lpText", "lpCaption", "uType", "wLanguageId"]),
        #
        'MessageBoxIndirectA': SimTypeFunction([SimTypePointer(SimTypeRef("MSGBOXPARAMSA", SimStruct), offset=0)], SimTypeInt(signed=False, label="MESSAGEBOX_RESULT"), arg_names=["lpmbp"]),
        #
        'MessageBoxIndirectW': SimTypeFunction([SimTypePointer(SimTypeRef("MSGBOXPARAMSW", SimStruct), offset=0)], SimTypeInt(signed=False, label="MESSAGEBOX_RESULT"), arg_names=["lpmbp"]),
        #
        'ShowCursor': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["bShow"]),
        #
        'SetCursorPos': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["X", "Y"]),
        #
        'SetPhysicalCursorPos': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["X", "Y"]),
        #
        'SetCursor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hCursor"]),
        #
        'GetCursorPos': SimTypeFunction([SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPoint"]),
        #
        'GetPhysicalCursorPos': SimTypeFunction([SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPoint"]),
        #
        'GetClipCursor': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpRect"]),
        #
        'GetCursor': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'CreateCaret': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "hBitmap", "nWidth", "nHeight"]),
        #
        'GetCaretBlinkTime': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'SetCaretBlinkTime': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["uMSeconds"]),
        #
        'DestroyCaret': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'HideCaret': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'ShowCaret': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd"]),
        #
        'SetCaretPos': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["X", "Y"]),
        #
        'GetCaretPos': SimTypeFunction([SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPoint"]),
        #
        'LogicalToPhysicalPoint': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpPoint"]),
        #
        'PhysicalToLogicalPoint': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpPoint"]),
        #
        'WindowFromPoint': SimTypeFunction([SimTypeRef("POINT", SimStruct)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Point"]),
        #
        'WindowFromPhysicalPoint': SimTypeFunction([SimTypeRef("POINT", SimStruct)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Point"]),
        #
        'ChildWindowFromPoint': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("POINT", SimStruct)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWndParent", "Point"]),
        #
        'ClipCursor': SimTypeFunction([SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpRect"]),
        #
        'ChildWindowFromPointEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("POINT", SimStruct), SimTypeInt(signed=False, label="CWP_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd", "pt", "flags"]),
        #
        'GetWindowWord': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeShort(signed=False, label="UInt16"), arg_names=["hWnd", "nIndex"]),
        #
        'SetWindowWord': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=False, label="UInt16"), arg_names=["hWnd", "nIndex", "wNewWord"]),
        #
        'GetWindowLongA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WINDOW_LONG_PTR_INDEX")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "nIndex"]),
        #
        'GetWindowLongW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WINDOW_LONG_PTR_INDEX")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "nIndex"]),
        #
        'SetWindowLongA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WINDOW_LONG_PTR_INDEX"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "nIndex", "dwNewLong"]),
        #
        'SetWindowLongW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WINDOW_LONG_PTR_INDEX"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "nIndex", "dwNewLong"]),
        #
        'GetClassWord': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeShort(signed=False, label="UInt16"), arg_names=["hWnd", "nIndex"]),
        #
        'SetClassWord': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=False, label="UInt16"), arg_names=["hWnd", "nIndex", "wNewWord"]),
        #
        'GetClassLongA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_CLASS_LONG_INDEX")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWnd", "nIndex"]),
        #
        'GetClassLongW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_CLASS_LONG_INDEX")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWnd", "nIndex"]),
        #
        'SetClassLongA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_CLASS_LONG_INDEX"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWnd", "nIndex", "dwNewLong"]),
        #
        'SetClassLongW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_CLASS_LONG_INDEX"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWnd", "nIndex", "dwNewLong"]),
        #
        'GetProcessDefaultLayout': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdwDefaultLayout"]),
        #
        'SetProcessDefaultLayout': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDefaultLayout"]),
        #
        'GetDesktopWindow': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'GetParent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd"]),
        #
        'SetParent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWndChild", "hWndNewParent"]),
        #
        'EnumChildWindows': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWndParent", "lpEnumFunc", "lParam"]),
        #
        'FindWindowA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpClassName", "lpWindowName"]),
        #
        'FindWindowW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpClassName", "lpWindowName"]),
        #
        'FindWindowExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWndParent", "hWndChildAfter", "lpszClass", "lpszWindow"]),
        #
        'FindWindowExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWndParent", "hWndChildAfter", "lpszClass", "lpszWindow"]),
        #
        'GetShellWindow': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'RegisterShellHookWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'DeregisterShellHookWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'EnumWindows': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpEnumFunc", "lParam"]),
        #
        'EnumThreadWindows': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwThreadId", "lpfn", "lParam"]),
        #
        'GetClassNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpClassName", "nMaxCount"]),
        #
        'GetClassNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "lpClassName", "nMaxCount"]),
        #
        'GetTopWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd"]),
        #
        'GetWindowThreadProcessId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWnd", "lpdwProcessId"]),
        #
        'IsGUIThread': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["bConvert"]),
        #
        'GetLastActivePopup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd"]),
        #
        'GetWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_WINDOW_CMD")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "uCmd"]),
        #
        'SetWindowsHookA': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["code", "wParam", "lParam"]), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["nFilterType", "pfnFilterProc"]),
        #
        'SetWindowsHookW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["code", "wParam", "lParam"]), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["nFilterType", "pfnFilterProc"]),
        #
        'UnhookWindowsHook': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["code", "wParam", "lParam"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nCode", "pfnFilterProc"]),
        #
        'SetWindowsHookExA': SimTypeFunction([SimTypeInt(signed=False, label="WINDOWS_HOOK_ID"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["code", "wParam", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["idHook", "lpfn", "hmod", "dwThreadId"]),
        #
        'SetWindowsHookExW': SimTypeFunction([SimTypeInt(signed=False, label="WINDOWS_HOOK_ID"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["code", "wParam", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["idHook", "lpfn", "hmod", "dwThreadId"]),
        #
        'UnhookWindowsHookEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hhk"]),
        #
        'CallNextHookEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hhk", "nCode", "wParam", "lParam"]),
        #
        'CheckMenuRadioItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hmenu", "first", "last", "check", "flags"]),
        #
        'LoadCursorA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpCursorName"]),
        #
        'LoadCursorW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpCursorName"]),
        #
        'LoadCursorFromFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName"]),
        #
        'LoadCursorFromFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName"]),
        #
        'CreateCursor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInst", "xHotSpot", "yHotSpot", "nWidth", "nHeight", "pvANDPlane", "pvXORPlane"]),
        #
        'DestroyCursor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCursor"]),
        #
        'SetSystemCursor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SYSTEM_CURSOR_ID")], SimTypeInt(signed=True, label="Int32"), arg_names=["hcur", "id"]),
        #
        'LoadIconA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpIconName"]),
        #
        'LoadIconW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "lpIconName"]),
        #
        'PrivateExtractIconsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szFileName", "nIconIndex", "cxIcon", "cyIcon", "phicon", "piconid", "nIcons", "flags"]),
        #
        'PrivateExtractIconsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szFileName", "nIconIndex", "cxIcon", "cyIcon", "phicon", "piconid", "nIcons", "flags"]),
        #
        'CreateIcon': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInstance", "nWidth", "nHeight", "cPlanes", "cBitsPixel", "lpbANDbits", "lpbXORbits"]),
        #
        'DestroyIcon': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIcon"]),
        #
        'LookupIconIdFromDirectory': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["presbits", "fIcon"]),
        #
        'LookupIconIdFromDirectoryEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="IMAGE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["presbits", "fIcon", "cxDesired", "cyDesired", "Flags"]),
        #
        'CreateIconFromResource': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["presbits", "dwResSize", "fIcon", "dwVer"]),
        #
        'CreateIconFromResourceEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="IMAGE_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["presbits", "dwResSize", "fIcon", "dwVer", "cxDesired", "cyDesired", "Flags"]),
        #
        'LoadImageA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="GDI_IMAGE_TYPE"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="IMAGE_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInst", "name", "type", "cx", "cy", "fuLoad"]),
        #
        'LoadImageW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="GDI_IMAGE_TYPE"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="IMAGE_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInst", "name", "type", "cx", "cy", "fuLoad"]),
        #
        'CopyImage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GDI_IMAGE_TYPE"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="IMAGE_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["h", "type", "cx", "cy", "flags"]),
        #
        'DrawIconEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DI_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "xLeft", "yTop", "hIcon", "cxWidth", "cyWidth", "istepIfAniCur", "hbrFlickerFreeDraw", "diFlags"]),
        #
        'CreateIconIndirect': SimTypeFunction([SimTypePointer(SimTypeRef("ICONINFO", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["piconinfo"]),
        #
        'CopyIcon': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hIcon"]),
        #
        'GetIconInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("ICONINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hIcon", "piconinfo"]),
        #
        'GetIconInfoExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("ICONINFOEXA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hicon", "piconinfo"]),
        #
        'GetIconInfoExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("ICONINFOEXW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hicon", "piconinfo"]),
        #
        'IsDialogMessageA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "lpMsg"]),
        #
        'IsDialogMessageW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "lpMsg"]),
        #
        'MapDialogRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "lpRect"]),
        #
        'GetScrollInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SCROLLBAR_CONSTANTS"), SimTypePointer(SimTypeRef("SCROLLINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "nBar", "lpsi"]),
        #
        'DefFrameProcA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "hWndMDIClient", "uMsg", "wParam", "lParam"]),
        #
        'DefFrameProcW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "hWndMDIClient", "uMsg", "wParam", "lParam"]),
        #
        'DefMDIChildProcA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "uMsg", "wParam", "lParam"]),
        #
        'DefMDIChildProcW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "uMsg", "wParam", "lParam"]),
        #
        'TranslateMDISysAccel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWndClient", "lpMsg"]),
        #
        'ArrangeIconicWindows': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWnd"]),
        #
        'CreateMDIWindowA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="WINDOW_STYLE"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpClassName", "lpWindowName", "dwStyle", "X", "Y", "nWidth", "nHeight", "hWndParent", "hInstance", "lParam"]),
        #
        'CreateMDIWindowW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="WINDOW_STYLE"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpClassName", "lpWindowName", "dwStyle", "X", "Y", "nWidth", "nHeight", "hWndParent", "hInstance", "lParam"]),
        #
        'TileWindows': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TILE_WINDOWS_HOW"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["hwndParent", "wHow", "lpRect", "cKids", "lpKids"]),
        #
        'CascadeWindows': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CASCADE_WINDOWS_HOW"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["hwndParent", "wHow", "lpRect", "cKids", "lpKids"]),
        #
        'SystemParametersInfoA': SimTypeFunction([SimTypeInt(signed=False, label="SYSTEM_PARAMETERS_INFO_ACTION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["uiAction", "uiParam", "pvParam", "fWinIni"]),
        #
        'SystemParametersInfoW': SimTypeFunction([SimTypeInt(signed=False, label="SYSTEM_PARAMETERS_INFO_ACTION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["uiAction", "uiParam", "pvParam", "fWinIni"]),
        #
        'SoundSentry': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'SetDebugErrorLevel': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwLevel"]),
        #
        'InternalGetWindowText': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "pString", "cchMaxCount"]),
        #
        'CancelShutdown': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'GetGUIThreadInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GUITHREADINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idThread", "pgui"]),
        #
        'SetProcessDPIAware': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'IsProcessDPIAware': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'InheritWindowMonitor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "hwndInherit"]),
        #
        'GetWindowModuleFileNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwnd", "pszFileName", "cchFileNameMax"]),
        #
        'GetWindowModuleFileNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwnd", "pszFileName", "cchFileNameMax"]),
        #
        'GetCursorInfo': SimTypeFunction([SimTypePointer(SimTypeRef("CURSORINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pci"]),
        #
        'GetWindowInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("WINDOWINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pwi"]),
        #
        'GetTitleBarInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TITLEBARINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pti"]),
        #
        'GetMenuBarInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="OBJECT_IDENTIFIER"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("MENUBARINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "idObject", "idItem", "pmbi"]),
        #
        'GetScrollBarInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="OBJECT_IDENTIFIER"), SimTypePointer(SimTypeRef("SCROLLBARINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "idObject", "psbi"]),
        #
        'GetAncestor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_ANCESTOR_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd", "gaFlags"]),
        #
        'RealChildWindowFromPoint': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("POINT", SimStruct)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwndParent", "ptParentClientCoords"]),
        #
        'RealGetWindowClassA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwnd", "ptszClassName", "cchClassNameMax"]),
        #
        'RealGetWindowClassW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwnd", "ptszClassName", "cchClassNameMax"]),
        #
        'GetAltTabInfoA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("ALTTABINFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "iItem", "pati", "pszItemText", "cchItemText"]),
        #
        'GetAltTabInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("ALTTABINFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "iItem", "pati", "pszItemText", "cchItemText"]),
        #
        'ChangeWindowMessageFilter': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="CHANGE_WINDOW_MESSAGE_FILTER_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["message", "dwFlag"]),
        #
        'ChangeWindowMessageFilterEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="WINDOW_MESSAGE_FILTER_ACTION"), SimTypePointer(SimTypeRef("CHANGEFILTERSTRUCT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "message", "action", "pChangeFilterStruct"]),
        #
        'SetAdditionalForegroundBoostProcesses': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["topLevelWindow", "processHandleCount", "processHandleArray"]),
        #
        'RegisterForTooltipDismissNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TOOLTIP_DISMISS_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "tdFlags"]),
        #
        'IsWindowArranged': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
    }

lib.set_prototypes(prototypes)
