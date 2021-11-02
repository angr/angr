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
lib.set_library_names("dwmapi.dll")
prototypes = \
    {
        # 
        'DwmDefWindowProc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "msg", "wParam", "lParam", "plResult"]),
        # 
        'DwmEnableBlurBehindWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"dwFlags": SimTypeInt(signed=False, label="UInt32"), "fEnable": SimTypeInt(signed=True, label="Int32"), "hRgnBlur": SimTypeBottom(label="HRGN"), "fTransitionOnMaximized": SimTypeInt(signed=True, label="Int32")}, name="DWM_BLURBEHIND", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "pBlurBehind"]),
        # 
        'DwmEnableComposition': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["uCompositionAction"]),
        # 
        'DwmEnableMMCSS': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fEnableMMCSS"]),
        # 
        'DwmExtendFrameIntoClientArea': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"cxLeftWidth": SimTypeInt(signed=True, label="Int32"), "cxRightWidth": SimTypeInt(signed=True, label="Int32"), "cyTopHeight": SimTypeInt(signed=True, label="Int32"), "cyBottomHeight": SimTypeInt(signed=True, label="Int32")}, name="MARGINS", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "pMarInset"]),
        # 
        'DwmGetColorizationColor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcrColorization", "pfOpaqueBlend"]),
        # 
        'DwmGetCompositionTimingInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "rateRefresh": SimStruct({"uiNumerator": SimTypeInt(signed=False, label="UInt32"), "uiDenominator": SimTypeInt(signed=False, label="UInt32")}, name="UNSIGNED_RATIO", pack=False, align=None), "qpcRefreshPeriod": SimTypeLongLong(signed=False, label="UInt64"), "rateCompose": SimStruct({"uiNumerator": SimTypeInt(signed=False, label="UInt32"), "uiDenominator": SimTypeInt(signed=False, label="UInt32")}, name="UNSIGNED_RATIO", pack=False, align=None), "qpcVBlank": SimTypeLongLong(signed=False, label="UInt64"), "cRefresh": SimTypeLongLong(signed=False, label="UInt64"), "cDXRefresh": SimTypeInt(signed=False, label="UInt32"), "qpcCompose": SimTypeLongLong(signed=False, label="UInt64"), "cFrame": SimTypeLongLong(signed=False, label="UInt64"), "cDXPresent": SimTypeInt(signed=False, label="UInt32"), "cRefreshFrame": SimTypeLongLong(signed=False, label="UInt64"), "cFrameSubmitted": SimTypeLongLong(signed=False, label="UInt64"), "cDXPresentSubmitted": SimTypeInt(signed=False, label="UInt32"), "cFrameConfirmed": SimTypeLongLong(signed=False, label="UInt64"), "cDXPresentConfirmed": SimTypeInt(signed=False, label="UInt32"), "cRefreshConfirmed": SimTypeLongLong(signed=False, label="UInt64"), "cDXRefreshConfirmed": SimTypeInt(signed=False, label="UInt32"), "cFramesLate": SimTypeLongLong(signed=False, label="UInt64"), "cFramesOutstanding": SimTypeInt(signed=False, label="UInt32"), "cFrameDisplayed": SimTypeLongLong(signed=False, label="UInt64"), "qpcFrameDisplayed": SimTypeLongLong(signed=False, label="UInt64"), "cRefreshFrameDisplayed": SimTypeLongLong(signed=False, label="UInt64"), "cFrameComplete": SimTypeLongLong(signed=False, label="UInt64"), "qpcFrameComplete": SimTypeLongLong(signed=False, label="UInt64"), "cFramePending": SimTypeLongLong(signed=False, label="UInt64"), "qpcFramePending": SimTypeLongLong(signed=False, label="UInt64"), "cFramesDisplayed": SimTypeLongLong(signed=False, label="UInt64"), "cFramesComplete": SimTypeLongLong(signed=False, label="UInt64"), "cFramesPending": SimTypeLongLong(signed=False, label="UInt64"), "cFramesAvailable": SimTypeLongLong(signed=False, label="UInt64"), "cFramesDropped": SimTypeLongLong(signed=False, label="UInt64"), "cFramesMissed": SimTypeLongLong(signed=False, label="UInt64"), "cRefreshNextDisplayed": SimTypeLongLong(signed=False, label="UInt64"), "cRefreshNextPresented": SimTypeLongLong(signed=False, label="UInt64"), "cRefreshesDisplayed": SimTypeLongLong(signed=False, label="UInt64"), "cRefreshesPresented": SimTypeLongLong(signed=False, label="UInt64"), "cRefreshStarted": SimTypeLongLong(signed=False, label="UInt64"), "cPixelsReceived": SimTypeLongLong(signed=False, label="UInt64"), "cPixelsDrawn": SimTypeLongLong(signed=False, label="UInt64"), "cBuffersEmpty": SimTypeLongLong(signed=False, label="UInt64")}, name="DWM_TIMING_INFO", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pTimingInfo"]),
        # 
        'DwmGetWindowAttribute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DWMWINDOWATTRIBUTE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "dwAttribute", "pvAttribute", "cbAttribute"]),
        # 
        'DwmIsCompositionEnabled': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfEnabled"]),
        # 
        'DwmModifyPreviousDxFrameDuration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "cRefreshes", "fRelative"]),
        # 
        'DwmQueryThumbnailSourceSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"cx": SimTypeInt(signed=True, label="Int32"), "cy": SimTypeInt(signed=True, label="Int32")}, name="SIZE", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThumbnail", "pSize"]),
        # 
        'DwmRegisterThumbnail': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndDestination", "hwndSource", "phThumbnailId"]),
        # 
        'DwmSetDxFrameDuration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "cRefreshes"]),
        # 
        'DwmSetPresentParameters': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "fQueue": SimTypeInt(signed=True, label="Int32"), "cRefreshStart": SimTypeLongLong(signed=False, label="UInt64"), "cBuffer": SimTypeInt(signed=False, label="UInt32"), "fUseSourceRate": SimTypeInt(signed=True, label="Int32"), "rateSource": SimStruct({"uiNumerator": SimTypeInt(signed=False, label="UInt32"), "uiDenominator": SimTypeInt(signed=False, label="UInt32")}, name="UNSIGNED_RATIO", pack=False, align=None), "cRefreshesPerFrame": SimTypeInt(signed=False, label="UInt32"), "eSampling": SimTypeInt(signed=False, label="DWM_SOURCE_FRAME_SAMPLING")}, name="DWM_PRESENT_PARAMETERS", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pPresentParams"]),
        # 
        'DwmSetWindowAttribute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DWMWINDOWATTRIBUTE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "dwAttribute", "pvAttribute", "cbAttribute"]),
        # 
        'DwmUnregisterThumbnail': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThumbnailId"]),
        # 
        'DwmUpdateThumbnailProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"dwFlags": SimTypeInt(signed=False, label="UInt32"), "rcDestination": SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), "rcSource": SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), "opacity": SimTypeChar(label="Byte"), "fVisible": SimTypeInt(signed=True, label="Int32"), "fSourceClientAreaOnly": SimTypeInt(signed=True, label="Int32")}, name="DWM_THUMBNAIL_PROPERTIES", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThumbnailId", "ptnProperties"]),
        # 
        'DwmSetIconicThumbnail': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "hbmp", "dwSITFlags"]),
        # 
        'DwmSetIconicLivePreviewBitmap': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"x": SimTypeInt(signed=True, label="Int32"), "y": SimTypeInt(signed=True, label="Int32")}, name="POINT", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "hbmp", "pptClient", "dwSITFlags"]),
        # 
        'DwmInvalidateIconicBitmaps': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        # 
        'DwmAttachMilContent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        # 
        'DwmDetachMilContent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        # 
        'DwmFlush': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        # 
        'DwmGetGraphicsStreamTransformHint': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"S_11": SimTypeFloat(size=64), "S_12": SimTypeFloat(size=64), "S_21": SimTypeFloat(size=64), "S_22": SimTypeFloat(size=64), "DX": SimTypeFloat(size=64), "DY": SimTypeFloat(size=64)}, name="MilMatrix3x2D", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uIndex", "pTransform"]),
        # 
        'DwmGetGraphicsStreamClient': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uIndex", "pClientUuid"]),
        # 
        'DwmGetTransportAttributes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfIsRemoting", "pfIsConnected", "pDwGeneration"]),
        # 
        'DwmTransitionOwnedWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DWMTRANSITION_OWNEDWINDOW_TARGET")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "target"]),
        # 
        'DwmRenderGesture': SimTypeFunction([SimTypeInt(signed=False, label="GESTURE_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimStruct({"x": SimTypeInt(signed=True, label="Int32"), "y": SimTypeInt(signed=True, label="Int32")}, name="POINT", pack=False, align=None), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["gt", "cContacts", "pdwPointerID", "pPoints"]),
        # 
        'DwmTetherContact': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimStruct({"x": SimTypeInt(signed=True, label="Int32"), "y": SimTypeInt(signed=True, label="Int32")}, name="POINT", pack=False, align=None)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwPointerID", "fEnable", "ptTether"]),
        # 
        'DwmShowContact': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DWM_SHOWCONTACT")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwPointerID", "eShowContact"]),
        # 
        'DwmGetUnmetTabRequirements': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="DWM_TAB_WINDOW_REQUIREMENTS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["appWindow", "value"]),
    }

lib.set_prototypes(prototypes)
