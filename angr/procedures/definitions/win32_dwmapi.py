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
lib.set_library_names("dwmapi.dll")
prototypes = \
    {
        #
        'DwmDefWindowProc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "msg", "wParam", "lParam", "plResult"]),
        #
        'DwmEnableBlurBehindWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DWM_BLURBEHIND", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "pBlurBehind"]),
        #
        'DwmEnableComposition': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["uCompositionAction"]),
        #
        'DwmEnableMMCSS': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fEnableMMCSS"]),
        #
        'DwmExtendFrameIntoClientArea': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MARGINS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "pMarInset"]),
        #
        'DwmGetColorizationColor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcrColorization", "pfOpaqueBlend"]),
        #
        'DwmGetCompositionTimingInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DWM_TIMING_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pTimingInfo"]),
        #
        'DwmGetWindowAttribute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "dwAttribute", "pvAttribute", "cbAttribute"]),
        #
        'DwmIsCompositionEnabled': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfEnabled"]),
        #
        'DwmModifyPreviousDxFrameDuration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "cRefreshes", "fRelative"]),
        #
        'DwmQueryThumbnailSourceSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThumbnail", "pSize"]),
        #
        'DwmRegisterThumbnail': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndDestination", "hwndSource", "phThumbnailId"]),
        #
        'DwmSetDxFrameDuration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "cRefreshes"]),
        #
        'DwmSetPresentParameters': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DWM_PRESENT_PARAMETERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pPresentParams"]),
        #
        'DwmSetWindowAttribute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "dwAttribute", "pvAttribute", "cbAttribute"]),
        #
        'DwmUnregisterThumbnail': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThumbnailId"]),
        #
        'DwmUpdateThumbnailProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DWM_THUMBNAIL_PROPERTIES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThumbnailId", "ptnProperties"]),
        #
        'DwmSetIconicThumbnail': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "hbmp", "dwSITFlags"]),
        #
        'DwmSetIconicLivePreviewBitmap': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "hbmp", "pptClient", "dwSITFlags"]),
        #
        'DwmInvalidateIconicBitmaps': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'DwmAttachMilContent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'DwmDetachMilContent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'DwmFlush': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'DwmGetGraphicsStreamTransformHint': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MilMatrix3x2D", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uIndex", "pTransform"]),
        #
        'DwmGetGraphicsStreamClient': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uIndex", "pClientUuid"]),
        #
        'DwmGetTransportAttributes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfIsRemoting", "pfIsConnected", "pDwGeneration"]),
        #
        'DwmTransitionOwnedWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DWMTRANSITION_OWNEDWINDOW_TARGET")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "target"]),
        #
        'DwmRenderGesture': SimTypeFunction([SimTypeInt(signed=False, label="GESTURE_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["gt", "cContacts", "pdwPointerID", "pPoints"]),
        #
        'DwmTetherContact': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeRef("POINT", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwPointerID", "fEnable", "ptTether"]),
        #
        'DwmShowContact': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DWM_SHOWCONTACT")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwPointerID", "eShowContact"]),
        #
        'DwmGetUnmetTabRequirements': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="DWM_TAB_WINDOW_REQUIREMENTS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["appWindow", "value"]),
    }

lib.set_prototypes(prototypes)
