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
lib.set_library_names("uxtheme.dll")
prototypes = \
    {
        #
        'BeginPanningFeedback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'UpdatePanningFeedback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "lTotalOverpanOffsetX", "lTotalOverpanOffsetY", "fInInertia"]),
        #
        'EndPanningFeedback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "fAnimateBack"]),
        #
        'GetThemeAnimationProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="TA_PROPERTY"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iStoryboardId", "iTargetId", "eProperty", "pvProperty", "cbSize", "pcbSizeOut"]),
        #
        'GetThemeAnimationTransform': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TA_TRANSFORM", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iStoryboardId", "iTargetId", "dwTransformIndex", "pTransform", "cbSize", "pcbSizeOut"]),
        #
        'GetThemeTimingFunction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("TA_TIMINGFUNCTION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iTimingFunctionId", "pTimingFunction", "cbSize", "pcbSizeOut"]),
        #
        'OpenThemeData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd", "pszClassList"]),
        #
        'OpenThemeDataEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="OPEN_THEME_DATA_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd", "pszClassList", "dwFlags"]),
        #
        'CloseThemeData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme"]),
        #
        'DrawThemeBackground': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "pRect", "pClipRect"]),
        #
        'DrawThemeBackgroundEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DTBGOPTS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "pRect", "pOptions"]),
        #
        'DrawThemeText': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="DRAW_TEXT_FORMAT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "pszText", "cchText", "dwTextFlags", "dwTextFlags2", "pRect"]),
        #
        'GetThemeBackgroundContentRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "pBoundingRect", "pContentRect"]),
        #
        'GetThemeBackgroundExtent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "pContentRect", "pExtentRect"]),
        #
        'GetThemeBackgroundRegion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "pRect", "pRegion"]),
        #
        'GetThemePartSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="THEMESIZE"), SimTypePointer(SimTypeRef("SIZE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "prc", "eSize", "psz"]),
        #
        'GetThemeTextExtent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="DRAW_TEXT_FORMAT"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "pszText", "cchCharCount", "dwTextFlags", "pBoundingRect", "pExtentRect"]),
        #
        'GetThemeTextMetrics': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("TEXTMETRICW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "ptm"]),
        #
        'HitTestThemeBackground': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="HIT_TEST_BACKGROUND_OPTIONS"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("POINT", SimStruct), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "dwOptions", "pRect", "hrgn", "ptTest", "pwHitTestCode"]),
        #
        'DrawThemeEdge': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="DRAWEDGE_FLAGS"), SimTypeInt(signed=False, label="DRAW_EDGE_FLAGS"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "pDestRect", "uEdge", "uFlags", "pContentRect"]),
        #
        'DrawThemeIcon': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "pRect", "himl", "iImageIndex"]),
        #
        'IsThemePartDefined': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId"]),
        #
        'IsThemeBackgroundPartiallyTransparent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId"]),
        #
        'GetThemeColor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId", "iPropId", "pColor"]),
        #
        'GetThemeMetric': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "iPropId", "piVal"]),
        #
        'GetThemeString': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId", "iPropId", "pszBuff", "cchMaxBuffChars"]),
        #
        'GetThemeBool': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId", "iPropId", "pfVal"]),
        #
        'GetThemeInt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId", "iPropId", "piVal"]),
        #
        'GetThemeEnumValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId", "iPropId", "piVal"]),
        #
        'GetThemePosition': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId", "iPropId", "pPoint"]),
        #
        'GetThemeFont': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("LOGFONTW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "iPropId", "pFont"]),
        #
        'GetThemeRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId", "iPropId", "pRect"]),
        #
        'GetThemeMargins': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("MARGINS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "iPropId", "prc", "pMargins"]),
        #
        'GetThemeIntList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("INTLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId", "iPropId", "pIntList"]),
        #
        'GetThemePropertyOrigin': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="PROPERTYORIGIN"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId", "iPropId", "pOrigin"]),
        #
        'SetWindowTheme': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszSubAppName", "pszSubIdList"]),
        #
        'GetThemeFilename': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId", "iPropId", "pszThemeFileName", "cchMaxBuffChars"]),
        #
        'GetThemeSysColor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hTheme", "iColorId"]),
        #
        'GetThemeSysColorBrush': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hTheme", "iColorId"]),
        #
        'GetThemeSysBool': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iBoolId"]),
        #
        'GetThemeSysSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iSizeId"]),
        #
        'GetThemeSysFont': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("LOGFONTW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iFontId", "plf"]),
        #
        'GetThemeSysString': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iStringId", "pszStringBuff", "cchMaxStringChars"]),
        #
        'GetThemeSysInt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iIntId", "piValue"]),
        #
        'IsThemeActive': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'IsAppThemed': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'GetWindowTheme': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd"]),
        #
        'EnableThemeDialogTexture': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "dwFlags"]),
        #
        'IsThemeDialogTextureEnabled': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'GetThemeAppProperties': SimTypeFunction([], SimTypeInt(signed=False, label="SET_THEME_APP_PROPERTIES_FLAGS")),
        #
        'SetThemeAppProperties': SimTypeFunction([SimTypeInt(signed=False, label="SET_THEME_APP_PROPERTIES_FLAGS")], SimTypeBottom(label="Void"), arg_names=["dwFlags"]),
        #
        'GetCurrentThemeName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszThemeFileName", "cchMaxNameChars", "pszColorBuff", "cchMaxColorChars", "pszSizeBuff", "cchMaxSizeChars"]),
        #
        'GetThemeDocumentationProperty': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszThemeName", "pszPropertyName", "pszValueBuff", "cchMaxValChars"]),
        #
        'DrawThemeParentBackground': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "hdc", "prc"]),
        #
        'EnableTheming': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fEnable"]),
        #
        'DrawThemeParentBackgroundEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DRAW_THEME_PARENT_BACKGROUND_FLAGS"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "hdc", "dwFlags", "prc"]),
        #
        'SetWindowThemeAttribute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WINDOWTHEMEATTRIBUTETYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "eAttribute", "pvAttribute", "cbAttribute"]),
        #
        'DrawThemeTextEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="DRAW_TEXT_FORMAT"), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DTTOPTS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "hdc", "iPartId", "iStateId", "pszText", "cchText", "dwTextFlags", "pRect", "pOptions"]),
        #
        'GetThemeBitmap': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="GET_THEME_BITMAP_FLAGS"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId", "iPropId", "dwFlags", "phBitmap"]),
        #
        'GetThemeStream': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateId", "iPropId", "ppvStream", "pcbStream", "hInst"]),
        #
        'BufferedPaintInit': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'BufferedPaintUnInit': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'BeginBufferedPaint': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="BP_BUFFERFORMAT"), SimTypePointer(SimTypeRef("BP_PAINTPARAMS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdcTarget", "prcTarget", "dwFormat", "pPaintParams", "phdc"]),
        #
        'EndBufferedPaint': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hBufferedPaint", "fUpdateTarget"]),
        #
        'GetBufferedPaintTargetRect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hBufferedPaint", "prc"]),
        #
        'GetBufferedPaintTargetDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hBufferedPaint"]),
        #
        'GetBufferedPaintDC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hBufferedPaint"]),
        #
        'GetBufferedPaintBits': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("RGBQUAD", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hBufferedPaint", "ppbBuffer", "pcxRow"]),
        #
        'BufferedPaintClear': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hBufferedPaint", "prc"]),
        #
        'BufferedPaintSetAlpha': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["hBufferedPaint", "prc", "alpha"]),
        #
        'BufferedPaintStopAllAnimations': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'BeginBufferedAnimation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0), SimTypeInt(signed=False, label="BP_BUFFERFORMAT"), SimTypePointer(SimTypeRef("BP_PAINTPARAMS", SimStruct), offset=0), SimTypePointer(SimTypeRef("BP_ANIMATIONPARAMS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd", "hdcTarget", "prcTarget", "dwFormat", "pPaintParams", "pAnimationParams", "phdcFrom", "phdcTo"]),
        #
        'EndBufferedAnimation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hbpAnimation", "fUpdateTarget"]),
        #
        'BufferedPaintRenderAnimation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "hdcTarget"]),
        #
        'IsCompositionActive': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'GetThemeTransitionDuration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTheme", "iPartId", "iStateIdFrom", "iStateIdTo", "iPropId", "pdwDuration"]),
        #
        'OpenThemeDataForDpi': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd", "pszClassList", "dpi"]),
    }

lib.set_prototypes(prototypes)
