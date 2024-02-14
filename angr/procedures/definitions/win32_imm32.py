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
lib.set_library_names("imm32.dll")
prototypes = \
    {
        #
        'ImmInstallIMEA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszIMEFileName", "lpszLayoutText"]),
        #
        'ImmInstallIMEW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszIMEFileName", "lpszLayoutText"]),
        #
        'ImmGetDefaultIMEWnd': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0"]),
        #
        'ImmGetDescriptionA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "lpszDescription", "uBufLen"]),
        #
        'ImmGetDescriptionW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "lpszDescription", "uBufLen"]),
        #
        'ImmGetIMEFileNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "lpszFileName", "uBufLen"]),
        #
        'ImmGetIMEFileNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "lpszFileName", "uBufLen"]),
        #
        'ImmGetProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1"]),
        #
        'ImmIsIME': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'ImmSimulateHotKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="IME_HOTKEY_IDENTIFIER")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'ImmCreateContext': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'ImmDestroyContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'ImmGetContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0"]),
        #
        'ImmReleaseContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'ImmAssociateContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1"]),
        #
        'ImmAssociateContextEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]),
        #
        'ImmGetCompositionStringA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="IME_COMPOSITION_STRING"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "lpBuf", "dwBufLen"]),
        #
        'ImmGetCompositionStringW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="IME_COMPOSITION_STRING"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "lpBuf", "dwBufLen"]),
        #
        'ImmSetCompositionStringA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SET_COMPOSITION_STRING_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "dwIndex", "lpComp", "dwCompLen", "lpRead", "dwReadLen"]),
        #
        'ImmSetCompositionStringW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SET_COMPOSITION_STRING_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "dwIndex", "lpComp", "dwCompLen", "lpRead", "dwReadLen"]),
        #
        'ImmGetCandidateListCountA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "lpdwListCount"]),
        #
        'ImmGetCandidateListCountW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "lpdwListCount"]),
        #
        'ImmGetCandidateListA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CANDIDATELIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "deIndex", "lpCandList", "dwBufLen"]),
        #
        'ImmGetCandidateListW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CANDIDATELIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "deIndex", "lpCandList", "dwBufLen"]),
        #
        'ImmGetGuideLineA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_GUIDE_LINE_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "dwIndex", "lpBuf", "dwBufLen"]),
        #
        'ImmGetGuideLineW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_GUIDE_LINE_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "dwIndex", "lpBuf", "dwBufLen"]),
        #
        'ImmGetConversionStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="IME_CONVERSION_MODE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="IME_SENTENCE_MODE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lpfdwConversion", "lpfdwSentence"]),
        #
        'ImmSetConversionStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="IME_CONVERSION_MODE"), SimTypeInt(signed=False, label="IME_SENTENCE_MODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]),
        #
        'ImmGetOpenStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'ImmSetOpenStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'ImmGetCompositionFontA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LOGFONTA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lplf"]),
        #
        'ImmGetCompositionFontW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LOGFONTW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lplf"]),
        #
        'ImmSetCompositionFontA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LOGFONTA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lplf"]),
        #
        'ImmSetCompositionFontW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LOGFONTW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lplf"]),
        #
        'ImmConfigureIMEA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'ImmConfigureIMEW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'ImmEscapeA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="IME_ESCAPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'ImmEscapeW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="IME_ESCAPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'ImmGetConversionListA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("CANDIDATELIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="GET_CONVERSION_LIST_FLAG")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "lpSrc", "lpDst", "dwBufLen", "uFlag"]),
        #
        'ImmGetConversionListW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CANDIDATELIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="GET_CONVERSION_LIST_FLAG")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "lpSrc", "lpDst", "dwBufLen", "uFlag"]),
        #
        'ImmNotifyIME': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="NOTIFY_IME_ACTION"), SimTypeInt(signed=False, label="NOTIFY_IME_INDEX"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "dwAction", "dwIndex", "dwValue"]),
        #
        'ImmGetStatusWindowPos': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lpptPos"]),
        #
        'ImmSetStatusWindowPos': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lpptPos"]),
        #
        'ImmGetCompositionWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("COMPOSITIONFORM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lpCompForm"]),
        #
        'ImmSetCompositionWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("COMPOSITIONFORM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lpCompForm"]),
        #
        'ImmGetCandidateWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CANDIDATEFORM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "lpCandidate"]),
        #
        'ImmSetCandidateWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CANDIDATEFORM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lpCandidate"]),
        #
        'ImmIsUIMessageA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'ImmIsUIMessageW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'ImmGetVirtualKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'ImmRegisterWordA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lpszReading", "param2", "lpszRegister"]),
        #
        'ImmRegisterWordW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lpszReading", "param2", "lpszRegister"]),
        #
        'ImmUnregisterWordA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lpszReading", "param2", "lpszUnregister"]),
        #
        'ImmUnregisterWordW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lpszReading", "param2", "lpszUnregister"]),
        #
        'ImmGetRegisterWordStyleA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("STYLEBUFA", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "nItem", "lpStyleBuf"]),
        #
        'ImmGetRegisterWordStyleW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("STYLEBUFW", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "nItem", "lpStyleBuf"]),
        #
        'ImmEnumRegisterWordA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszReading", "param1", "lpszString", "param3"]), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "lpszReading", "param3", "lpszRegister", "param5"]),
        #
        'ImmEnumRegisterWordW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszReading", "param1", "lpszString", "param3"]), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "lpszReading", "param3", "lpszRegister", "param5"]),
        #
        'ImmDisableIME': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'ImmEnumInputContext': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idThread", "lpfn", "lParam"]),
        #
        'ImmGetImeMenuItemsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IMEMENUITEMINFOA", SimStruct), offset=0), SimTypePointer(SimTypeRef("IMEMENUITEMINFOA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "lpImeParentMenu", "lpImeMenu", "dwSize"]),
        #
        'ImmGetImeMenuItemsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IMEMENUITEMINFOW", SimStruct), offset=0), SimTypePointer(SimTypeRef("IMEMENUITEMINFOW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "lpImeParentMenu", "lpImeMenu", "dwSize"]),
        #
        'ImmDisableTextFrameService': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["idThread"]),
        #
        'ImmDisableLegacyIME': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'ImmGetHotKey': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "lpuModifiers", "lpuVKey", "phKL"]),
        #
        'ImmSetHotKey': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'ImmGenerateMessage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'ImmRequestMessageA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'ImmRequestMessageW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'ImmCreateSoftKeyboard': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'ImmDestroySoftKeyboard': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'ImmShowSoftKeyboard': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]),
        #
        'ImmLockIMC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeRef("INPUTCONTEXT", SimStruct), offset=0), arg_names=["param0"]),
        #
        'ImmUnlockIMC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'ImmGetIMCLockCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'ImmCreateIMCC': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0"]),
        #
        'ImmDestroyIMCC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0"]),
        #
        'ImmLockIMCC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["param0"]),
        #
        'ImmUnlockIMCC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'ImmGetIMCCLockCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'ImmReSizeIMCC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0", "param1"]),
        #
        'ImmGetIMCCSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
    }

lib.set_prototypes(prototypes)
