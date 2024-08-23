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
lib.set_library_names("icu.dll")
prototypes = \
    {
        #
        'utf8_nextCharSafeBody': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="SByte")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "pi", "length", "c", "strict"]),
        #
        'utf8_appendCharSafeBody': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "i", "length", "c", "pIsError"]),
        #
        'utf8_prevCharSafeBody': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="SByte")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "start", "pi", "c", "strict"]),
        #
        'utf8_back1SafeBody': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "start", "i"]),
        #
        'u_versionFromString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["versionArray", "versionString"]),
        #
        'u_versionFromUString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["versionArray", "versionString"]),
        #
        'u_versionToString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["versionArray", "versionString"]),
        #
        'u_getVersion': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["versionArray"]),
        #
        'u_errorName': SimTypeFunction([SimTypeInt(signed=False, label="UErrorCode")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["code"]),
        #
        'utrace_setLevel': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["traceLevel"]),
        #
        'utrace_getLevel': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'utrace_setFunctions': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["context", "fnNumber"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "fnNumber", "fmt", "args"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "fnNumber", "level", "fmt", "args"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "e", "x", "d"]),
        #
        'utrace_getFunctions': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["context", "fnNumber"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "fnNumber", "fmt", "args"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "fnNumber", "level", "fmt", "args"]), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "e", "x", "d"]),
        #
        'utrace_vformat': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["outBuf", "capacity", "indent", "fmt", "args"]),
        #
        'utrace_format': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["outBuf", "capacity", "indent", "fmt"]),
        #
        'utrace_functionName': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["fnNumber"]),
        #
        'u_shapeArabic': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["source", "sourceLength", "dest", "destSize", "options", "pErrorCode"]),
        #
        'uscript_getCode': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UScriptCode"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nameOrAbbrOrLocale", "fillIn", "capacity", "err"]),
        #
        'uscript_getName': SimTypeFunction([SimTypeInt(signed=False, label="UScriptCode")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["scriptCode"]),
        #
        'uscript_getShortName': SimTypeFunction([SimTypeInt(signed=False, label="UScriptCode")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["scriptCode"]),
        #
        'uscript_getScript': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UScriptCode"), arg_names=["codepoint", "err"]),
        #
        'uscript_hasScript': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UScriptCode")], SimTypeChar(label="SByte"), arg_names=["c", "sc"]),
        #
        'uscript_getScriptExtensions': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UScriptCode"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["c", "scripts", "capacity", "errorCode"]),
        #
        'uscript_getSampleString': SimTypeFunction([SimTypeInt(signed=False, label="UScriptCode"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["script", "dest", "capacity", "pErrorCode"]),
        #
        'uscript_getUsage': SimTypeFunction([SimTypeInt(signed=False, label="UScriptCode")], SimTypeInt(signed=False, label="UScriptUsage"), arg_names=["script"]),
        #
        'uscript_isRightToLeft': SimTypeFunction([SimTypeInt(signed=False, label="UScriptCode")], SimTypeChar(label="SByte"), arg_names=["script"]),
        #
        'uscript_breaksBetweenLetters': SimTypeFunction([SimTypeInt(signed=False, label="UScriptCode")], SimTypeChar(label="SByte"), arg_names=["script"]),
        #
        'uscript_isCased': SimTypeFunction([SimTypeInt(signed=False, label="UScriptCode")], SimTypeChar(label="SByte"), arg_names=["script"]),
        #
        'uiter_current32': SimTypeFunction([SimTypePointer(SimTypeRef("UCharIterator", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iter"]),
        #
        'uiter_next32': SimTypeFunction([SimTypePointer(SimTypeRef("UCharIterator", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iter"]),
        #
        'uiter_previous32': SimTypeFunction([SimTypePointer(SimTypeRef("UCharIterator", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iter"]),
        #
        'uiter_getState': SimTypeFunction([SimTypePointer(SimTypeRef("UCharIterator", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["iter"]),
        #
        'uiter_setState': SimTypeFunction([SimTypePointer(SimTypeRef("UCharIterator", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["iter", "state", "pErrorCode"]),
        #
        'uiter_setString': SimTypeFunction([SimTypePointer(SimTypeRef("UCharIterator", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["iter", "s", "length"]),
        #
        'uiter_setUTF16BE': SimTypeFunction([SimTypePointer(SimTypeRef("UCharIterator", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["iter", "s", "length"]),
        #
        'uiter_setUTF8': SimTypeFunction([SimTypePointer(SimTypeRef("UCharIterator", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["iter", "s", "length"]),
        #
        'uenum_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["en"]),
        #
        'uenum_count': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["en", "status"]),
        #
        'uenum_unext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["en", "resultLength", "status"]),
        #
        'uenum_next': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["en", "resultLength", "status"]),
        #
        'uenum_reset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["en", "status"]),
        #
        'uenum_openUCharStringsEnumeration': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["strings", "count", "ec"]),
        #
        'uenum_openCharStringsEnumeration': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["strings", "count", "ec"]),
        #
        'uloc_getDefault': SimTypeFunction([], SimTypePointer(SimTypeChar(label="Byte"), offset=0)),
        #
        'uloc_setDefault': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["localeID", "status"]),
        #
        'uloc_getLanguage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localeID", "language", "languageCapacity", "err"]),
        #
        'uloc_getScript': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localeID", "script", "scriptCapacity", "err"]),
        #
        'uloc_getCountry': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localeID", "country", "countryCapacity", "err"]),
        #
        'uloc_getVariant': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localeID", "variant", "variantCapacity", "err"]),
        #
        'uloc_getName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localeID", "name", "nameCapacity", "err"]),
        #
        'uloc_canonicalize': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localeID", "name", "nameCapacity", "err"]),
        #
        'uloc_getISO3Language': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["localeID"]),
        #
        'uloc_getISO3Country': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["localeID"]),
        #
        'uloc_getLCID': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["localeID"]),
        #
        'uloc_getDisplayLanguage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["locale", "displayLocale", "language", "languageCapacity", "status"]),
        #
        'uloc_getDisplayScript': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["locale", "displayLocale", "script", "scriptCapacity", "status"]),
        #
        'uloc_getDisplayCountry': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["locale", "displayLocale", "country", "countryCapacity", "status"]),
        #
        'uloc_getDisplayVariant': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["locale", "displayLocale", "variant", "variantCapacity", "status"]),
        #
        'uloc_getDisplayKeyword': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["keyword", "displayLocale", "dest", "destCapacity", "status"]),
        #
        'uloc_getDisplayKeywordValue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["locale", "keyword", "displayLocale", "dest", "destCapacity", "status"]),
        #
        'uloc_getDisplayName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localeID", "inLocaleID", "result", "maxResultSize", "err"]),
        #
        'uloc_getAvailable': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["n"]),
        #
        'uloc_countAvailable': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'uloc_openAvailableByType': SimTypeFunction([SimTypeInt(signed=False, label="ULocAvailableType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["type", "status"]),
        #
        'uloc_getISOLanguages': SimTypeFunction([], SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)),
        #
        'uloc_getISOCountries': SimTypeFunction([], SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)),
        #
        'uloc_getParent': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localeID", "parent", "parentCapacity", "err"]),
        #
        'uloc_getBaseName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localeID", "name", "nameCapacity", "err"]),
        #
        'uloc_openKeywords': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["localeID", "status"]),
        #
        'uloc_getKeywordValue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localeID", "keywordName", "buffer", "bufferCapacity", "status"]),
        #
        'uloc_setKeywordValue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["keywordName", "keywordValue", "buffer", "bufferCapacity", "status"]),
        #
        'uloc_isRightToLeft': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="SByte"), arg_names=["locale"]),
        #
        'uloc_getCharacterOrientation': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="ULayoutType"), arg_names=["localeId", "status"]),
        #
        'uloc_getLineOrientation': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="ULayoutType"), arg_names=["localeId", "status"]),
        #
        'uloc_acceptLanguageFromHTTP': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UAcceptResult"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["result", "resultAvailable", "outResult", "httpAcceptLanguage", "availableLocales", "status"]),
        #
        'uloc_acceptLanguage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UAcceptResult"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["result", "resultAvailable", "outResult", "acceptList", "acceptListCount", "availableLocales", "status"]),
        #
        'uloc_getLocaleForLCID': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hostID", "locale", "localeCapacity", "status"]),
        #
        'uloc_addLikelySubtags': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localeID", "maximizedLocaleID", "maximizedLocaleIDCapacity", "err"]),
        #
        'uloc_minimizeSubtags': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localeID", "minimizedLocaleID", "minimizedLocaleIDCapacity", "err"]),
        #
        'uloc_forLanguageTag': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["langtag", "localeID", "localeIDCapacity", "parsedLength", "err"]),
        #
        'uloc_toLanguageTag': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localeID", "langtag", "langtagCapacity", "strict", "err"]),
        #
        'uloc_toUnicodeLocaleKey': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["keyword"]),
        #
        'uloc_toUnicodeLocaleType': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["keyword", "value"]),
        #
        'uloc_toLegacyKey': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["keyword"]),
        #
        'uloc_toLegacyType': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["keyword", "value"]),
        #
        'ures_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["packageName", "locale", "status"]),
        #
        'ures_openDirect': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["packageName", "locale", "status"]),
        #
        'ures_openU': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["packageName", "locale", "status"]),
        #
        'ures_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["resourceBundle"]),
        #
        'ures_getVersion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["resB", "versionInfo"]),
        #
        'ures_getLocaleByType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ULocDataLocaleType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["resourceBundle", "type", "status"]),
        #
        'ures_getString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["resourceBundle", "len", "status"]),
        #
        'ures_getUTF8String': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["resB", "dest", "length", "forceCopy", "status"]),
        #
        'ures_getBinary': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["resourceBundle", "len", "status"]),
        #
        'ures_getIntVector': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), arg_names=["resourceBundle", "len", "status"]),
        #
        'ures_getUInt': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["resourceBundle", "status"]),
        #
        'ures_getInt': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["resourceBundle", "status"]),
        #
        'ures_getSize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["resourceBundle"]),
        #
        'ures_getType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UResType"), arg_names=["resourceBundle"]),
        #
        'ures_getKey': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["resourceBundle"]),
        #
        'ures_resetIterator': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["resourceBundle"]),
        #
        'ures_hasNext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["resourceBundle"]),
        #
        'ures_getNextResource': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["resourceBundle", "fillIn", "status"]),
        #
        'ures_getNextString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["resourceBundle", "len", "key", "status"]),
        #
        'ures_getByIndex': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["resourceBundle", "indexR", "fillIn", "status"]),
        #
        'ures_getStringByIndex': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["resourceBundle", "indexS", "len", "status"]),
        #
        'ures_getUTF8StringByIndex': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["resB", "stringIndex", "dest", "pLength", "forceCopy", "status"]),
        #
        'ures_getByKey': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["resourceBundle", "key", "fillIn", "status"]),
        #
        'ures_getStringByKey': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["resB", "key", "len", "status"]),
        #
        'ures_getUTF8StringByKey': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["resB", "key", "dest", "pLength", "forceCopy", "status"]),
        #
        'ures_openAvailableLocales': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["packageName", "status"]),
        #
        'uldn_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UDialectHandling"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["locale", "dialectHandling", "pErrorCode"]),
        #
        'uldn_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["ldn"]),
        #
        'uldn_getLocale': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["ldn"]),
        #
        'uldn_getDialectHandling': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UDialectHandling"), arg_names=["ldn"]),
        #
        'uldn_localeDisplayName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ldn", "locale", "result", "maxResultSize", "pErrorCode"]),
        #
        'uldn_languageDisplayName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ldn", "lang", "result", "maxResultSize", "pErrorCode"]),
        #
        'uldn_scriptDisplayName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ldn", "script", "result", "maxResultSize", "pErrorCode"]),
        #
        'uldn_scriptCodeDisplayName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UScriptCode"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ldn", "scriptCode", "result", "maxResultSize", "pErrorCode"]),
        #
        'uldn_regionDisplayName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ldn", "region", "result", "maxResultSize", "pErrorCode"]),
        #
        'uldn_variantDisplayName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ldn", "variant", "result", "maxResultSize", "pErrorCode"]),
        #
        'uldn_keyDisplayName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ldn", "key", "result", "maxResultSize", "pErrorCode"]),
        #
        'uldn_keyValueDisplayName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ldn", "key", "value", "result", "maxResultSize", "pErrorCode"]),
        #
        'uldn_openForContext': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UDisplayContext"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["locale", "contexts", "length", "pErrorCode"]),
        #
        'uldn_getContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UDisplayContextType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UDisplayContext"), arg_names=["ldn", "type", "pErrorCode"]),
        #
        'ucurr_forLocale': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["locale", "buff", "buffCapacity", "ec"]),
        #
        'ucurr_register': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["isoCode", "locale", "status"]),
        #
        'ucurr_unregister': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["key", "status"]),
        #
        'ucurr_getName': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UCurrNameStyle"), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["currency", "locale", "nameStyle", "isChoiceFormat", "len", "ec"]),
        #
        'ucurr_getPluralName': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["currency", "locale", "isChoiceFormat", "pluralCount", "len", "ec"]),
        #
        'ucurr_getDefaultFractionDigits': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["currency", "ec"]),
        #
        'ucurr_getDefaultFractionDigitsForUsage': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UCurrencyUsage"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["currency", "usage", "ec"]),
        #
        'ucurr_getRoundingIncrement': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeFloat(size=64), arg_names=["currency", "ec"]),
        #
        'ucurr_getRoundingIncrementForUsage': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UCurrencyUsage"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeFloat(size=64), arg_names=["currency", "usage", "ec"]),
        #
        'ucurr_openISOCurrencies': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["currType", "pErrorCode"]),
        #
        'ucurr_isAvailable': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["isoCode", "from", "to", "errorCode"]),
        #
        'ucurr_countCurrencies': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeFloat(size=64), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["locale", "date", "ec"]),
        #
        'ucurr_forLocaleAndDate': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeFloat(size=64), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["locale", "date", "index", "buff", "buffCapacity", "ec"]),
        #
        'ucurr_getKeywordValuesForLocale': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["key", "locale", "commonlyUsed", "status"]),
        #
        'ucurr_getNumericCode': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["currency"]),
        #
        'ucpmap_get': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["map", "c"]),
        #
        'ucpmap_getRange': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UCPMapRangeOption"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["context", "value"]), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["map", "start", "option", "surrogateValue", "filter", "context", "pValue"]),
        #
        'ucptrie_openFromBinary': SimTypeFunction([SimTypeInt(signed=False, label="UCPTrieType"), SimTypeInt(signed=False, label="UCPTrieValueWidth"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeRef("UCPTrie", SimStruct), offset=0), arg_names=["type", "valueWidth", "data", "length", "pActualLength", "pErrorCode"]),
        #
        'ucptrie_close': SimTypeFunction([SimTypePointer(SimTypeRef("UCPTrie", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["trie"]),
        #
        'ucptrie_getType': SimTypeFunction([SimTypePointer(SimTypeRef("UCPTrie", SimStruct), offset=0)], SimTypeInt(signed=False, label="UCPTrieType"), arg_names=["trie"]),
        #
        'ucptrie_getValueWidth': SimTypeFunction([SimTypePointer(SimTypeRef("UCPTrie", SimStruct), offset=0)], SimTypeInt(signed=False, label="UCPTrieValueWidth"), arg_names=["trie"]),
        #
        'ucptrie_get': SimTypeFunction([SimTypePointer(SimTypeRef("UCPTrie", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["trie", "c"]),
        #
        'ucptrie_getRange': SimTypeFunction([SimTypePointer(SimTypeRef("UCPTrie", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UCPMapRangeOption"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["context", "value"]), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["trie", "start", "option", "surrogateValue", "filter", "context", "pValue"]),
        #
        'ucptrie_toBinary': SimTypeFunction([SimTypePointer(SimTypeRef("UCPTrie", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["trie", "data", "capacity", "pErrorCode"]),
        #
        'ucptrie_internalSmallIndex': SimTypeFunction([SimTypePointer(SimTypeRef("UCPTrie", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["trie", "c"]),
        #
        'ucptrie_internalSmallU8Index': SimTypeFunction([SimTypePointer(SimTypeRef("UCPTrie", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["trie", "lt1", "t2", "t3"]),
        #
        'ucptrie_internalU8PrevIndex': SimTypeFunction([SimTypePointer(SimTypeRef("UCPTrie", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["trie", "c", "start", "src"]),
        #
        'umutablecptrie_open': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["initialValue", "errorValue", "pErrorCode"]),
        #
        'umutablecptrie_clone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["other", "pErrorCode"]),
        #
        'umutablecptrie_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["trie"]),
        #
        'umutablecptrie_fromUCPMap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["map", "pErrorCode"]),
        #
        'umutablecptrie_fromUCPTrie': SimTypeFunction([SimTypePointer(SimTypeRef("UCPTrie", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["trie", "pErrorCode"]),
        #
        'umutablecptrie_get': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["trie", "c"]),
        #
        'umutablecptrie_getRange': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UCPMapRangeOption"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["context", "value"]), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["trie", "start", "option", "surrogateValue", "filter", "context", "pValue"]),
        #
        'umutablecptrie_set': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["trie", "c", "value", "pErrorCode"]),
        #
        'umutablecptrie_setRange': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["trie", "start", "end", "value", "pErrorCode"]),
        #
        'umutablecptrie_buildImmutable': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UCPTrieType"), SimTypeInt(signed=False, label="UCPTrieValueWidth"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeRef("UCPTrie", SimStruct), offset=0), arg_names=["trie", "type", "valueWidth", "pErrorCode"]),
        #
        'UCNV_FROM_U_CALLBACK_STOP': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterFromUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "fromUArgs", "codeUnits", "length", "codePoint", "reason", "err"]),
        #
        'UCNV_TO_U_CALLBACK_STOP': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterToUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "toUArgs", "codeUnits", "length", "reason", "err"]),
        #
        'UCNV_FROM_U_CALLBACK_SKIP': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterFromUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "fromUArgs", "codeUnits", "length", "codePoint", "reason", "err"]),
        #
        'UCNV_FROM_U_CALLBACK_SUBSTITUTE': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterFromUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "fromUArgs", "codeUnits", "length", "codePoint", "reason", "err"]),
        #
        'UCNV_FROM_U_CALLBACK_ESCAPE': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterFromUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "fromUArgs", "codeUnits", "length", "codePoint", "reason", "err"]),
        #
        'UCNV_TO_U_CALLBACK_SKIP': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterToUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "toUArgs", "codeUnits", "length", "reason", "err"]),
        #
        'UCNV_TO_U_CALLBACK_SUBSTITUTE': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterToUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "toUArgs", "codeUnits", "length", "reason", "err"]),
        #
        'UCNV_TO_U_CALLBACK_ESCAPE': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterToUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "toUArgs", "codeUnits", "length", "reason", "err"]),
        #
        'ucnv_compareNames': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["name1", "name2"]),
        #
        'ucnv_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["converterName", "err"]),
        #
        'ucnv_openU': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["name", "err"]),
        #
        'ucnv_openCCSID': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterPlatform"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["codepage", "platform", "err"]),
        #
        'ucnv_openPackage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["packageName", "converterName", "err"]),
        #
        'ucnv_safeClone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["cnv", "stackBuffer", "pBufferSize", "status"]),
        #
        'ucnv_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter"]),
        #
        'ucnv_getSubstChars': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter", "subChars", "len", "err"]),
        #
        'ucnv_setSubstChars': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter", "subChars", "len", "err"]),
        #
        'ucnv_setSubstString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cnv", "s", "length", "err"]),
        #
        'ucnv_getInvalidChars': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter", "errBytes", "len", "err"]),
        #
        'ucnv_getInvalidUChars': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter", "errUChars", "len", "err"]),
        #
        'ucnv_reset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter"]),
        #
        'ucnv_resetToUnicode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter"]),
        #
        'ucnv_resetFromUnicode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter"]),
        #
        'ucnv_getMaxCharSize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["converter"]),
        #
        'ucnv_getMinCharSize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["converter"]),
        #
        'ucnv_getDisplayName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["converter", "displayLocale", "displayName", "displayNameCapacity", "err"]),
        #
        'ucnv_getName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["converter", "err"]),
        #
        'ucnv_getCCSID': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["converter", "err"]),
        #
        'ucnv_getPlatform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UConverterPlatform"), arg_names=["converter", "err"]),
        #
        'ucnv_getType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UConverterType"), arg_names=["converter"]),
        #
        'ucnv_getStarters': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter", "starters", "err"]),
        #
        'ucnv_getUnicodeSet': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UConverterUnicodeSet"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cnv", "setFillIn", "whichSet", "pErrorCode"]),
        #
        'ucnv_getToUCallBack': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterToUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "args", "codeUnits", "length", "reason", "pErrorCode"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter", "action", "context"]),
        #
        'ucnv_getFromUCallBack': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterFromUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "args", "codeUnits", "length", "codePoint", "reason", "pErrorCode"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter", "action", "context"]),
        #
        'ucnv_setToUCallBack': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterToUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "args", "codeUnits", "length", "reason", "pErrorCode"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterToUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "args", "codeUnits", "length", "reason", "pErrorCode"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter", "newAction", "newContext", "oldAction", "oldContext", "err"]),
        #
        'ucnv_setFromUCallBack': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterFromUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "args", "codeUnits", "length", "codePoint", "reason", "pErrorCode"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UConverterFromUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UConverterCallbackReason"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "args", "codeUnits", "length", "codePoint", "reason", "pErrorCode"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter", "newAction", "newContext", "oldAction", "oldContext", "err"]),
        #
        'ucnv_fromUnicode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter", "target", "targetLimit", "source", "sourceLimit", "offsets", "flush", "err"]),
        #
        'ucnv_toUnicode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["converter", "target", "targetLimit", "source", "sourceLimit", "offsets", "flush", "err"]),
        #
        'ucnv_fromUChars': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cnv", "dest", "destCapacity", "src", "srcLength", "pErrorCode"]),
        #
        'ucnv_toUChars': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cnv", "dest", "destCapacity", "src", "srcLength", "pErrorCode"]),
        #
        'ucnv_getNextUChar': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["converter", "source", "sourceLimit", "err"]),
        #
        'ucnv_convertEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeChar(label="SByte"), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["targetCnv", "sourceCnv", "target", "targetLimit", "source", "sourceLimit", "pivotStart", "pivotSource", "pivotTarget", "pivotLimit", "reset", "flush", "pErrorCode"]),
        #
        'ucnv_convert': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["toConverterName", "fromConverterName", "target", "targetCapacity", "source", "sourceLength", "pErrorCode"]),
        #
        'ucnv_toAlgorithmic': SimTypeFunction([SimTypeInt(signed=False, label="UConverterType"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["algorithmicType", "cnv", "target", "targetCapacity", "source", "sourceLength", "pErrorCode"]),
        #
        'ucnv_fromAlgorithmic': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UConverterType"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cnv", "algorithmicType", "target", "targetCapacity", "source", "sourceLength", "pErrorCode"]),
        #
        'ucnv_flushCache': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'ucnv_countAvailable': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'ucnv_getAvailableName': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["n"]),
        #
        'ucnv_openAllNames': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pErrorCode"]),
        #
        'ucnv_countAliases': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["alias", "pErrorCode"]),
        #
        'ucnv_getAlias': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["alias", "n", "pErrorCode"]),
        #
        'ucnv_getAliases': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["alias", "aliases", "pErrorCode"]),
        #
        'ucnv_openStandardNames': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["convName", "standard", "pErrorCode"]),
        #
        'ucnv_countStandards': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        #
        'ucnv_getStandard': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["n", "pErrorCode"]),
        #
        'ucnv_getStandardName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["name", "standard", "pErrorCode"]),
        #
        'ucnv_getCanonicalName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["alias", "standard", "pErrorCode"]),
        #
        'ucnv_getDefaultName': SimTypeFunction([], SimTypePointer(SimTypeChar(label="Byte"), offset=0)),
        #
        'ucnv_setDefaultName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["name"]),
        #
        'ucnv_fixFileSeparator': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["cnv", "source", "sourceLen"]),
        #
        'ucnv_isAmbiguous': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["cnv"]),
        #
        'ucnv_setFallback': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeChar(label="SByte")], SimTypeBottom(label="Void"), arg_names=["cnv", "usesFallback"]),
        #
        'ucnv_usesFallback': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["cnv"]),
        #
        'ucnv_detectUnicodeSignature': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["source", "sourceLength", "signatureLength", "pErrorCode"]),
        #
        'ucnv_fromUCountPending': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cnv", "status"]),
        #
        'ucnv_toUCountPending': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cnv", "status"]),
        #
        'ucnv_isFixedWidth': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["cnv", "status"]),
        #
        'ucnv_cbFromUWriteBytes': SimTypeFunction([SimTypePointer(SimTypeRef("UConverterFromUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["args", "source", "length", "offsetIndex", "err"]),
        #
        'ucnv_cbFromUWriteSub': SimTypeFunction([SimTypePointer(SimTypeRef("UConverterFromUnicodeArgs", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["args", "offsetIndex", "err"]),
        #
        'ucnv_cbFromUWriteUChars': SimTypeFunction([SimTypePointer(SimTypeRef("UConverterFromUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["args", "source", "sourceLimit", "offsetIndex", "err"]),
        #
        'ucnv_cbToUWriteUChars': SimTypeFunction([SimTypePointer(SimTypeRef("UConverterToUnicodeArgs", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["args", "source", "length", "offsetIndex", "err"]),
        #
        'ucnv_cbToUWriteSub': SimTypeFunction([SimTypePointer(SimTypeRef("UConverterToUnicodeArgs", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["args", "offsetIndex", "err"]),
        #
        'u_init': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["status"]),
        #
        'u_cleanup': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'u_setMemoryFunctions': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["context", "size"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["context", "mem", "size"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "mem"]), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "a", "r", "f", "status"]),
        #
        'u_catopen': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["name", "locale", "ec"]),
        #
        'u_catclose': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["catd"]),
        #
        'u_catgets': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["catd", "set_num", "msg_num", "s", "len", "ec"]),
        #
        'u_hasBinaryProperty': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UProperty")], SimTypeChar(label="SByte"), arg_names=["c", "which"]),
        #
        'u_getBinaryPropertySet': SimTypeFunction([SimTypeInt(signed=False, label="UProperty"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["property", "pErrorCode"]),
        #
        'u_isUAlphabetic': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isULowercase': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isUUppercase': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isUWhiteSpace': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_getIntPropertyValue': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UProperty")], SimTypeInt(signed=True, label="Int32"), arg_names=["c", "which"]),
        #
        'u_getIntPropertyMinValue': SimTypeFunction([SimTypeInt(signed=False, label="UProperty")], SimTypeInt(signed=True, label="Int32"), arg_names=["which"]),
        #
        'u_getIntPropertyMaxValue': SimTypeFunction([SimTypeInt(signed=False, label="UProperty")], SimTypeInt(signed=True, label="Int32"), arg_names=["which"]),
        #
        'u_getIntPropertyMap': SimTypeFunction([SimTypeInt(signed=False, label="UProperty"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["property", "pErrorCode"]),
        #
        'u_getNumericValue': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeFloat(size=64), arg_names=["c"]),
        #
        'u_islower': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isupper': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_istitle': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isdigit': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isalpha': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isalnum': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isxdigit': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_ispunct': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isgraph': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isblank': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isdefined': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isspace': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isJavaSpaceChar': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isWhitespace': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_iscntrl': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isISOControl': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isprint': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isbase': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_charDirection': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UCharDirection"), arg_names=["c"]),
        #
        'u_isMirrored': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_charMirror': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["c"]),
        #
        'u_getBidiPairedBracket': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["c"]),
        #
        'u_charType': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_enumCharTypes': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UCharCategory")], SimTypeChar(label="SByte"), arg_names=["context", "start", "limit", "type"]), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["enumRange", "context"]),
        #
        'u_getCombiningClass': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="Byte"), arg_names=["c"]),
        #
        'u_charDigitValue': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["c"]),
        #
        'ublock_getCode': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UBlockCode"), arg_names=["c"]),
        #
        'u_charName': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UCharNameChoice"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["code", "nameChoice", "buffer", "bufferLength", "pErrorCode"]),
        #
        'u_charFromName': SimTypeFunction([SimTypeInt(signed=False, label="UCharNameChoice"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nameChoice", "name", "pErrorCode"]),
        #
        'u_enumCharNames': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UCharNameChoice"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["context", "code", "nameChoice", "name", "length"]), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UCharNameChoice"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["start", "limit", "fn", "context", "nameChoice", "pErrorCode"]),
        #
        'u_getPropertyName': SimTypeFunction([SimTypeInt(signed=False, label="UProperty"), SimTypeInt(signed=False, label="UPropertyNameChoice")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["property", "nameChoice"]),
        #
        'u_getPropertyEnum': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UProperty"), arg_names=["alias"]),
        #
        'u_getPropertyValueName': SimTypeFunction([SimTypeInt(signed=False, label="UProperty"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UPropertyNameChoice")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["property", "value", "nameChoice"]),
        #
        'u_getPropertyValueEnum': SimTypeFunction([SimTypeInt(signed=False, label="UProperty"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["property", "alias"]),
        #
        'u_isIDStart': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isIDPart': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isIDIgnorable': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isJavaIDStart': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_isJavaIDPart': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["c"]),
        #
        'u_tolower': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["c"]),
        #
        'u_toupper': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["c"]),
        #
        'u_totitle': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["c"]),
        #
        'u_foldCase': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["c", "options"]),
        #
        'u_digit': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="SByte")], SimTypeInt(signed=True, label="Int32"), arg_names=["ch", "radix"]),
        #
        'u_forDigit': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="SByte")], SimTypeInt(signed=True, label="Int32"), arg_names=["digit", "radix"]),
        #
        'u_charAge': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["c", "versionArray"]),
        #
        'u_getUnicodeVersion': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["versionArray"]),
        #
        'u_getFC_NFKC_Closure': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["c", "dest", "destCapacity", "pErrorCode"]),
        #
        'ubidi_open': SimTypeFunction([], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)),
        #
        'ubidi_openSized': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["maxLength", "maxRunCount", "pErrorCode"]),
        #
        'ubidi_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["pBiDi"]),
        #
        'ubidi_setInverse': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeChar(label="SByte")], SimTypeBottom(label="Void"), arg_names=["pBiDi", "isInverse"]),
        #
        'ubidi_isInverse': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["pBiDi"]),
        #
        'ubidi_orderParagraphsLTR': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeChar(label="SByte")], SimTypeBottom(label="Void"), arg_names=["pBiDi", "orderParagraphsLTR"]),
        #
        'ubidi_isOrderParagraphsLTR': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["pBiDi"]),
        #
        'ubidi_setReorderingMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UBiDiReorderingMode")], SimTypeBottom(label="Void"), arg_names=["pBiDi", "reorderingMode"]),
        #
        'ubidi_getReorderingMode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UBiDiReorderingMode"), arg_names=["pBiDi"]),
        #
        'ubidi_setReorderingOptions': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pBiDi", "reorderingOptions"]),
        #
        'ubidi_getReorderingOptions': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pBiDi"]),
        #
        'ubidi_setContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pBiDi", "prologue", "proLength", "epilogue", "epiLength", "pErrorCode"]),
        #
        'ubidi_setPara': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pBiDi", "text", "length", "paraLevel", "embeddingLevels", "pErrorCode"]),
        #
        'ubidi_setLine': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pParaBiDi", "start", "limit", "pLineBiDi", "pErrorCode"]),
        #
        'ubidi_getDirection': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UBiDiDirection"), arg_names=["pBiDi"]),
        #
        'ubidi_getBaseDirection': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UBiDiDirection"), arg_names=["text", "length"]),
        #
        'ubidi_getText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["pBiDi"]),
        #
        'ubidi_getLength': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBiDi"]),
        #
        'ubidi_getParaLevel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["pBiDi"]),
        #
        'ubidi_countParagraphs': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBiDi"]),
        #
        'ubidi_getParagraph': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBiDi", "charIndex", "pParaStart", "pParaLimit", "pParaLevel", "pErrorCode"]),
        #
        'ubidi_getParagraphByIndex': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pBiDi", "paraIndex", "pParaStart", "pParaLimit", "pParaLevel", "pErrorCode"]),
        #
        'ubidi_getLevelAt': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="Byte"), arg_names=["pBiDi", "charIndex"]),
        #
        'ubidi_getLevels': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pBiDi", "pErrorCode"]),
        #
        'ubidi_getLogicalRun': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pBiDi", "logicalPosition", "pLogicalLimit", "pLevel"]),
        #
        'ubidi_countRuns': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBiDi", "pErrorCode"]),
        #
        'ubidi_getVisualRun': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UBiDiDirection"), arg_names=["pBiDi", "runIndex", "pLogicalStart", "pLength"]),
        #
        'ubidi_getVisualIndex': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBiDi", "logicalIndex", "pErrorCode"]),
        #
        'ubidi_getLogicalIndex': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBiDi", "visualIndex", "pErrorCode"]),
        #
        'ubidi_getLogicalMap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pBiDi", "indexMap", "pErrorCode"]),
        #
        'ubidi_getVisualMap': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pBiDi", "indexMap", "pErrorCode"]),
        #
        'ubidi_reorderLogical': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["levels", "length", "indexMap"]),
        #
        'ubidi_reorderVisual': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["levels", "length", "indexMap"]),
        #
        'ubidi_invertMap': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["srcMap", "destMap", "length"]),
        #
        'ubidi_getProcessedLength': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBiDi"]),
        #
        'ubidi_getResultLength': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBiDi"]),
        #
        'ubidi_getCustomizedClass': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UCharDirection"), arg_names=["pBiDi", "c"]),
        #
        'ubidi_setClassCallback': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UCharDirection"), arg_names=["context", "c"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UCharDirection"), arg_names=["context", "c"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pBiDi", "newFn", "newContext", "oldFn", "oldContext", "pErrorCode"]),
        #
        'ubidi_getClassCallback': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UCharDirection"), arg_names=["context", "c"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["pBiDi", "fn", "context"]),
        #
        'ubidi_writeReordered': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBiDi", "dest", "destSize", "options", "pErrorCode"]),
        #
        'ubidi_writeReverse': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["src", "srcLength", "dest", "destSize", "options", "pErrorCode"]),
        #
        'ubiditransform_transform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UBiDiOrder"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UBiDiOrder"), SimTypeInt(signed=False, label="UBiDiMirroring"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pBiDiTransform", "src", "srcLength", "dest", "destSize", "inParaLevel", "inOrder", "outParaLevel", "outOrder", "doMirroring", "shapingOptions", "pErrorCode"]),
        #
        'ubiditransform_open': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pErrorCode"]),
        #
        'ubiditransform_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["pBidiTransform"]),
        #
        'utext_close': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0)], SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), arg_names=["ut"]),
        #
        'utext_openUTF8': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), arg_names=["ut", "s", "length", "status"]),
        #
        'utext_openUChars': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), arg_names=["ut", "s", "length", "status"]),
        #
        'utext_clone': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypeChar(label="SByte"), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), arg_names=["dest", "src", "deep", "readOnly", "status"]),
        #
        'utext_equals': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0)], SimTypeChar(label="SByte"), arg_names=["a", "b"]),
        #
        'utext_nativeLength': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["ut"]),
        #
        'utext_isLengthExpensive': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0)], SimTypeChar(label="SByte"), arg_names=["ut"]),
        #
        'utext_char32At': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeInt(signed=True, label="Int32"), arg_names=["ut", "nativeIndex"]),
        #
        'utext_current32': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ut"]),
        #
        'utext_next32': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ut"]),
        #
        'utext_previous32': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ut"]),
        #
        'utext_next32From': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeInt(signed=True, label="Int32"), arg_names=["ut", "nativeIndex"]),
        #
        'utext_previous32From': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeInt(signed=True, label="Int32"), arg_names=["ut", "nativeIndex"]),
        #
        'utext_getNativeIndex': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["ut"]),
        #
        'utext_setNativeIndex': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeBottom(label="Void"), arg_names=["ut", "nativeIndex"]),
        #
        'utext_moveIndex32': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["ut", "delta"]),
        #
        'utext_getPreviousNativeIndex': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["ut"]),
        #
        'utext_extract': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ut", "nativeStart", "nativeLimit", "dest", "destCapacity", "status"]),
        #
        'utext_isWritable': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0)], SimTypeChar(label="SByte"), arg_names=["ut"]),
        #
        'utext_hasMetaData': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0)], SimTypeChar(label="SByte"), arg_names=["ut"]),
        #
        'utext_replace': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ut", "nativeStart", "nativeLimit", "replacementText", "replacementLength", "status"]),
        #
        'utext_copy': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ut", "nativeStart", "nativeLimit", "destIndex", "move", "status"]),
        #
        'utext_freeze': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ut"]),
        #
        'utext_setup': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), arg_names=["ut", "extraSpace", "status"]),
        #
        'uset_openEmpty': SimTypeFunction([], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)),
        #
        'uset_open': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["start", "end"]),
        #
        'uset_openPattern': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pattern", "patternLength", "ec"]),
        #
        'uset_openPatternOptions': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pattern", "patternLength", "options", "ec"]),
        #
        'uset_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["set"]),
        #
        'uset_clone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["set"]),
        #
        'uset_isFrozen': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["set"]),
        #
        'uset_freeze': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["set"]),
        #
        'uset_cloneAsThawed': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["set"]),
        #
        'uset_set': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["set", "start", "end"]),
        #
        'uset_applyPattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["set", "pattern", "patternLength", "options", "status"]),
        #
        'uset_applyIntPropertyValue': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UProperty"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["set", "prop", "value", "ec"]),
        #
        'uset_applyPropertyAlias': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["set", "prop", "propLength", "value", "valueLength", "ec"]),
        #
        'uset_resemblesPattern': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["pattern", "patternLength", "pos"]),
        #
        'uset_toPattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["set", "result", "resultCapacity", "escapeUnprintable", "ec"]),
        #
        'uset_add': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["set", "c"]),
        #
        'uset_addAll': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["set", "additionalSet"]),
        #
        'uset_addRange': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["set", "start", "end"]),
        #
        'uset_addString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["set", "str", "strLen"]),
        #
        'uset_addAllCodePoints': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["set", "str", "strLen"]),
        #
        'uset_remove': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["set", "c"]),
        #
        'uset_removeRange': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["set", "start", "end"]),
        #
        'uset_removeString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["set", "str", "strLen"]),
        #
        'uset_removeAll': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["set", "removeSet"]),
        #
        'uset_retain': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["set", "start", "end"]),
        #
        'uset_retainAll': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["set", "retain"]),
        #
        'uset_compact': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["set"]),
        #
        'uset_complement': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["set"]),
        #
        'uset_complementAll': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["set", "complement"]),
        #
        'uset_clear': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["set"]),
        #
        'uset_closeOver': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["set", "attributes"]),
        #
        'uset_removeAllStrings': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["set"]),
        #
        'uset_isEmpty': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["set"]),
        #
        'uset_contains': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["set", "c"]),
        #
        'uset_containsRange': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["set", "start", "end"]),
        #
        'uset_containsString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["set", "str", "strLen"]),
        #
        'uset_indexOf': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["set", "c"]),
        #
        'uset_charAt': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["set", "charIndex"]),
        #
        'uset_size': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["set"]),
        #
        'uset_getItemCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["set"]),
        #
        'uset_getItem': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["set", "itemIndex", "start", "end", "str", "strCapacity", "ec"]),
        #
        'uset_containsAll': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["set1", "set2"]),
        #
        'uset_containsAllCodePoints': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["set", "str", "strLen"]),
        #
        'uset_containsNone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["set1", "set2"]),
        #
        'uset_containsSome': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["set1", "set2"]),
        #
        'uset_span': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="USetSpanCondition")], SimTypeInt(signed=True, label="Int32"), arg_names=["set", "s", "length", "spanCondition"]),
        #
        'uset_spanBack': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="USetSpanCondition")], SimTypeInt(signed=True, label="Int32"), arg_names=["set", "s", "length", "spanCondition"]),
        #
        'uset_spanUTF8': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="USetSpanCondition")], SimTypeInt(signed=True, label="Int32"), arg_names=["set", "s", "length", "spanCondition"]),
        #
        'uset_spanBackUTF8': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="USetSpanCondition")], SimTypeInt(signed=True, label="Int32"), arg_names=["set", "s", "length", "spanCondition"]),
        #
        'uset_equals': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["set1", "set2"]),
        #
        'uset_serialize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["set", "dest", "destCapacity", "pErrorCode"]),
        #
        'uset_getSerializedSet': SimTypeFunction([SimTypePointer(SimTypeRef("USerializedSet", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["fillSet", "src", "srcLength"]),
        #
        'uset_setSerializedToOne': SimTypeFunction([SimTypePointer(SimTypeRef("USerializedSet", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["fillSet", "c"]),
        #
        'uset_serializedContains': SimTypeFunction([SimTypePointer(SimTypeRef("USerializedSet", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["set", "c"]),
        #
        'uset_getSerializedRangeCount': SimTypeFunction([SimTypePointer(SimTypeRef("USerializedSet", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["set"]),
        #
        'uset_getSerializedRange': SimTypeFunction([SimTypePointer(SimTypeRef("USerializedSet", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeChar(label="SByte"), arg_names=["set", "rangeIndex", "pStart", "pEnd"]),
        #
        'unorm2_getNFCInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pErrorCode"]),
        #
        'unorm2_getNFDInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pErrorCode"]),
        #
        'unorm2_getNFKCInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pErrorCode"]),
        #
        'unorm2_getNFKDInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pErrorCode"]),
        #
        'unorm2_getNFKCCasefoldInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pErrorCode"]),
        #
        'unorm2_getInstance': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UNormalization2Mode"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["packageName", "name", "mode", "pErrorCode"]),
        #
        'unorm2_openFiltered': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["norm2", "filterSet", "pErrorCode"]),
        #
        'unorm2_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["norm2"]),
        #
        'unorm2_normalize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["norm2", "src", "length", "dest", "capacity", "pErrorCode"]),
        #
        'unorm2_normalizeSecondAndAppend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["norm2", "first", "firstLength", "firstCapacity", "second", "secondLength", "pErrorCode"]),
        #
        'unorm2_append': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["norm2", "first", "firstLength", "firstCapacity", "second", "secondLength", "pErrorCode"]),
        #
        'unorm2_getDecomposition': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["norm2", "c", "decomposition", "capacity", "pErrorCode"]),
        #
        'unorm2_getRawDecomposition': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["norm2", "c", "decomposition", "capacity", "pErrorCode"]),
        #
        'unorm2_composePair': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["norm2", "a", "b"]),
        #
        'unorm2_getCombiningClass': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="Byte"), arg_names=["norm2", "c"]),
        #
        'unorm2_isNormalized': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["norm2", "s", "length", "pErrorCode"]),
        #
        'unorm2_quickCheck': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UNormalizationCheckResult"), arg_names=["norm2", "s", "length", "pErrorCode"]),
        #
        'unorm2_spanQuickCheckYes': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["norm2", "s", "length", "pErrorCode"]),
        #
        'unorm2_hasBoundaryBefore': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["norm2", "c"]),
        #
        'unorm2_hasBoundaryAfter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["norm2", "c"]),
        #
        'unorm2_isInert': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["norm2", "c"]),
        #
        'unorm_compare': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s1", "length1", "s2", "length2", "options", "pErrorCode"]),
        #
        'ucnvsel_open': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UConverterUnicodeSet"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["converterList", "converterListSize", "excludedCodePoints", "whichSet", "status"]),
        #
        'ucnvsel_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["sel"]),
        #
        'ucnvsel_openFromSerialized': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["buffer", "length", "status"]),
        #
        'ucnvsel_serialize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sel", "buffer", "bufferCapacity", "status"]),
        #
        'ucnvsel_selectForString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["sel", "s", "length", "status"]),
        #
        'ucnvsel_selectForUTF8': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["sel", "s", "length", "status"]),
        #
        'u_charsToUChars': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["cs", "us", "length"]),
        #
        'u_UCharsToChars': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["us", "cs", "length"]),
        #
        'u_strlen': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s"]),
        #
        'u_countChar32': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "length"]),
        #
        'u_strHasMoreChar32Than': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["s", "length", "number"]),
        #
        'u_strcat': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dst", "src"]),
        #
        'u_strncat': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dst", "src", "n"]),
        #
        'u_strstr': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["s", "substring"]),
        #
        'u_strFindFirst': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["s", "length", "substring", "subLength"]),
        #
        'u_strchr': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["s", "c"]),
        #
        'u_strchr32': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["s", "c"]),
        #
        'u_strrstr': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["s", "substring"]),
        #
        'u_strFindLast': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["s", "length", "substring", "subLength"]),
        #
        'u_strrchr': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["s", "c"]),
        #
        'u_strrchr32': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["s", "c"]),
        #
        'u_strpbrk': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["string", "matchSet"]),
        #
        'u_strcspn': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["string", "matchSet"]),
        #
        'u_strspn': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["string", "matchSet"]),
        #
        'u_strtok_r': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["src", "delim", "saveState"]),
        #
        'u_strcmp': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s1", "s2"]),
        #
        'u_strcmpCodePointOrder': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s1", "s2"]),
        #
        'u_strCompare': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="SByte")], SimTypeInt(signed=True, label="Int32"), arg_names=["s1", "length1", "s2", "length2", "codePointOrder"]),
        #
        'u_strCompareIter': SimTypeFunction([SimTypePointer(SimTypeRef("UCharIterator", SimStruct), offset=0), SimTypePointer(SimTypeRef("UCharIterator", SimStruct), offset=0), SimTypeChar(label="SByte")], SimTypeInt(signed=True, label="Int32"), arg_names=["iter1", "iter2", "codePointOrder"]),
        #
        'u_strCaseCompare': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s1", "length1", "s2", "length2", "options", "pErrorCode"]),
        #
        'u_strncmp': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ucs1", "ucs2", "n"]),
        #
        'u_strncmpCodePointOrder': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s1", "s2", "n"]),
        #
        'u_strcasecmp': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s1", "s2", "options"]),
        #
        'u_strncasecmp': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s1", "s2", "n", "options"]),
        #
        'u_memcasecmp': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s1", "s2", "length", "options"]),
        #
        'u_strcpy': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dst", "src"]),
        #
        'u_strncpy': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dst", "src", "n"]),
        #
        'u_uastrcpy': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dst", "src"]),
        #
        'u_uastrncpy': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dst", "src", "n"]),
        #
        'u_austrcpy': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["dst", "src"]),
        #
        'u_austrncpy': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["dst", "src", "n"]),
        #
        'u_memcpy': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dest", "src", "count"]),
        #
        'u_memmove': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dest", "src", "count"]),
        #
        'u_memset': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dest", "c", "count"]),
        #
        'u_memcmp': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["buf1", "buf2", "count"]),
        #
        'u_memcmpCodePointOrder': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s1", "s2", "count"]),
        #
        'u_memchr': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["s", "c", "count"]),
        #
        'u_memchr32': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["s", "c", "count"]),
        #
        'u_memrchr': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["s", "c", "count"]),
        #
        'u_memrchr32': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["s", "c", "count"]),
        #
        'u_unescape': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["src", "dest", "destCapacity"]),
        #
        'u_unescapeAt': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["offset", "context"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["charAt", "offset", "length", "context"]),
        #
        'u_strToUpper': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dest", "destCapacity", "src", "srcLength", "locale", "pErrorCode"]),
        #
        'u_strToLower': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dest", "destCapacity", "src", "srcLength", "locale", "pErrorCode"]),
        #
        'u_strToTitle': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dest", "destCapacity", "src", "srcLength", "titleIter", "locale", "pErrorCode"]),
        #
        'u_strFoldCase': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dest", "destCapacity", "src", "srcLength", "options", "pErrorCode"]),
        #
        'u_strToWCS': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["dest", "destCapacity", "pDestLength", "src", "srcLength", "pErrorCode"]),
        #
        'u_strFromWCS': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dest", "destCapacity", "pDestLength", "src", "srcLength", "pErrorCode"]),
        #
        'u_strToUTF8': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["dest", "destCapacity", "pDestLength", "src", "srcLength", "pErrorCode"]),
        #
        'u_strFromUTF8': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dest", "destCapacity", "pDestLength", "src", "srcLength", "pErrorCode"]),
        #
        'u_strToUTF8WithSub': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["dest", "destCapacity", "pDestLength", "src", "srcLength", "subchar", "pNumSubstitutions", "pErrorCode"]),
        #
        'u_strFromUTF8WithSub': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dest", "destCapacity", "pDestLength", "src", "srcLength", "subchar", "pNumSubstitutions", "pErrorCode"]),
        #
        'u_strFromUTF8Lenient': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dest", "destCapacity", "pDestLength", "src", "srcLength", "pErrorCode"]),
        #
        'u_strToUTF32': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), arg_names=["dest", "destCapacity", "pDestLength", "src", "srcLength", "pErrorCode"]),
        #
        'u_strFromUTF32': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dest", "destCapacity", "pDestLength", "src", "srcLength", "pErrorCode"]),
        #
        'u_strToUTF32WithSub': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), arg_names=["dest", "destCapacity", "pDestLength", "src", "srcLength", "subchar", "pNumSubstitutions", "pErrorCode"]),
        #
        'u_strFromUTF32WithSub': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dest", "destCapacity", "pDestLength", "src", "srcLength", "subchar", "pNumSubstitutions", "pErrorCode"]),
        #
        'u_strToJavaModifiedUTF8': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["dest", "destCapacity", "pDestLength", "src", "srcLength", "pErrorCode"]),
        #
        'u_strFromJavaModifiedUTF8WithSub': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dest", "destCapacity", "pDestLength", "src", "srcLength", "subchar", "pNumSubstitutions", "pErrorCode"]),
        #
        'ucasemap_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["locale", "options", "pErrorCode"]),
        #
        'ucasemap_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["csm"]),
        #
        'ucasemap_getLocale': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["csm"]),
        #
        'ucasemap_getOptions': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["csm"]),
        #
        'ucasemap_setLocale': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["csm", "locale", "pErrorCode"]),
        #
        'ucasemap_setOptions': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["csm", "options", "pErrorCode"]),
        #
        'ucasemap_getBreakIterator': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["csm"]),
        #
        'ucasemap_setBreakIterator': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["csm", "iterToAdopt", "pErrorCode"]),
        #
        'ucasemap_toTitle': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["csm", "dest", "destCapacity", "src", "srcLength", "pErrorCode"]),
        #
        'ucasemap_utf8ToLower': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["csm", "dest", "destCapacity", "src", "srcLength", "pErrorCode"]),
        #
        'ucasemap_utf8ToUpper': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["csm", "dest", "destCapacity", "src", "srcLength", "pErrorCode"]),
        #
        'ucasemap_utf8ToTitle': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["csm", "dest", "destCapacity", "src", "srcLength", "pErrorCode"]),
        #
        'ucasemap_utf8FoldCase': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["csm", "dest", "destCapacity", "src", "srcLength", "pErrorCode"]),
        #
        'usprep_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["path", "fileName", "status"]),
        #
        'usprep_openByType': SimTypeFunction([SimTypeInt(signed=False, label="UStringPrepProfileType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["type", "status"]),
        #
        'usprep_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["profile"]),
        #
        'usprep_prepare': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prep", "src", "srcLength", "dest", "destCapacity", "options", "parseError", "status"]),
        #
        'uidna_openUTS46': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["options", "pErrorCode"]),
        #
        'uidna_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["idna"]),
        #
        'uidna_labelToASCII': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UIDNAInfo", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idna", "label", "length", "dest", "capacity", "pInfo", "pErrorCode"]),
        #
        'uidna_labelToUnicode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UIDNAInfo", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idna", "label", "length", "dest", "capacity", "pInfo", "pErrorCode"]),
        #
        'uidna_nameToASCII': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UIDNAInfo", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idna", "name", "length", "dest", "capacity", "pInfo", "pErrorCode"]),
        #
        'uidna_nameToUnicode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UIDNAInfo", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idna", "name", "length", "dest", "capacity", "pInfo", "pErrorCode"]),
        #
        'uidna_labelToASCII_UTF8': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UIDNAInfo", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idna", "label", "length", "dest", "capacity", "pInfo", "pErrorCode"]),
        #
        'uidna_labelToUnicodeUTF8': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UIDNAInfo", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idna", "label", "length", "dest", "capacity", "pInfo", "pErrorCode"]),
        #
        'uidna_nameToASCII_UTF8': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UIDNAInfo", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idna", "name", "length", "dest", "capacity", "pInfo", "pErrorCode"]),
        #
        'uidna_nameToUnicodeUTF8': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UIDNAInfo", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["idna", "name", "length", "dest", "capacity", "pInfo", "pErrorCode"]),
        #
        'ubrk_open': SimTypeFunction([SimTypeInt(signed=False, label="UBreakIteratorType"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["type", "locale", "text", "textLength", "status"]),
        #
        'ubrk_openRules': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["rules", "rulesLength", "text", "textLength", "parseErr", "status"]),
        #
        'ubrk_openBinaryRules': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["binaryRules", "rulesLength", "text", "textLength", "status"]),
        #
        'ubrk_safeClone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["bi", "stackBuffer", "pBufferSize", "status"]),
        #
        'ubrk_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["bi"]),
        #
        'ubrk_setText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["bi", "text", "textLength", "status"]),
        #
        'ubrk_setUText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["bi", "text", "status"]),
        #
        'ubrk_current': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bi"]),
        #
        'ubrk_next': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bi"]),
        #
        'ubrk_previous': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bi"]),
        #
        'ubrk_first': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bi"]),
        #
        'ubrk_last': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bi"]),
        #
        'ubrk_preceding': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["bi", "offset"]),
        #
        'ubrk_following': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["bi", "offset"]),
        #
        'ubrk_getAvailable': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["index"]),
        #
        'ubrk_countAvailable': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'ubrk_isBoundary': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["bi", "offset"]),
        #
        'ubrk_getRuleStatus': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bi"]),
        #
        'ubrk_getRuleStatusVec': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bi", "fillInVec", "capacity", "status"]),
        #
        'ubrk_getLocaleByType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ULocDataLocaleType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["bi", "type", "status"]),
        #
        'ubrk_refreshUText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["bi", "text", "status"]),
        #
        'ubrk_getBinaryRules': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bi", "binaryRules", "rulesCapacity", "status"]),
        #
        'u_getDataVersion': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["dataVersionFillin", "status"]),
        #
        'ucal_openTimeZoneIDEnumeration': SimTypeFunction([SimTypeInt(signed=False, label="USystemTimeZoneType"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["zoneType", "region", "rawOffset", "ec"]),
        #
        'ucal_openTimeZones': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["ec"]),
        #
        'ucal_openCountryTimeZones': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["country", "ec"]),
        #
        'ucal_getDefaultTimeZone': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["result", "resultCapacity", "ec"]),
        #
        'ucal_setDefaultTimeZone': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["zoneID", "ec"]),
        #
        'ucal_getHostTimeZone': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["result", "resultCapacity", "ec"]),
        #
        'ucal_getDSTSavings': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["zoneID", "ec"]),
        #
        'ucal_getNow': SimTypeFunction([], SimTypeFloat(size=64)),
        #
        'ucal_open': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UCalendarType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["zoneID", "len", "locale", "type", "status"]),
        #
        'ucal_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["cal"]),
        #
        'ucal_clone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["cal", "status"]),
        #
        'ucal_setTimeZone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cal", "zoneID", "len", "status"]),
        #
        'ucal_getTimeZoneID': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cal", "result", "resultLength", "status"]),
        #
        'ucal_getTimeZoneDisplayName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UCalendarDisplayNameType"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cal", "type", "locale", "result", "resultLength", "status"]),
        #
        'ucal_inDaylightTime': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["cal", "status"]),
        #
        'ucal_setGregorianChange': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeFloat(size=64), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cal", "date", "pErrorCode"]),
        #
        'ucal_getGregorianChange': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeFloat(size=64), arg_names=["cal", "pErrorCode"]),
        #
        'ucal_getAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UCalendarAttribute")], SimTypeInt(signed=True, label="Int32"), arg_names=["cal", "attr"]),
        #
        'ucal_setAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UCalendarAttribute"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["cal", "attr", "newValue"]),
        #
        'ucal_getAvailable': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["localeIndex"]),
        #
        'ucal_countAvailable': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'ucal_getMillis': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeFloat(size=64), arg_names=["cal", "status"]),
        #
        'ucal_setMillis': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeFloat(size=64), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cal", "dateTime", "status"]),
        #
        'ucal_setDate': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cal", "year", "month", "date", "status"]),
        #
        'ucal_setDateTime': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cal", "year", "month", "date", "hour", "minute", "second", "status"]),
        #
        'ucal_equivalentTo': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["cal1", "cal2"]),
        #
        'ucal_add': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UCalendarDateFields"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cal", "field", "amount", "status"]),
        #
        'ucal_roll': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UCalendarDateFields"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cal", "field", "amount", "status"]),
        #
        'ucal_get': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UCalendarDateFields"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cal", "field", "status"]),
        #
        'ucal_set': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UCalendarDateFields"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["cal", "field", "value"]),
        #
        'ucal_isSet': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UCalendarDateFields")], SimTypeChar(label="SByte"), arg_names=["cal", "field"]),
        #
        'ucal_clearField': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UCalendarDateFields")], SimTypeBottom(label="Void"), arg_names=["cal", "field"]),
        #
        'ucal_clear': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["calendar"]),
        #
        'ucal_getLimit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UCalendarDateFields"), SimTypeInt(signed=False, label="UCalendarLimitType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cal", "field", "type", "status"]),
        #
        'ucal_getLocaleByType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="ULocDataLocaleType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["cal", "type", "status"]),
        #
        'ucal_getTZDataVersion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["status"]),
        #
        'ucal_getCanonicalTimeZoneID': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["id", "len", "result", "resultCapacity", "isSystemID", "status"]),
        #
        'ucal_getType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["cal", "status"]),
        #
        'ucal_getKeywordValuesForLocale': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["key", "locale", "commonlyUsed", "status"]),
        #
        'ucal_getDayOfWeekType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UCalendarDaysOfWeek"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UCalendarWeekdayType"), arg_names=["cal", "dayOfWeek", "status"]),
        #
        'ucal_getWeekendTransition': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UCalendarDaysOfWeek"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cal", "dayOfWeek", "status"]),
        #
        'ucal_isWeekend': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeFloat(size=64), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["cal", "date", "status"]),
        #
        'ucal_getFieldDifference': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeFloat(size=64), SimTypeInt(signed=False, label="UCalendarDateFields"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cal", "target", "field", "status"]),
        #
        'ucal_getTimeZoneTransitionDate': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UTimeZoneTransitionType"), SimTypePointer(SimTypeFloat(size=64), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["cal", "type", "transition", "status"]),
        #
        'ucal_getWindowsTimeZoneID': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["id", "len", "winid", "winidCapacity", "status"]),
        #
        'ucal_getTimeZoneIDForWindowsID': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["winid", "len", "region", "id", "idCapacity", "status"]),
        #
        'ucol_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["loc", "status"]),
        #
        'ucol_openRules': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UColAttributeValue"), SimTypeInt(signed=False, label="UColAttributeValue"), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["rules", "rulesLength", "normalizationMode", "strength", "parseError", "status"]),
        #
        'ucol_getContractionsAndExpansions': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["coll", "contractions", "expansions", "addPrefixes", "status"]),
        #
        'ucol_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["coll"]),
        #
        'ucol_strcoll': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UCollationResult"), arg_names=["coll", "source", "sourceLength", "target", "targetLength"]),
        #
        'ucol_strcollUTF8': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UCollationResult"), arg_names=["coll", "source", "sourceLength", "target", "targetLength", "status"]),
        #
        'ucol_greater': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["coll", "source", "sourceLength", "target", "targetLength"]),
        #
        'ucol_greaterOrEqual': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["coll", "source", "sourceLength", "target", "targetLength"]),
        #
        'ucol_equal': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["coll", "source", "sourceLength", "target", "targetLength"]),
        #
        'ucol_strcollIter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UCharIterator", SimStruct), offset=0), SimTypePointer(SimTypeRef("UCharIterator", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UCollationResult"), arg_names=["coll", "sIter", "tIter", "status"]),
        #
        'ucol_getStrength': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UColAttributeValue"), arg_names=["coll"]),
        #
        'ucol_setStrength': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UColAttributeValue")], SimTypeBottom(label="Void"), arg_names=["coll", "strength"]),
        #
        'ucol_getReorderCodes': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["coll", "dest", "destCapacity", "pErrorCode"]),
        #
        'ucol_setReorderCodes': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["coll", "reorderCodes", "reorderCodesLength", "pErrorCode"]),
        #
        'ucol_getEquivalentReorderCodes': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["reorderCode", "dest", "destCapacity", "pErrorCode"]),
        #
        'ucol_getDisplayName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["objLoc", "dispLoc", "result", "resultLength", "status"]),
        #
        'ucol_getAvailable': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["localeIndex"]),
        #
        'ucol_countAvailable': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'ucol_openAvailableLocales': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["status"]),
        #
        'ucol_getKeywords': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["status"]),
        #
        'ucol_getKeywordValues': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["keyword", "status"]),
        #
        'ucol_getKeywordValuesForLocale': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["key", "locale", "commonlyUsed", "status"]),
        #
        'ucol_getFunctionalEquivalent': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["result", "resultCapacity", "keyword", "locale", "isAvailable", "status"]),
        #
        'ucol_getRules': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["coll", "length"]),
        #
        'ucol_getSortKey': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["coll", "source", "sourceLength", "result", "resultLength"]),
        #
        'ucol_nextSortKeyPart': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UCharIterator", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["coll", "iter", "state", "dest", "count", "status"]),
        #
        'ucol_getBound': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UColBoundMode"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["source", "sourceLength", "boundType", "noOfLevels", "result", "resultLength", "status"]),
        #
        'ucol_getVersion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["coll", "info"]),
        #
        'ucol_getUCAVersion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["coll", "info"]),
        #
        'ucol_mergeSortkeys': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["src1", "src1Length", "src2", "src2Length", "dest", "destCapacity"]),
        #
        'ucol_setAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UColAttribute"), SimTypeInt(signed=False, label="UColAttributeValue"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["coll", "attr", "value", "status"]),
        #
        'ucol_getAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UColAttribute"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UColAttributeValue"), arg_names=["coll", "attr", "status"]),
        #
        'ucol_setMaxVariable': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UColReorderCode"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["coll", "group", "pErrorCode"]),
        #
        'ucol_getMaxVariable': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UColReorderCode"), arg_names=["coll"]),
        #
        'ucol_getVariableTop': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["coll", "status"]),
        #
        'ucol_safeClone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["coll", "stackBuffer", "pBufferSize", "status"]),
        #
        'ucol_getRulesEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UColRuleOption"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["coll", "delta", "buffer", "bufferLen"]),
        #
        'ucol_getLocaleByType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ULocDataLocaleType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["coll", "type", "status"]),
        #
        'ucol_getTailoredSet': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["coll", "status"]),
        #
        'ucol_cloneBinary': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["coll", "buffer", "capacity", "status"]),
        #
        'ucol_openBinary': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["bin", "length", "base", "status"]),
        #
        'ucol_openElements': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["coll", "text", "textLength", "status"]),
        #
        'ucol_keyHashCode': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["key", "length"]),
        #
        'ucol_closeElements': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["elems"]),
        #
        'ucol_reset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["elems"]),
        #
        'ucol_next': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["elems", "status"]),
        #
        'ucol_previous': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["elems", "status"]),
        #
        'ucol_getMaxExpansion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["elems", "order"]),
        #
        'ucol_setText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["elems", "text", "textLength", "status"]),
        #
        'ucol_getOffset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["elems"]),
        #
        'ucol_setOffset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["elems", "offset", "status"]),
        #
        'ucol_primaryOrder': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["order"]),
        #
        'ucol_secondaryOrder': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["order"]),
        #
        'ucol_tertiaryOrder': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["order"]),
        #
        'ucsdet_open': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["status"]),
        #
        'ucsdet_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["ucsd"]),
        #
        'ucsdet_setText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ucsd", "textIn", "len", "status"]),
        #
        'ucsdet_setDeclaredEncoding': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ucsd", "encoding", "length", "status"]),
        #
        'ucsdet_detect': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["ucsd", "status"]),
        #
        'ucsdet_detectAll': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0), arg_names=["ucsd", "matchesFound", "status"]),
        #
        'ucsdet_getName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["ucsm", "status"]),
        #
        'ucsdet_getConfidence': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ucsm", "status"]),
        #
        'ucsdet_getLanguage': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["ucsm", "status"]),
        #
        'ucsdet_getUChars': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ucsm", "buf", "cap", "status"]),
        #
        'ucsdet_getAllDetectableCharsets': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["ucsd", "status"]),
        #
        'ucsdet_isInputFilterEnabled': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["ucsd"]),
        #
        'ucsdet_enableInputFilter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeChar(label="SByte")], SimTypeChar(label="SByte"), arg_names=["ucsd", "filter"]),
        #
        'ufieldpositer_open': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["status"]),
        #
        'ufieldpositer_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["fpositer"]),
        #
        'ufieldpositer_next': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fpositer", "beginIndex", "endIndex"]),
        #
        'ufmt_open': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["status"]),
        #
        'ufmt_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt"]),
        #
        'ufmt_getType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UFormattableType"), arg_names=["fmt", "status"]),
        #
        'ufmt_isNumeric': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["fmt"]),
        #
        'ufmt_getDate': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeFloat(size=64), arg_names=["fmt", "status"]),
        #
        'ufmt_getDouble': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeFloat(size=64), arg_names=["fmt", "status"]),
        #
        'ufmt_getLong': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "status"]),
        #
        'ufmt_getInt64': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["fmt", "status"]),
        #
        'ufmt_getObject': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["fmt", "status"]),
        #
        'ufmt_getUChars': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["fmt", "len", "status"]),
        #
        'ufmt_getArrayLength': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "status"]),
        #
        'ufmt_getArrayItemByIndex': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["fmt", "n", "status"]),
        #
        'ufmt_getDecNumChars': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["fmt", "len", "status"]),
        #
        'ucfpos_open': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["ec"]),
        #
        'ucfpos_reset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ucfpos", "ec"]),
        #
        'ucfpos_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["ucfpos"]),
        #
        'ucfpos_constrainCategory': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ucfpos", "category", "ec"]),
        #
        'ucfpos_constrainField': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ucfpos", "category", "field", "ec"]),
        #
        'ucfpos_getCategory': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ucfpos", "ec"]),
        #
        'ucfpos_getField': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ucfpos", "ec"]),
        #
        'ucfpos_getIndexes': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ucfpos", "pStart", "pLimit", "ec"]),
        #
        'ucfpos_getInt64IterationContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["ucfpos", "ec"]),
        #
        'ucfpos_setInt64IterationContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ucfpos", "context", "ec"]),
        #
        'ucfpos_matchesField': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["ucfpos", "category", "field", "ec"]),
        #
        'ucfpos_setState': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ucfpos", "category", "field", "start", "limit", "ec"]),
        #
        'ufmtval_getString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["ufmtval", "pLength", "ec"]),
        #
        'ufmtval_nextPosition': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["ufmtval", "ucfpos", "ec"]),
        #
        'udtitvfmt_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["locale", "skeleton", "skeletonLength", "tzID", "tzIDLength", "status"]),
        #
        'udtitvfmt_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["formatter"]),
        #
        'udtitvfmt_openResult': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["ec"]),
        #
        'udtitvfmt_resultAsValue': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["uresult", "ec"]),
        #
        'udtitvfmt_closeResult': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["uresult"]),
        #
        'udtitvfmt_format': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UFieldPosition", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["formatter", "fromDate", "toDate", "result", "resultCapacity", "position", "status"]),
        #
        'ugender_getInstance': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["locale", "status"]),
        #
        'ugender_getListGender': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UGender"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UGender"), arg_names=["genderInfo", "genders", "size", "status"]),
        #
        'ulistfmt_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["locale", "status"]),
        #
        'ulistfmt_openForType': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UListFormatterType"), SimTypeInt(signed=False, label="UListFormatterWidth"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["locale", "type", "width", "status"]),
        #
        'ulistfmt_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["listfmt"]),
        #
        'ulistfmt_openResult': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["ec"]),
        #
        'ulistfmt_resultAsValue': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["uresult", "ec"]),
        #
        'ulistfmt_closeResult': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["uresult"]),
        #
        'ulistfmt_format': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["listfmt", "strings", "stringLengths", "stringCount", "result", "resultCapacity", "status"]),
        #
        'ulistfmt_formatStringsToResult': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["listfmt", "strings", "stringLengths", "stringCount", "uresult", "status"]),
        #
        'ulocdata_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["localeID", "status"]),
        #
        'ulocdata_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["uld"]),
        #
        'ulocdata_setNoSubstitute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeChar(label="SByte")], SimTypeBottom(label="Void"), arg_names=["uld", "setting"]),
        #
        'ulocdata_getNoSubstitute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["uld"]),
        #
        'ulocdata_getExemplarSet': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ULocaleDataExemplarSetType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["uld", "fillIn", "options", "extype", "status"]),
        #
        'ulocdata_getDelimiter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="ULocaleDataDelimiterType"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uld", "type", "result", "resultLength", "status"]),
        #
        'ulocdata_getMeasurementSystem': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UMeasurementSystem"), arg_names=["localeID", "status"]),
        #
        'ulocdata_getPaperSize': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["localeID", "height", "width", "status"]),
        #
        'ulocdata_getCLDRVersion': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["versionArray", "status"]),
        #
        'ulocdata_getLocaleDisplayPattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uld", "pattern", "patternCapacity", "status"]),
        #
        'ulocdata_getLocaleSeparator': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uld", "separator", "separatorCapacity", "status"]),
        #
        'u_formatMessage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["locale", "pattern", "patternLength", "result", "resultLength", "status"]),
        #
        'u_vformatMessage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["locale", "pattern", "patternLength", "result", "resultLength", "ap", "status"]),
        #
        'u_parseMessage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["locale", "pattern", "patternLength", "source", "sourceLength", "status"]),
        #
        'u_vparseMessage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["locale", "pattern", "patternLength", "source", "sourceLength", "ap", "status"]),
        #
        'u_formatMessageWithError': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["locale", "pattern", "patternLength", "result", "resultLength", "parseError", "status"]),
        #
        'u_vformatMessageWithError': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["locale", "pattern", "patternLength", "result", "resultLength", "parseError", "ap", "status"]),
        #
        'u_parseMessageWithError': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["locale", "pattern", "patternLength", "source", "sourceLength", "parseError", "status"]),
        #
        'u_vparseMessageWithError': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["locale", "pattern", "patternLength", "source", "sourceLength", "ap", "parseError", "status"]),
        #
        'umsg_open': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["pattern", "patternLength", "locale", "parseError", "status"]),
        #
        'umsg_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["format"]),
        #
        'umsg_clone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["fmt", "status"]),
        #
        'umsg_setLocale': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "locale"]),
        #
        'umsg_getLocale': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["fmt"]),
        #
        'umsg_applyPattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "pattern", "patternLength", "parseError", "status"]),
        #
        'umsg_toPattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "result", "resultLength", "status"]),
        #
        'umsg_format': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "result", "resultLength", "status"]),
        #
        'umsg_vformat': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "result", "resultLength", "ap", "status"]),
        #
        'umsg_parse': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "source", "sourceLength", "count", "status"]),
        #
        'umsg_vparse': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "source", "sourceLength", "count", "ap", "status"]),
        #
        'umsg_autoQuoteApostrophe': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pattern", "patternLength", "dest", "destCapacity", "ec"]),
        #
        'unum_open': SimTypeFunction([SimTypeInt(signed=False, label="UNumberFormatStyle"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["style", "pattern", "patternLength", "locale", "parseErr", "status"]),
        #
        'unum_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt"]),
        #
        'unum_clone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["fmt", "status"]),
        #
        'unum_format': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UFieldPosition", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "number", "result", "resultLength", "pos", "status"]),
        #
        'unum_formatInt64': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UFieldPosition", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "number", "result", "resultLength", "pos", "status"]),
        #
        'unum_formatDouble': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UFieldPosition", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "number", "result", "resultLength", "pos", "status"]),
        #
        'unum_formatDoubleForFields': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["format", "number", "result", "resultLength", "fpositer", "status"]),
        #
        'unum_formatDecimal': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UFieldPosition", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "number", "length", "result", "resultLength", "pos", "status"]),
        #
        'unum_formatDoubleCurrency': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UFieldPosition", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "number", "currency", "result", "resultLength", "pos", "status"]),
        #
        'unum_formatUFormattable': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UFieldPosition", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "number", "result", "resultLength", "pos", "status"]),
        #
        'unum_parse': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "text", "textLength", "parsePos", "status"]),
        #
        'unum_parseInt64': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["fmt", "text", "textLength", "parsePos", "status"]),
        #
        'unum_parseDouble': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeFloat(size=64), arg_names=["fmt", "text", "textLength", "parsePos", "status"]),
        #
        'unum_parseDecimal': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "text", "textLength", "parsePos", "outBuf", "outBufLength", "status"]),
        #
        'unum_parseDoubleCurrency': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeFloat(size=64), arg_names=["fmt", "text", "textLength", "parsePos", "currency", "status"]),
        #
        'unum_parseToUFormattable': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["fmt", "result", "text", "textLength", "parsePos", "status"]),
        #
        'unum_applyPattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["format", "localized", "pattern", "patternLength", "parseError", "status"]),
        #
        'unum_getAvailable': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["localeIndex"]),
        #
        'unum_countAvailable': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'unum_getAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UNumberFormatAttribute")], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "attr"]),
        #
        'unum_setAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UNumberFormatAttribute"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["fmt", "attr", "newValue"]),
        #
        'unum_getDoubleAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UNumberFormatAttribute")], SimTypeFloat(size=64), arg_names=["fmt", "attr"]),
        #
        'unum_setDoubleAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UNumberFormatAttribute"), SimTypeFloat(size=64)], SimTypeBottom(label="Void"), arg_names=["fmt", "attr", "newValue"]),
        #
        'unum_getTextAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UNumberFormatTextAttribute"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "tag", "result", "resultLength", "status"]),
        #
        'unum_setTextAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UNumberFormatTextAttribute"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "tag", "newValue", "newValueLength", "status"]),
        #
        'unum_toPattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "isPatternLocalized", "result", "resultLength", "status"]),
        #
        'unum_getSymbol': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UNumberFormatSymbol"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "symbol", "buffer", "size", "status"]),
        #
        'unum_setSymbol': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UNumberFormatSymbol"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "symbol", "value", "length", "status"]),
        #
        'unum_getLocaleByType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="ULocDataLocaleType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["fmt", "type", "status"]),
        #
        'unum_setContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDisplayContext"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "value", "status"]),
        #
        'unum_getContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDisplayContextType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UDisplayContext"), arg_names=["fmt", "type", "status"]),
        #
        'udat_toCalendarDateField': SimTypeFunction([SimTypeInt(signed=False, label="UDateFormatField")], SimTypeInt(signed=False, label="UCalendarDateFields"), arg_names=["field"]),
        #
        'udat_open': SimTypeFunction([SimTypeInt(signed=False, label="UDateFormatStyle"), SimTypeInt(signed=False, label="UDateFormatStyle"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["timeStyle", "dateStyle", "locale", "tzID", "tzIDLength", "pattern", "patternLength", "status"]),
        #
        'udat_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["format"]),
        #
        'udat_getBooleanAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDateFormatBooleanAttribute"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["fmt", "attr", "status"]),
        #
        'udat_setBooleanAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDateFormatBooleanAttribute"), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "attr", "newValue", "status"]),
        #
        'udat_clone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["fmt", "status"]),
        #
        'udat_format': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UFieldPosition", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["format", "dateToFormat", "result", "resultLength", "position", "status"]),
        #
        'udat_formatCalendar': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UFieldPosition", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["format", "calendar", "result", "capacity", "position", "status"]),
        #
        'udat_formatForFields': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["format", "dateToFormat", "result", "resultLength", "fpositer", "status"]),
        #
        'udat_formatCalendarForFields': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["format", "calendar", "result", "capacity", "fpositer", "status"]),
        #
        'udat_parse': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeFloat(size=64), arg_names=["format", "text", "textLength", "parsePos", "status"]),
        #
        'udat_parseCalendar': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["format", "calendar", "text", "textLength", "parsePos", "status"]),
        #
        'udat_isLenient': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["fmt"]),
        #
        'udat_setLenient': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeChar(label="SByte")], SimTypeBottom(label="Void"), arg_names=["fmt", "isLenient"]),
        #
        'udat_getCalendar': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["fmt"]),
        #
        'udat_setCalendar': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "calendarToSet"]),
        #
        'udat_getNumberFormat': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["fmt"]),
        #
        'udat_getNumberFormatForField': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["fmt", "field"]),
        #
        'udat_adoptNumberFormatForFields': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "fields", "numberFormatToSet", "status"]),
        #
        'udat_setNumberFormat': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "numberFormatToSet"]),
        #
        'udat_adoptNumberFormat': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "numberFormatToAdopt"]),
        #
        'udat_getAvailable': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["localeIndex"]),
        #
        'udat_countAvailable': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'udat_get2DigitYearStart': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeFloat(size=64), arg_names=["fmt", "status"]),
        #
        'udat_set2DigitYearStart': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeFloat(size=64), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "d", "status"]),
        #
        'udat_toPattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "localized", "result", "resultLength", "status"]),
        #
        'udat_applyPattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["format", "localized", "pattern", "patternLength"]),
        #
        'udat_getSymbols': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDateFormatSymbolType"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "type", "symbolIndex", "result", "resultLength", "status"]),
        #
        'udat_countSymbols': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDateFormatSymbolType")], SimTypeInt(signed=True, label="Int32"), arg_names=["fmt", "type"]),
        #
        'udat_setSymbols': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDateFormatSymbolType"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["format", "type", "symbolIndex", "value", "valueLength", "status"]),
        #
        'udat_getLocaleByType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="ULocDataLocaleType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["fmt", "type", "status"]),
        #
        'udat_setContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDisplayContext"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["fmt", "value", "status"]),
        #
        'udat_getContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDisplayContextType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UDisplayContext"), arg_names=["fmt", "type", "status"]),
        #
        'udatpg_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["locale", "pErrorCode"]),
        #
        'udatpg_openEmpty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["pErrorCode"]),
        #
        'udatpg_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["dtpg"]),
        #
        'udatpg_clone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["dtpg", "pErrorCode"]),
        #
        'udatpg_getBestPattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dtpg", "skeleton", "length", "bestPattern", "capacity", "pErrorCode"]),
        #
        'udatpg_getBestPatternWithOptions': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UDateTimePatternMatchOptions"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dtpg", "skeleton", "length", "options", "bestPattern", "capacity", "pErrorCode"]),
        #
        'udatpg_getSkeleton': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["unusedDtpg", "pattern", "length", "skeleton", "capacity", "pErrorCode"]),
        #
        'udatpg_getBaseSkeleton': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["unusedDtpg", "pattern", "length", "baseSkeleton", "capacity", "pErrorCode"]),
        #
        'udatpg_addPattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="SByte"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="UDateTimePatternConflict"), arg_names=["dtpg", "pattern", "patternLength", "override", "conflictingPattern", "capacity", "pLength", "pErrorCode"]),
        #
        'udatpg_setAppendItemFormat': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDateTimePatternField"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["dtpg", "field", "value", "length"]),
        #
        'udatpg_getAppendItemFormat': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDateTimePatternField"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dtpg", "field", "pLength"]),
        #
        'udatpg_setAppendItemName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDateTimePatternField"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["dtpg", "field", "value", "length"]),
        #
        'udatpg_getAppendItemName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDateTimePatternField"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dtpg", "field", "pLength"]),
        #
        'udatpg_getFieldDisplayName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDateTimePatternField"), SimTypeInt(signed=False, label="UDateTimePGDisplayWidth"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dtpg", "field", "width", "fieldName", "capacity", "pErrorCode"]),
        #
        'udatpg_setDateTimeFormat': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["dtpg", "dtFormat", "length"]),
        #
        'udatpg_getDateTimeFormat': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dtpg", "pLength"]),
        #
        'udatpg_setDecimal': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["dtpg", "decimal", "length"]),
        #
        'udatpg_getDecimal': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dtpg", "pLength"]),
        #
        'udatpg_replaceFieldTypes': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dtpg", "pattern", "patternLength", "skeleton", "skeletonLength", "dest", "destCapacity", "pErrorCode"]),
        #
        'udatpg_replaceFieldTypesWithOptions': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UDateTimePatternMatchOptions"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dtpg", "pattern", "patternLength", "skeleton", "skeletonLength", "options", "dest", "destCapacity", "pErrorCode"]),
        #
        'udatpg_openSkeletons': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["dtpg", "pErrorCode"]),
        #
        'udatpg_openBaseSkeletons': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["dtpg", "pErrorCode"]),
        #
        'udatpg_getPatternForSkeleton': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["dtpg", "skeleton", "skeletonLength", "pLength"]),
        #
        'unumf_openForSkeletonAndLocale': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["skeleton", "skeletonLen", "locale", "ec"]),
        #
        'unumf_openForSkeletonAndLocaleWithError': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["skeleton", "skeletonLen", "locale", "perror", "ec"]),
        #
        'unumf_openResult': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["ec"]),
        #
        'unumf_formatInt': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["uformatter", "value", "uresult", "ec"]),
        #
        'unumf_formatDouble': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=64), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["uformatter", "value", "uresult", "ec"]),
        #
        'unumf_formatDecimal': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["uformatter", "value", "valueLen", "uresult", "ec"]),
        #
        'unumf_resultAsValue': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["uresult", "ec"]),
        #
        'unumf_resultToString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uresult", "buffer", "bufferCapacity", "ec"]),
        #
        'unumf_resultNextFieldPosition': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UFieldPosition", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["uresult", "ufpos", "ec"]),
        #
        'unumf_resultGetAllFieldPositions': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["uresult", "ufpositer", "ec"]),
        #
        'unumf_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["uformatter"]),
        #
        'unumf_closeResult': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["uresult"]),
        #
        'unumsys_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["locale", "status"]),
        #
        'unumsys_openByName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["name", "status"]),
        #
        'unumsys_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["unumsys"]),
        #
        'unumsys_openAvailableNames': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["status"]),
        #
        'unumsys_getName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["unumsys"]),
        #
        'unumsys_isAlgorithmic': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["unumsys"]),
        #
        'unumsys_getRadix': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["unumsys"]),
        #
        'unumsys_getDescription': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["unumsys", "result", "resultLength", "status"]),
        #
        'uplrules_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["locale", "status"]),
        #
        'uplrules_openForType': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UPluralType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["locale", "type", "status"]),
        #
        'uplrules_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["uplrules"]),
        #
        'uplrules_select': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uplrules", "number", "keyword", "capacity", "status"]),
        #
        'uplrules_selectFormatted': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uplrules", "number", "keyword", "capacity", "status"]),
        #
        'uplrules_getKeywords': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["uplrules", "status"]),
        #
        'uregex_open': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pattern", "patternLength", "flags", "pe", "status"]),
        #
        'uregex_openUText': SimTypeFunction([SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pattern", "flags", "pe", "status"]),
        #
        'uregex_openC': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pattern", "flags", "pe", "status"]),
        #
        'uregex_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp"]),
        #
        'uregex_clone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["regexp", "status"]),
        #
        'uregex_pattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["regexp", "patLength", "status"]),
        #
        'uregex_patternUText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), arg_names=["regexp", "status"]),
        #
        'uregex_flags': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "status"]),
        #
        'uregex_setText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "text", "textLength", "status"]),
        #
        'uregex_setUText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "text", "status"]),
        #
        'uregex_getText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["regexp", "textLength", "status"]),
        #
        'uregex_getUText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), arg_names=["regexp", "dest", "status"]),
        #
        'uregex_refreshUText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "text", "status"]),
        #
        'uregex_matches': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["regexp", "startIndex", "status"]),
        #
        'uregex_matches64': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["regexp", "startIndex", "status"]),
        #
        'uregex_lookingAt': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["regexp", "startIndex", "status"]),
        #
        'uregex_lookingAt64': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["regexp", "startIndex", "status"]),
        #
        'uregex_find': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["regexp", "startIndex", "status"]),
        #
        'uregex_find64': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["regexp", "startIndex", "status"]),
        #
        'uregex_findNext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["regexp", "status"]),
        #
        'uregex_groupCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "status"]),
        #
        'uregex_groupNumberFromName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "groupName", "nameLength", "status"]),
        #
        'uregex_groupNumberFromCName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "groupName", "nameLength", "status"]),
        #
        'uregex_group': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "groupNum", "dest", "destCapacity", "status"]),
        #
        'uregex_groupUText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), arg_names=["regexp", "groupNum", "dest", "groupLength", "status"]),
        #
        'uregex_start': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "groupNum", "status"]),
        #
        'uregex_start64': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["regexp", "groupNum", "status"]),
        #
        'uregex_end': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "groupNum", "status"]),
        #
        'uregex_end64': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["regexp", "groupNum", "status"]),
        #
        'uregex_reset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "index", "status"]),
        #
        'uregex_reset64': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "index", "status"]),
        #
        'uregex_setRegion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "regionStart", "regionLimit", "status"]),
        #
        'uregex_setRegion64': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "regionStart", "regionLimit", "status"]),
        #
        'uregex_setRegionAndStart': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "regionStart", "regionLimit", "startIndex", "status"]),
        #
        'uregex_regionStart': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "status"]),
        #
        'uregex_regionStart64': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["regexp", "status"]),
        #
        'uregex_regionEnd': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "status"]),
        #
        'uregex_regionEnd64': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["regexp", "status"]),
        #
        'uregex_hasTransparentBounds': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["regexp", "status"]),
        #
        'uregex_useTransparentBounds': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "b", "status"]),
        #
        'uregex_hasAnchoringBounds': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["regexp", "status"]),
        #
        'uregex_useAnchoringBounds': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "b", "status"]),
        #
        'uregex_hitEnd': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["regexp", "status"]),
        #
        'uregex_requireEnd': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeChar(label="SByte"), arg_names=["regexp", "status"]),
        #
        'uregex_replaceAll': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "replacementText", "replacementLength", "destBuf", "destCapacity", "status"]),
        #
        'uregex_replaceAllUText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), arg_names=["regexp", "replacement", "dest", "status"]),
        #
        'uregex_replaceFirst': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "replacementText", "replacementLength", "destBuf", "destCapacity", "status"]),
        #
        'uregex_replaceFirstUText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), arg_names=["regexp", "replacement", "dest", "status"]),
        #
        'uregex_appendReplacement': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "replacementText", "replacementLength", "destBuf", "destCapacity", "status"]),
        #
        'uregex_appendReplacementUText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "replacementText", "dest", "status"]),
        #
        'uregex_appendTail': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "destBuf", "destCapacity", "status"]),
        #
        'uregex_appendTailUText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), arg_names=["regexp", "dest", "status"]),
        #
        'uregex_split': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "destBuf", "destCapacity", "requiredCapacity", "destFields", "destFieldsCapacity", "status"]),
        #
        'uregex_splitUText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("UText", SimStruct), offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "destFields", "destFieldsCapacity", "status"]),
        #
        'uregex_setTimeLimit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "limit", "status"]),
        #
        'uregex_getTimeLimit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "status"]),
        #
        'uregex_setStackLimit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "limit", "status"]),
        #
        'uregex_getStackLimit': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regexp", "status"]),
        #
        'uregex_setMatchCallback': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["context", "steps"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "callback", "context", "status"]),
        #
        'uregex_getMatchCallback': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="SByte"), arg_names=["context", "steps"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "callback", "context", "status"]),
        #
        'uregex_setFindProgressCallback': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeChar(label="SByte"), arg_names=["context", "matchIndex"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "callback", "context", "status"]),
        #
        'uregex_getFindProgressCallback': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeChar(label="SByte"), arg_names=["context", "matchIndex"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["regexp", "callback", "context", "status"]),
        #
        'uregion_getRegionFromCode': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["regionCode", "status"]),
        #
        'uregion_getRegionFromNumericCode': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["code", "status"]),
        #
        'uregion_getAvailable': SimTypeFunction([SimTypeInt(signed=False, label="URegionType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["type", "status"]),
        #
        'uregion_areEqual': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["uregion", "otherRegion"]),
        #
        'uregion_getContainingRegion': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["uregion"]),
        #
        'uregion_getContainingRegionOfType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="URegionType")], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["uregion", "type"]),
        #
        'uregion_getContainedRegions': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["uregion", "status"]),
        #
        'uregion_getContainedRegionsOfType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="URegionType"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["uregion", "type", "status"]),
        #
        'uregion_contains': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="SByte"), arg_names=["uregion", "otherRegion"]),
        #
        'uregion_getPreferredValues': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["uregion", "status"]),
        #
        'uregion_getRegionCode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["uregion"]),
        #
        'uregion_getNumericCode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uregion"]),
        #
        'uregion_getType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="URegionType"), arg_names=["uregion"]),
        #
        'ureldatefmt_open': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UDateRelativeDateTimeFormatterStyle"), SimTypeInt(signed=False, label="UDisplayContext"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["locale", "nfToAdopt", "width", "capitalizationContext", "status"]),
        #
        'ureldatefmt_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["reldatefmt"]),
        #
        'ureldatefmt_openResult': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["ec"]),
        #
        'ureldatefmt_resultAsValue': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["ufrdt", "ec"]),
        #
        'ureldatefmt_closeResult': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["ufrdt"]),
        #
        'ureldatefmt_formatNumeric': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=64), SimTypeInt(signed=False, label="URelativeDateTimeUnit"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["reldatefmt", "offset", "unit", "result", "resultCapacity", "status"]),
        #
        'ureldatefmt_formatNumericToResult': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=64), SimTypeInt(signed=False, label="URelativeDateTimeUnit"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["reldatefmt", "offset", "unit", "result", "status"]),
        #
        'ureldatefmt_format': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=64), SimTypeInt(signed=False, label="URelativeDateTimeUnit"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["reldatefmt", "offset", "unit", "result", "resultCapacity", "status"]),
        #
        'ureldatefmt_formatToResult': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeFloat(size=64), SimTypeInt(signed=False, label="URelativeDateTimeUnit"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["reldatefmt", "offset", "unit", "result", "status"]),
        #
        'ureldatefmt_combineDateAndTime': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["reldatefmt", "relativeDateString", "relativeDateStringLen", "timeString", "timeStringLen", "result", "resultCapacity", "status"]),
        #
        'usearch_open': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pattern", "patternlength", "text", "textlength", "locale", "breakiter", "status"]),
        #
        'usearch_openFromCollator': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pattern", "patternlength", "text", "textlength", "collator", "breakiter", "status"]),
        #
        'usearch_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["searchiter"]),
        #
        'usearch_setOffset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["strsrch", "position", "status"]),
        #
        'usearch_getOffset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strsrch"]),
        #
        'usearch_setAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="USearchAttribute"), SimTypeInt(signed=False, label="USearchAttributeValue"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["strsrch", "attribute", "value", "status"]),
        #
        'usearch_getAttribute': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="USearchAttribute")], SimTypeInt(signed=False, label="USearchAttributeValue"), arg_names=["strsrch", "attribute"]),
        #
        'usearch_getMatchedStart': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strsrch"]),
        #
        'usearch_getMatchedLength': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strsrch"]),
        #
        'usearch_getMatchedText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strsrch", "result", "resultCapacity", "status"]),
        #
        'usearch_setBreakIterator': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["strsrch", "breakiter", "status"]),
        #
        'usearch_getBreakIterator': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["strsrch"]),
        #
        'usearch_setText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["strsrch", "text", "textlength", "status"]),
        #
        'usearch_getText': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["strsrch", "length"]),
        #
        'usearch_getCollator': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["strsrch"]),
        #
        'usearch_setCollator': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["strsrch", "collator", "status"]),
        #
        'usearch_setPattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["strsrch", "pattern", "patternlength", "status"]),
        #
        'usearch_getPattern': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["strsrch", "length"]),
        #
        'usearch_first': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strsrch", "status"]),
        #
        'usearch_following': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strsrch", "position", "status"]),
        #
        'usearch_last': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strsrch", "status"]),
        #
        'usearch_preceding': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strsrch", "position", "status"]),
        #
        'usearch_next': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strsrch", "status"]),
        #
        'usearch_previous': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strsrch", "status"]),
        #
        'usearch_reset': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["strsrch"]),
        #
        'uspoof_open': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["status"]),
        #
        'uspoof_openFromSerialized': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["data", "length", "pActualLength", "pErrorCode"]),
        #
        'uspoof_openFromSource': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["confusables", "confusablesLen", "confusablesWholeScript", "confusablesWholeScriptLen", "errType", "pe", "status"]),
        #
        'uspoof_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["sc"]),
        #
        'uspoof_clone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["sc", "status"]),
        #
        'uspoof_setChecks': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["sc", "checks", "status"]),
        #
        'uspoof_getChecks': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sc", "status"]),
        #
        'uspoof_setRestrictionLevel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="URestrictionLevel")], SimTypeBottom(label="Void"), arg_names=["sc", "restrictionLevel"]),
        #
        'uspoof_getRestrictionLevel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="URestrictionLevel"), arg_names=["sc"]),
        #
        'uspoof_setAllowedLocales': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["sc", "localesList", "status"]),
        #
        'uspoof_getAllowedLocales': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["sc", "status"]),
        #
        'uspoof_setAllowedChars': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["sc", "chars", "status"]),
        #
        'uspoof_getAllowedChars': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["sc", "status"]),
        #
        'uspoof_check': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sc", "id", "length", "position", "status"]),
        #
        'uspoof_checkUTF8': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sc", "id", "length", "position", "status"]),
        #
        'uspoof_check2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sc", "id", "length", "checkResult", "status"]),
        #
        'uspoof_check2UTF8': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sc", "id", "length", "checkResult", "status"]),
        #
        'uspoof_openCheckResult': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["status"]),
        #
        'uspoof_closeCheckResult': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["checkResult"]),
        #
        'uspoof_getCheckResultChecks': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["checkResult", "status"]),
        #
        'uspoof_getCheckResultRestrictionLevel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=False, label="URestrictionLevel"), arg_names=["checkResult", "status"]),
        #
        'uspoof_getCheckResultNumerics': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["checkResult", "status"]),
        #
        'uspoof_areConfusable': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sc", "id1", "length1", "id2", "length2", "status"]),
        #
        'uspoof_areConfusableUTF8': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sc", "id1", "length1", "id2", "length2", "status"]),
        #
        'uspoof_getSkeleton': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sc", "type", "id", "length", "dest", "destCapacity", "status"]),
        #
        'uspoof_getSkeletonUTF8': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sc", "type", "id", "length", "dest", "destCapacity", "status"]),
        #
        'uspoof_getInclusionSet': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["status"]),
        #
        'uspoof_getRecommendedSet': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["status"]),
        #
        'uspoof_serialize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sc", "data", "capacity", "status"]),
        #
        'utmscale_getTimeScaleValue': SimTypeFunction([SimTypeInt(signed=False, label="UDateTimeScale"), SimTypeInt(signed=False, label="UTimeScaleValue"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["timeScale", "value", "status"]),
        #
        'utmscale_fromInt64': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UDateTimeScale"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["otherTime", "timeScale", "status"]),
        #
        'utmscale_toInt64': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UDateTimeScale"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["universalTime", "timeScale", "status"]),
        #
        'utrans_openU': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UTransDirection"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UParseError", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["id", "idLength", "dir", "rules", "rulesLength", "parseError", "pErrorCode"]),
        #
        'utrans_openInverse': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["trans", "status"]),
        #
        'utrans_clone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), arg_names=["trans", "status"]),
        #
        'utrans_close': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["trans"]),
        #
        'utrans_getUnicodeID': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["trans", "resultLength"]),
        #
        'utrans_register': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["adoptedTrans", "status"]),
        #
        'utrans_unregisterID': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["id", "idLength"]),
        #
        'utrans_setFilter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["trans", "filterPattern", "filterPatternLen", "status"]),
        #
        'utrans_countAvailableIDs': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'utrans_openIDs': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["pErrorCode"]),
        #
        'utrans_trans': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("UReplaceableCallbacks", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["trans", "rep", "repFunc", "start", "limit", "status"]),
        #
        'utrans_transIncremental': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("UReplaceableCallbacks", SimStruct), offset=0), SimTypePointer(SimTypeRef("UTransPosition", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["trans", "rep", "repFunc", "pos", "status"]),
        #
        'utrans_transUChars': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["trans", "text", "textLength", "textCapacity", "start", "limit", "status"]),
        #
        'utrans_transIncrementalUChars': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UTransPosition", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeBottom(label="Void"), arg_names=["trans", "text", "textLength", "textCapacity", "pos", "status"]),
        #
        'utrans_toRules': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["trans", "escapeUnprintable", "result", "resultLength", "status"]),
        #
        'utrans_getSourceSet': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UErrorCode"), offset=0)], SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), arg_names=["trans", "ignoreFilter", "fillIn", "status"]),
    }

lib.set_prototypes(prototypes)
