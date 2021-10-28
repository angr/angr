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
lib.set_library_names("shlwapi.dll")
prototypes = \
    {
        # 
        'ShellMessageBoxA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAppInst", "hWnd", "lpcText", "lpcTitle", "fuStyle"]),
        # 
        'ShellMessageBoxW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAppInst", "hWnd", "lpcText", "lpcTitle", "fuStyle"]),
        # 
        'StrChrA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszStart", "wMatch"]),
        # 
        'StrChrW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeChar(label="Char")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszStart", "wMatch"]),
        # 
        'StrChrIA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszStart", "wMatch"]),
        # 
        'StrChrIW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeChar(label="Char")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszStart", "wMatch"]),
        # 
        'StrChrNW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeChar(label="Char"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszStart", "wMatch", "cchMax"]),
        # 
        'StrChrNIW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeChar(label="Char"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszStart", "wMatch", "cchMax"]),
        # 
        'StrCmpNA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psz1", "psz2", "nChar"]),
        # 
        'StrCmpNW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psz1", "psz2", "nChar"]),
        # 
        'StrCmpNIA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psz1", "psz2", "nChar"]),
        # 
        'StrCmpNIW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psz1", "psz2", "nChar"]),
        # 
        'StrCSpnA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszStr", "pszSet"]),
        # 
        'StrCSpnW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszStr", "pszSet"]),
        # 
        'StrCSpnIA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszStr", "pszSet"]),
        # 
        'StrCSpnIW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszStr", "pszSet"]),
        # 
        'StrDupA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszSrch"]),
        # 
        'StrDupW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszSrch"]),
        # 
        'StrFormatByteSizeEx': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="SFBS_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ull", "flags", "pszBuf", "cchBuf"]),
        # 
        'StrFormatByteSizeA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["dw", "pszBuf", "cchBuf"]),
        # 
        'StrFormatByteSize64A': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["qdw", "pszBuf", "cchBuf"]),
        # 
        'StrFormatByteSizeW': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["qdw", "pszBuf", "cchBuf"]),
        # 
        'StrFormatKBSizeW': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["qdw", "pszBuf", "cchBuf"]),
        # 
        'StrFormatKBSizeA': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["qdw", "pszBuf", "cchBuf"]),
        # 
        'StrFromTimeIntervalA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszOut", "cchMax", "dwTimeMS", "digits"]),
        # 
        'StrFromTimeIntervalW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszOut", "cchMax", "dwTimeMS", "digits"]),
        # 
        'StrIsIntlEqualA': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fCaseSens", "pszString1", "pszString2", "nChar"]),
        # 
        'StrIsIntlEqualW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fCaseSens", "pszString1", "pszString2", "nChar"]),
        # 
        'StrNCatA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["psz1", "psz2", "cchMax"]),
        # 
        'StrNCatW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["psz1", "psz2", "cchMax"]),
        # 
        'StrPBrkA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["psz", "pszSet"]),
        # 
        'StrPBrkW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["psz", "pszSet"]),
        # 
        'StrRChrA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszStart", "pszEnd", "wMatch"]),
        # 
        'StrRChrW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeChar(label="Char")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszStart", "pszEnd", "wMatch"]),
        # 
        'StrRChrIA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszStart", "pszEnd", "wMatch"]),
        # 
        'StrRChrIW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeChar(label="Char")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszStart", "pszEnd", "wMatch"]),
        # 
        'StrRStrIA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszSource", "pszLast", "pszSrch"]),
        # 
        'StrRStrIW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszSource", "pszLast", "pszSrch"]),
        # 
        'StrSpnA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psz", "pszSet"]),
        # 
        'StrSpnW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psz", "pszSet"]),
        # 
        'StrStrA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszFirst", "pszSrch"]),
        # 
        'StrStrW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszFirst", "pszSrch"]),
        # 
        'StrStrIA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszFirst", "pszSrch"]),
        # 
        'StrStrIW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszFirst", "pszSrch"]),
        # 
        'StrStrNW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszFirst", "pszSrch", "cchMax"]),
        # 
        'StrStrNIW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszFirst", "pszSrch", "cchMax"]),
        # 
        'StrToIntA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszSrc"]),
        # 
        'StrToIntW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszSrc"]),
        # 
        'StrToIntExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszString", "dwFlags", "piRet"]),
        # 
        'StrToIntExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszString", "dwFlags", "piRet"]),
        # 
        'StrToInt64ExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszString", "dwFlags", "pllRet"]),
        # 
        'StrToInt64ExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszString", "dwFlags", "pllRet"]),
        # 
        'StrTrimA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psz", "pszTrimChars"]),
        # 
        'StrTrimW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psz", "pszTrimChars"]),
        # 
        'StrCatW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["psz1", "psz2"]),
        # 
        'StrCmpW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psz1", "psz2"]),
        # 
        'StrCmpIW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psz1", "psz2"]),
        # 
        'StrCpyW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["psz1", "psz2"]),
        # 
        'StrCpyNW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszDst", "pszSrc", "cchMax"]),
        # 
        'StrCatBuffW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszDest", "pszSrc", "cchDestBuffSize"]),
        # 
        'StrCatBuffA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszDest", "pszSrc", "cchDestBuffSize"]),
        # 
        'ChrCmpIA': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["w1", "w2"]),
        # 
        'ChrCmpIW': SimTypeFunction([SimTypeChar(label="Char"), SimTypeChar(label="Char")], SimTypeInt(signed=True, label="Int32"), arg_names=["w1", "w2"]),
        # 
        'wvnsprintfA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszDest", "cchDest", "pszFmt", "arglist"]),
        # 
        'wvnsprintfW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszDest", "cchDest", "pszFmt", "arglist"]),
        # 
        'wnsprintfA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszDest", "cchDest", "pszFmt"]),
        # 
        'wnsprintfW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszDest", "cchDest", "pszFmt"]),
        # 
        'StrRetToStrA': SimTypeFunction([SimTypePointer(SimStruct({"uType": SimTypeInt(signed=False, label="UInt32"), "Anonymous": SimUnion({"pOleStr": SimTypePointer(SimTypeChar(label="Char"), offset=0), "uOffset": SimTypeInt(signed=False, label="UInt32"), "cStr": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 260)}, name="<anon>", label="None")}, name="STRRET", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"mkid": SimStruct({"cb": SimTypeShort(signed=False, label="UInt16"), "abID": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="SHITEMID", pack=False, align=None)}, name="ITEMIDLIST", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstr", "pidl", "ppsz"]),
        # 
        'StrRetToStrW': SimTypeFunction([SimTypePointer(SimStruct({"uType": SimTypeInt(signed=False, label="UInt32"), "Anonymous": SimUnion({"pOleStr": SimTypePointer(SimTypeChar(label="Char"), offset=0), "uOffset": SimTypeInt(signed=False, label="UInt32"), "cStr": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 260)}, name="<anon>", label="None")}, name="STRRET", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"mkid": SimStruct({"cb": SimTypeShort(signed=False, label="UInt16"), "abID": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="SHITEMID", pack=False, align=None)}, name="ITEMIDLIST", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstr", "pidl", "ppsz"]),
        # 
        'StrRetToBufA': SimTypeFunction([SimTypePointer(SimStruct({"uType": SimTypeInt(signed=False, label="UInt32"), "Anonymous": SimUnion({"pOleStr": SimTypePointer(SimTypeChar(label="Char"), offset=0), "uOffset": SimTypeInt(signed=False, label="UInt32"), "cStr": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 260)}, name="<anon>", label="None")}, name="STRRET", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"mkid": SimStruct({"cb": SimTypeShort(signed=False, label="UInt16"), "abID": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="SHITEMID", pack=False, align=None)}, name="ITEMIDLIST", pack=False, align=None), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pstr", "pidl", "pszBuf", "cchBuf"]),
        # 
        'StrRetToBufW': SimTypeFunction([SimTypePointer(SimStruct({"uType": SimTypeInt(signed=False, label="UInt32"), "Anonymous": SimUnion({"pOleStr": SimTypePointer(SimTypeChar(label="Char"), offset=0), "uOffset": SimTypeInt(signed=False, label="UInt32"), "cStr": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 260)}, name="<anon>", label="None")}, name="STRRET", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"mkid": SimStruct({"cb": SimTypeShort(signed=False, label="UInt16"), "abID": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="SHITEMID", pack=False, align=None)}, name="ITEMIDLIST", pack=False, align=None), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pstr", "pidl", "pszBuf", "cchBuf"]),
        # 
        'SHStrDupA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psz", "ppwsz"]),
        # 
        'SHStrDupW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psz", "ppwsz"]),
        # 
        'StrCmpLogicalW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psz1", "psz2"]),
        # 
        'StrCatChainW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszDst", "cchDst", "ichAt", "pszSrc"]),
        # 
        'StrRetToBSTR': SimTypeFunction([SimTypePointer(SimStruct({"uType": SimTypeInt(signed=False, label="UInt32"), "Anonymous": SimUnion({"pOleStr": SimTypePointer(SimTypeChar(label="Char"), offset=0), "uOffset": SimTypeInt(signed=False, label="UInt32"), "cStr": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 260)}, name="<anon>", label="None")}, name="STRRET", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"mkid": SimStruct({"cb": SimTypeShort(signed=False, label="UInt16"), "abID": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="SHITEMID", pack=False, align=None)}, name="ITEMIDLIST", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstr", "pidl", "pbstr"]),
        # 
        'SHLoadIndirectString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszSource", "pszOutBuf", "cchOutBuf", "ppvReserved"]),
        # 
        'IsCharSpaceA': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["wch"]),
        # 
        'IsCharSpaceW': SimTypeFunction([SimTypeChar(label="Char")], SimTypeInt(signed=True, label="Int32"), arg_names=["wch"]),
        # 
        'StrCmpCA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszStr1", "pszStr2"]),
        # 
        'StrCmpCW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszStr1", "pszStr2"]),
        # 
        'StrCmpICA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszStr1", "pszStr2"]),
        # 
        'StrCmpICW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszStr1", "pszStr2"]),
        # 
        'StrCmpNCA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszStr1", "pszStr2", "nChar"]),
        # 
        'StrCmpNCW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszStr1", "pszStr2", "nChar"]),
        # 
        'StrCmpNICA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszStr1", "pszStr2", "nChar"]),
        # 
        'StrCmpNICW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszStr1", "pszStr2", "nChar"]),
        # 
        'IntlStrEqWorkerA': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fCaseSens", "lpString1", "lpString2", "nChar"]),
        # 
        'IntlStrEqWorkerW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fCaseSens", "lpString1", "lpString2", "nChar"]),
        # 
        'PathAddBackslashA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszPath"]),
        # 
        'PathAddBackslashW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszPath"]),
        # 
        'PathAddExtensionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszExt"]),
        # 
        'PathAddExtensionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszExt"]),
        # 
        'PathAppendA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszMore"]),
        # 
        'PathAppendW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszMore"]),
        # 
        'PathBuildRootA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszRoot", "iDrive"]),
        # 
        'PathBuildRootW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszRoot", "iDrive"]),
        # 
        'PathCanonicalizeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszBuf", "pszPath"]),
        # 
        'PathCanonicalizeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszBuf", "pszPath"]),
        # 
        'PathCombineA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszDest", "pszDir", "pszFile"]),
        # 
        'PathCombineW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszDest", "pszDir", "pszFile"]),
        # 
        'PathCompactPathA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "pszPath", "dx"]),
        # 
        'PathCompactPathW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDC", "pszPath", "dx"]),
        # 
        'PathCompactPathExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszOut", "pszSrc", "cchMax", "dwFlags"]),
        # 
        'PathCompactPathExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszOut", "pszSrc", "cchMax", "dwFlags"]),
        # 
        'PathCommonPrefixA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFile1", "pszFile2", "achPath"]),
        # 
        'PathCommonPrefixW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFile1", "pszFile2", "achPath"]),
        # 
        'PathFileExistsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathFileExistsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathFindExtensionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszPath"]),
        # 
        'PathFindExtensionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszPath"]),
        # 
        'PathFindFileNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszPath"]),
        # 
        'PathFindFileNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszPath"]),
        # 
        'PathFindNextComponentA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszPath"]),
        # 
        'PathFindNextComponentW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszPath"]),
        # 
        'PathFindOnPathA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "ppszOtherDirs"]),
        # 
        'PathFindOnPathW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "ppszOtherDirs"]),
        # 
        'PathFindSuffixArrayA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszPath", "apszSuffix", "iArraySize"]),
        # 
        'PathFindSuffixArrayW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszPath", "apszSuffix", "iArraySize"]),
        # 
        'PathGetArgsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszPath"]),
        # 
        'PathGetArgsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszPath"]),
        # 
        'PathIsLFNFileSpecA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszName"]),
        # 
        'PathIsLFNFileSpecW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszName"]),
        # 
        'PathGetCharTypeA': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ch"]),
        # 
        'PathGetCharTypeW': SimTypeFunction([SimTypeChar(label="Char")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ch"]),
        # 
        'PathGetDriveNumberA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathGetDriveNumberW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsDirectoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsDirectoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsDirectoryEmptyA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsDirectoryEmptyW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsFileSpecA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsFileSpecW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsPrefixA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPrefix", "pszPath"]),
        # 
        'PathIsPrefixW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPrefix", "pszPath"]),
        # 
        'PathIsRelativeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsRelativeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsRootA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsRootW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsSameRootA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath1", "pszPath2"]),
        # 
        'PathIsSameRootW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath1", "pszPath2"]),
        # 
        'PathIsUNCA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsUNCW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsNetworkPathA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsNetworkPathW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsUNCServerA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsUNCServerW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsUNCServerShareA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsUNCServerShareW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsContentTypeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszContentType"]),
        # 
        'PathIsContentTypeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszContentType"]),
        # 
        'PathIsURLA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsURLW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathMakePrettyA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathMakePrettyW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathMatchSpecA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFile", "pszSpec"]),
        # 
        'PathMatchSpecW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFile", "pszSpec"]),
        # 
        'PathMatchSpecExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFile", "pszSpec", "dwFlags"]),
        # 
        'PathMatchSpecExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFile", "pszSpec", "dwFlags"]),
        # 
        'PathParseIconLocationA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszIconFile"]),
        # 
        'PathParseIconLocationW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszIconFile"]),
        # 
        'PathQuoteSpacesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpsz"]),
        # 
        'PathQuoteSpacesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpsz"]),
        # 
        'PathRelativePathToA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszFrom", "dwAttrFrom", "pszTo", "dwAttrTo"]),
        # 
        'PathRelativePathToW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszFrom", "dwAttrFrom", "pszTo", "dwAttrTo"]),
        # 
        'PathRemoveArgsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pszPath"]),
        # 
        'PathRemoveArgsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pszPath"]),
        # 
        'PathRemoveBackslashA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszPath"]),
        # 
        'PathRemoveBackslashW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszPath"]),
        # 
        'PathRemoveBlanksA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pszPath"]),
        # 
        'PathRemoveBlanksW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pszPath"]),
        # 
        'PathRemoveExtensionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pszPath"]),
        # 
        'PathRemoveExtensionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pszPath"]),
        # 
        'PathRemoveFileSpecA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathRemoveFileSpecW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathRenameExtensionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszExt"]),
        # 
        'PathRenameExtensionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszExt"]),
        # 
        'PathSearchAndQualifyA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszBuf", "cchBuf"]),
        # 
        'PathSearchAndQualifyW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszBuf", "cchBuf"]),
        # 
        'PathSetDlgItemPathA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["hDlg", "id", "pszPath"]),
        # 
        'PathSetDlgItemPathW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["hDlg", "id", "pszPath"]),
        # 
        'PathSkipRootA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszPath"]),
        # 
        'PathSkipRootW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszPath"]),
        # 
        'PathStripPathA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pszPath"]),
        # 
        'PathStripPathW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pszPath"]),
        # 
        'PathStripToRootA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathStripToRootW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathUnquoteSpacesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpsz"]),
        # 
        'PathUnquoteSpacesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpsz"]),
        # 
        'PathMakeSystemFolderA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathMakeSystemFolderW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathUnmakeSystemFolderA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathUnmakeSystemFolderW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        # 
        'PathIsSystemFolderA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "dwAttrb"]),
        # 
        'PathIsSystemFolderW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "dwAttrb"]),
        # 
        'PathUndecorateA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pszPath"]),
        # 
        'PathUndecorateW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pszPath"]),
        # 
        'PathUnExpandEnvStringsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszBuf", "cchBuf"]),
        # 
        'PathUnExpandEnvStringsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszBuf", "cchBuf"]),
        # 
        'UrlCompareA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psz1", "psz2", "fIgnoreSlash"]),
        # 
        'UrlCompareW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psz1", "psz2", "fIgnoreSlash"]),
        # 
        'UrlCombineA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszBase", "pszRelative", "pszCombined", "pcchCombined", "dwFlags"]),
        # 
        'UrlCombineW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszBase", "pszRelative", "pszCombined", "pcchCombined", "dwFlags"]),
        # 
        'UrlCanonicalizeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pszCanonicalized", "pcchCanonicalized", "dwFlags"]),
        # 
        'UrlCanonicalizeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pszCanonicalized", "pcchCanonicalized", "dwFlags"]),
        # 
        'UrlIsOpaqueA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszURL"]),
        # 
        'UrlIsOpaqueW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszURL"]),
        # 
        'UrlIsNoHistoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszURL"]),
        # 
        'UrlIsNoHistoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszURL"]),
        # 
        'UrlIsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="URLIS")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "UrlIs"]),
        # 
        'UrlIsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="URLIS")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "UrlIs"]),
        # 
        'UrlGetLocationA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pszURL"]),
        # 
        'UrlGetLocationW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszURL"]),
        # 
        'UrlUnescapeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pszUnescaped", "pcchUnescaped", "dwFlags"]),
        # 
        'UrlUnescapeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pszUnescaped", "pcchUnescaped", "dwFlags"]),
        # 
        'UrlEscapeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pszEscaped", "pcchEscaped", "dwFlags"]),
        # 
        'UrlEscapeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pszEscaped", "pcchEscaped", "dwFlags"]),
        # 
        'UrlCreateFromPathA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszUrl", "pcchUrl", "dwFlags"]),
        # 
        'UrlCreateFromPathW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszUrl", "pcchUrl", "dwFlags"]),
        # 
        'PathCreateFromUrlA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pszPath", "pcchPath", "dwFlags"]),
        # 
        'PathCreateFromUrlW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pszPath", "pcchPath", "dwFlags"]),
        # 
        'PathCreateFromUrlAlloc': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszIn", "ppszOut", "dwFlags"]),
        # 
        'UrlHashA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pbHash", "cbHash"]),
        # 
        'UrlHashW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pbHash", "cbHash"]),
        # 
        'UrlGetPartW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszIn", "pszOut", "pcchOut", "dwPart", "dwFlags"]),
        # 
        'UrlGetPartA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszIn", "pszOut", "pcchOut", "dwPart", "dwFlags"]),
        # 
        'UrlApplySchemeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszIn", "pszOut", "pcchOut", "dwFlags"]),
        # 
        'UrlApplySchemeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszIn", "pszOut", "pcchOut", "dwFlags"]),
        # 
        'HashData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pbData", "cbData", "pbHash", "cbHash"]),
        # 
        'UrlFixupW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pcszUrl", "pszTranslatedUrl", "cchMax"]),
        # 
        'ParseURLA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "pszProtocol": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cchProtocol": SimTypeInt(signed=False, label="UInt32"), "pszSuffix": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cchSuffix": SimTypeInt(signed=False, label="UInt32"), "nScheme": SimTypeInt(signed=False, label="UInt32")}, name="PARSEDURLA", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcszURL", "ppu"]),
        # 
        'ParseURLW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "pszProtocol": SimTypePointer(SimTypeChar(label="Char"), offset=0), "cchProtocol": SimTypeInt(signed=False, label="UInt32"), "pszSuffix": SimTypePointer(SimTypeChar(label="Char"), offset=0), "cchSuffix": SimTypeInt(signed=False, label="UInt32"), "nScheme": SimTypeInt(signed=False, label="UInt32")}, name="PARSEDURLW", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcszURL", "ppu"]),
        # 
        'SHDeleteEmptyKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszSubKey"]),
        # 
        'SHDeleteEmptyKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszSubKey"]),
        # 
        'SHDeleteKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszSubKey"]),
        # 
        'SHDeleteKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszSubKey"]),
        # 
        'SHRegDuplicateHKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hkey"]),
        # 
        'SHDeleteValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszSubKey", "pszValue"]),
        # 
        'SHDeleteValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszSubKey", "pszValue"]),
        # 
        'SHGetValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszSubKey", "pszValue", "pdwType", "pvData", "pcbData"]),
        # 
        'SHGetValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszSubKey", "pszValue", "pdwType", "pvData", "pcbData"]),
        # 
        'SHSetValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszSubKey", "pszValue", "dwType", "pvData", "cbData"]),
        # 
        'SHSetValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszSubKey", "pszValue", "dwType", "pvData", "cbData"]),
        # 
        'SHRegGetValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszSubKey", "pszValue", "srrfFlags", "pdwType", "pvData", "pcbData"]),
        # 
        'SHRegGetValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszSubKey", "pszValue", "srrfFlags", "pdwType", "pvData", "pcbData"]),
        # 
        'SHRegGetValueFromHKCUHKLM': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszKey", "pwszValue", "srrfFlags", "pdwType", "pvData", "pcbData"]),
        # 
        'SHQueryValueExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszValue", "pdwReserved", "pdwType", "pvData", "pcbData"]),
        # 
        'SHQueryValueExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pszValue", "pdwReserved", "pdwType", "pvData", "pcbData"]),
        # 
        'SHEnumKeyExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "dwIndex", "pszName", "pcchName"]),
        # 
        'SHEnumKeyExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "dwIndex", "pszName", "pcchName"]),
        # 
        'SHEnumValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "dwIndex", "pszValueName", "pcchValueName", "pdwType", "pvData", "pcbData"]),
        # 
        'SHEnumValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "dwIndex", "pszValueName", "pcchValueName", "pdwType", "pvData", "pcbData"]),
        # 
        'SHQueryInfoKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pcSubKeys", "pcchMaxSubKeyLen", "pcValues", "pcchMaxValueNameLen"]),
        # 
        'SHQueryInfoKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hkey", "pcSubKeys", "pcchMaxSubKeyLen", "pcValues", "pcchMaxValueNameLen"]),
        # 
        'SHCopyKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hkeySrc", "pszSrcSubKey", "hkeyDest", "fReserved"]),
        # 
        'SHCopyKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hkeySrc", "pszSrcSubKey", "hkeyDest", "fReserved"]),
        # 
        'SHRegGetPathA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "pcszSubKey", "pcszValue", "pszPath", "dwFlags"]),
        # 
        'SHRegGetPathW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "pcszSubKey", "pcszValue", "pszPath", "dwFlags"]),
        # 
        'SHRegSetPathA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "pcszSubKey", "pcszValue", "pcszPath", "dwFlags"]),
        # 
        'SHRegSetPathW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "pcszSubKey", "pcszValue", "pcszPath", "dwFlags"]),
        # 
        'SHRegCreateUSKeyA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "samDesired", "hRelativeUSKey", "phNewUSKey", "dwFlags"]),
        # 
        'SHRegCreateUSKeyW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzPath", "samDesired", "hRelativeUSKey", "phNewUSKey", "dwFlags"]),
        # 
        'SHRegOpenUSKeyA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "samDesired", "hRelativeUSKey", "phNewUSKey", "fIgnoreHKCU"]),
        # 
        'SHRegOpenUSKeyW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzPath", "samDesired", "hRelativeUSKey", "phNewUSKey", "fIgnoreHKCU"]),
        # 
        'SHRegQueryUSValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSKey", "pszValue", "pdwType", "pvData", "pcbData", "fIgnoreHKCU", "pvDefaultData", "dwDefaultDataSize"]),
        # 
        'SHRegQueryUSValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSKey", "pszValue", "pdwType", "pvData", "pcbData", "fIgnoreHKCU", "pvDefaultData", "dwDefaultDataSize"]),
        # 
        'SHRegWriteUSValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSKey", "pszValue", "dwType", "pvData", "cbData", "dwFlags"]),
        # 
        'SHRegWriteUSValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSKey", "pwzValue", "dwType", "pvData", "cbData", "dwFlags"]),
        # 
        'SHRegDeleteUSValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="SHREGDEL_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSKey", "pszValue", "delRegFlags"]),
        # 
        'SHRegDeleteUSValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="SHREGDEL_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSKey", "pwzValue", "delRegFlags"]),
        # 
        'SHRegDeleteEmptyUSKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="SHREGDEL_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSKey", "pwzSubKey", "delRegFlags"]),
        # 
        'SHRegDeleteEmptyUSKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="SHREGDEL_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSKey", "pszSubKey", "delRegFlags"]),
        # 
        'SHRegEnumUSKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="SHREGENUM_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSKey", "dwIndex", "pszName", "pcchName", "enumRegFlags"]),
        # 
        'SHRegEnumUSKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="SHREGENUM_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSKey", "dwIndex", "pwzName", "pcchName", "enumRegFlags"]),
        # 
        'SHRegEnumUSValueA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="SHREGENUM_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSkey", "dwIndex", "pszValueName", "pcchValueName", "pdwType", "pvData", "pcbData", "enumRegFlags"]),
        # 
        'SHRegEnumUSValueW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="SHREGENUM_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSkey", "dwIndex", "pszValueName", "pcchValueName", "pdwType", "pvData", "pcbData", "enumRegFlags"]),
        # 
        'SHRegQueryInfoUSKeyA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="SHREGENUM_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSKey", "pcSubKeys", "pcchMaxSubKeyLen", "pcValues", "pcchMaxValueNameLen", "enumRegFlags"]),
        # 
        'SHRegQueryInfoUSKeyW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="SHREGENUM_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSKey", "pcSubKeys", "pcchMaxSubKeyLen", "pcValues", "pcchMaxValueNameLen", "enumRegFlags"]),
        # 
        'SHRegCloseUSKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hUSKey"]),
        # 
        'SHRegGetUSValueA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszSubKey", "pszValue", "pdwType", "pvData", "pcbData", "fIgnoreHKCU", "pvDefaultData", "dwDefaultDataSize"]),
        # 
        'SHRegGetUSValueW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszSubKey", "pszValue", "pdwType", "pvData", "pcbData", "fIgnoreHKCU", "pvDefaultData", "dwDefaultDataSize"]),
        # 
        'SHRegSetUSValueA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszSubKey", "pszValue", "dwType", "pvData", "cbData", "dwFlags"]),
        # 
        'SHRegSetUSValueW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzSubKey", "pwzValue", "dwType", "pvData", "cbData", "dwFlags"]),
        # 
        'SHRegGetIntW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hk", "pwzKey", "iDefault"]),
        # 
        'SHRegGetBoolUSValueA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszSubKey", "pszValue", "fIgnoreHKCU", "fDefault"]),
        # 
        'SHRegGetBoolUSValueW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszSubKey", "pszValue", "fIgnoreHKCU", "fDefault"]),
        # 
        'AssocCreate': SimTypeFunction([SimTypeBottom(label="Guid"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsid", "riid", "ppv"]),
        # 
        'AssocQueryStringA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ASSOCSTR"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "str", "pszAssoc", "pszExtra", "pszOut", "pcchOut"]),
        # 
        'AssocQueryStringW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ASSOCSTR"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "str", "pszAssoc", "pszExtra", "pszOut", "pcchOut"]),
        # 
        'AssocQueryStringByKeyA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ASSOCSTR"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "str", "hkAssoc", "pszExtra", "pszOut", "pcchOut"]),
        # 
        'AssocQueryStringByKeyW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ASSOCSTR"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "str", "hkAssoc", "pszExtra", "pszOut", "pcchOut"]),
        # 
        'AssocQueryKeyA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ASSOCKEY"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "key", "pszAssoc", "pszExtra", "phkeyOut"]),
        # 
        'AssocQueryKeyW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ASSOCKEY"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "key", "pszAssoc", "pszExtra", "phkeyOut"]),
        # 
        'AssocIsDangerous': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszAssoc"]),
        # 
        'AssocGetPerceivedType': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="PERCEIVED"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszExt", "ptype", "pflag", "ppszType"]),
        # 
        'SHOpenRegStreamA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="IStream"), arg_names=["hkey", "pszSubkey", "pszValue", "grfMode"]),
        # 
        'SHOpenRegStreamW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="IStream"), arg_names=["hkey", "pszSubkey", "pszValue", "grfMode"]),
        # 
        'SHOpenRegStream2A': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="IStream"), arg_names=["hkey", "pszSubkey", "pszValue", "grfMode"]),
        # 
        'SHOpenRegStream2W': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="IStream"), arg_names=["hkey", "pszSubkey", "pszValue", "grfMode"]),
        # 
        'SHCreateStreamOnFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFile", "grfMode", "ppstm"]),
        # 
        'SHCreateStreamOnFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFile", "grfMode", "ppstm"]),
        # 
        'SHCreateStreamOnFileEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeBottom(label="IStream"), SimTypePointer(SimTypeBottom(label="IStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFile", "grfMode", "dwAttributes", "fCreate", "pstmTemplate", "ppstm"]),
        # 
        'SHCreateMemStream': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="IStream"), arg_names=["pInit", "cbInit"]),
        # 
        'GetAcceptLanguagesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszLanguages", "pcchLanguages"]),
        # 
        'GetAcceptLanguagesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszLanguages", "pcchLanguages"]),
        # 
        'IUnknown_Set': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0), SimTypeBottom(label="IUnknown")], SimTypeBottom(label="Void"), arg_names=["ppunk", "punk"]),
        # 
        'IUnknown_AtomicRelease': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["ppunk"]),
        # 
        'IUnknown_GetWindow': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punk", "phwnd"]),
        # 
        'IUnknown_SetSite': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["punk", "punkSite"]),
        # 
        'IUnknown_GetSite': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punk", "riid", "ppv"]),
        # 
        'IUnknown_QueryService': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punk", "guidService", "riid", "ppvOut"]),
        # 
        'IStream_Read': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pstm", "pv", "cb"]),
        # 
        'IStream_Write': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pstm", "pv", "cb"]),
        # 
        'IStream_Reset': SimTypeFunction([SimTypeBottom(label="IStream")], SimTypeInt(signed=True, label="Int32"), arg_names=["pstm"]),
        # 
        'IStream_Size': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimUnion({"Anonymous": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=False, label="UInt32")}, name="_Anonymous_e__Struct", pack=False, align=None), "u": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=False, label="UInt32")}, name="_u_e__Struct", pack=False, align=None), "QuadPart": SimTypeLongLong(signed=False, label="UInt64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstm", "pui"]),
        # 
        'ConnectToConnectionPoint': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="IConnectionPoint"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punk", "riidEvent", "fConnect", "punkTarget", "pdwCookie", "ppcpOut"]),
        # 
        'IStream_ReadPidl': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypePointer(SimStruct({"mkid": SimStruct({"cb": SimTypeShort(signed=False, label="UInt16"), "abID": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="SHITEMID", pack=False, align=None)}, name="ITEMIDLIST", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstm", "ppidlOut"]),
        # 
        'IStream_WritePidl': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimStruct({"mkid": SimStruct({"cb": SimTypeShort(signed=False, label="UInt16"), "abID": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="SHITEMID", pack=False, align=None)}, name="ITEMIDLIST", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstm", "pidlWrite"]),
        # 
        'IStream_ReadStr': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstm", "ppsz"]),
        # 
        'IStream_WriteStr': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstm", "psz"]),
        # 
        'IStream_Copy': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypeBottom(label="IStream"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pstmFrom", "pstmTo", "cb"]),
        # 
        'SHGetViewStatePropertyBag': SimTypeFunction([SimTypePointer(SimStruct({"mkid": SimStruct({"cb": SimTypeShort(signed=False, label="UInt16"), "abID": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="SHITEMID", pack=False, align=None)}, name="ITEMIDLIST", pack=False, align=None), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidl", "pszBagName", "dwFlags", "riid", "ppv"]),
        # 
        'SHFormatDateTimeA': SimTypeFunction([SimTypePointer(SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pft", "pdwFlags", "pszBuf", "cchBuf"]),
        # 
        'SHFormatDateTimeW': SimTypeFunction([SimTypePointer(SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pft", "pdwFlags", "pszBuf", "cchBuf"]),
        # 
        'SHAnsiToUnicode': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszSrc", "pwszDst", "cwchBuf"]),
        # 
        'SHAnsiToAnsi': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszSrc", "pszDst", "cchBuf"]),
        # 
        'SHUnicodeToAnsi': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszSrc", "pszDst", "cchBuf"]),
        # 
        'SHUnicodeToUnicode': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzSrc", "pwzDst", "cwchBuf"]),
        # 
        'SHMessageBoxCheckA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszText", "pszCaption", "uType", "iDefault", "pszRegVal"]),
        # 
        'SHMessageBoxCheckW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszText", "pszCaption", "uType", "iDefault", "pszRegVal"]),
        # 
        'SHSendMessageBroadcastA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["uMsg", "wParam", "lParam"]),
        # 
        'SHSendMessageBroadcastW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["uMsg", "wParam", "lParam"]),
        # 
        'SHStripMneumonicA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["pszMenu"]),
        # 
        'SHStripMneumonicW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeChar(label="Char"), arg_names=["pszMenu"]),
        # 
        'IsOS': SimTypeFunction([SimTypeInt(signed=False, label="OS")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwOS"]),
        # 
        'SHGlobalCounterGetValue': SimTypeFunction([SimTypeInt(signed=False, label="SHGLOBALCOUNTER")], SimTypeInt(signed=True, label="Int32"), arg_names=["id"]),
        # 
        'SHGlobalCounterIncrement': SimTypeFunction([SimTypeInt(signed=False, label="SHGLOBALCOUNTER")], SimTypeInt(signed=True, label="Int32"), arg_names=["id"]),
        # 
        'SHGlobalCounterDecrement': SimTypeFunction([SimTypeInt(signed=False, label="SHGLOBALCOUNTER")], SimTypeInt(signed=True, label="Int32"), arg_names=["id"]),
        # 
        'SHAllocShared': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pvData", "dwSize", "dwProcessId"]),
        # 
        'SHFreeShared': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hData", "dwProcessId"]),
        # 
        'SHLockShared': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hData", "dwProcessId"]),
        # 
        'SHUnlockShared': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvData"]),
        # 
        'WhichPlatform': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        # 
        'QISearch': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"piid": SimTypePointer(SimTypeBottom(label="Guid"), offset=0), "dwOffset": SimTypeInt(signed=False, label="UInt32")}, name="QITAB", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["that", "pqit", "riid", "ppv"]),
        # 
        'SHIsLowMemoryMachine': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwType"]),
        # 
        'GetMenuPosFromID': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hmenu", "id"]),
        # 
        'SHGetInverseCMAP': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pbMap", "cbMap"]),
        # 
        'SHAutoComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndEdit", "dwFlags"]),
        # 
        'SHCreateThreadRef': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcRef", "ppunk"]),
        # 
        'SHSetThreadRef': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["punk"]),
        # 
        'SHGetThreadRef': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppunk"]),
        # 
        'SHSkipJunction': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbc", "pclsid"]),
        # 
        'SHCreateThread': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpThreadParameter"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpThreadParameter"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfnThreadProc", "pData", "flags", "pfnCallback"]),
        # 
        'SHCreateThreadWithHandle': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpThreadParameter"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpThreadParameter"]), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfnThreadProc", "pData", "flags", "pfnCallback", "pHandle"]),
        # 
        'SHReleaseThreadRef': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        # 
        'SHCreateShellPalette': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hdc"]),
        # 
        'ColorRGBToHLS': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["clrRGB", "pwHue", "pwLuminance", "pwSaturation"]),
        # 
        'ColorHLSToRGB': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["wHue", "wLuminance", "wSaturation"]),
        # 
        'ColorAdjustLuma': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["clrRGB", "n", "fScale"]),
        # 
        'IsInternetESCEnabled': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
    }

lib.set_prototypes(prototypes)
