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
lib.add_all_from_dict(P['win32'])
lib.add_alias('EncodePointer', 'DecodePointer')
lib.add_alias('GlobalAlloc', 'LocalAlloc')

lib.add('lstrcatA', P['libc']['strcat'])
lib.add('lstrcmpA', P['libc']['strcmp'])
lib.add('lstrcpyA', P['libc']['strcpy'])
lib.add('lstrcpynA', P['libc']['strncpy'])
lib.add('lstrlenA', P['libc']['strlen'])
lib.add('lstrcmpW', P['libc']['wcscmp'])
lib.add('lstrcmpiW', P['libc']['wcscasecmp'])
lib.set_library_names("kernel32.dll")
prototypes = \
    {
        #
        'ClearCommBreak': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile"]),
        #
        'ClearCommError': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="CLEAR_COMM_ERROR_FLAGS"), offset=0), SimTypePointer(SimTypeRef("COMSTAT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpErrors", "lpStat"]),
        #
        'SetupComm': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "dwInQueue", "dwOutQueue"]),
        #
        'EscapeCommFunction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ESCAPE_COMM_FUNCTION")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "dwFunc"]),
        #
        'GetCommConfig': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("COMMCONFIG", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCommDev", "lpCC", "lpdwSize"]),
        #
        'GetCommMask': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="COMM_EVENT_MASK"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpEvtMask"]),
        #
        'GetCommProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("COMMPROP", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpCommProp"]),
        #
        'GetCommModemStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="MODEM_STATUS_FLAGS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpModemStat"]),
        #
        'GetCommState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DCB", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpDCB"]),
        #
        'GetCommTimeouts': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("COMMTIMEOUTS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpCommTimeouts"]),
        #
        'PurgeComm': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PURGE_COMM_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "dwFlags"]),
        #
        'SetCommBreak': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile"]),
        #
        'SetCommConfig': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("COMMCONFIG", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCommDev", "lpCC", "dwSize"]),
        #
        'SetCommMask': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="COMM_EVENT_MASK")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "dwEvtMask"]),
        #
        'SetCommState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DCB", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpDCB"]),
        #
        'SetCommTimeouts': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("COMMTIMEOUTS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpCommTimeouts"]),
        #
        'TransmitCommChar': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="SByte")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "cChar"]),
        #
        'WaitCommEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="COMM_EVENT_MASK"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpEvtMask", "lpOverlapped"]),
        #
        'BuildCommDCBA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("DCB", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDef", "lpDCB"]),
        #
        'BuildCommDCBW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DCB", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDef", "lpDCB"]),
        #
        'BuildCommDCBAndTimeoutsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("DCB", SimStruct), offset=0), SimTypePointer(SimTypeRef("COMMTIMEOUTS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDef", "lpDCB", "lpCommTimeouts"]),
        #
        'BuildCommDCBAndTimeoutsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DCB", SimStruct), offset=0), SimTypePointer(SimTypeRef("COMMTIMEOUTS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDef", "lpDCB", "lpCommTimeouts"]),
        #
        'CommConfigDialogA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("COMMCONFIG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszName", "hWnd", "lpCC"]),
        #
        'CommConfigDialogW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("COMMCONFIG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszName", "hWnd", "lpCC"]),
        #
        'GetDefaultCommConfigA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("COMMCONFIG", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszName", "lpCC", "lpdwSize"]),
        #
        'GetDefaultCommConfigW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("COMMCONFIG", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszName", "lpCC", "lpdwSize"]),
        #
        'SetDefaultCommConfigA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("COMMCONFIG", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszName", "lpCC", "dwSize"]),
        #
        'SetDefaultCommConfigW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("COMMCONFIG", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszName", "lpCC", "dwSize"]),
        #
        'CloseHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hObject"]),
        #
        'DuplicateHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="DUPLICATE_HANDLE_OPTIONS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hSourceProcessHandle", "hSourceHandle", "hTargetProcessHandle", "lpTargetHandle", "dwDesiredAccess", "bInheritHandle", "dwOptions"]),
        #
        'GetHandleInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hObject", "lpdwFlags"]),
        #
        'SetHandleInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="HANDLE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hObject", "dwMask", "dwFlags"]),
        #
        'FreeLibrary': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLibModule"]),
        #
        'GetLastError': SimTypeFunction([], SimTypeInt(signed=False, label="WIN32_ERROR")),
        #
        'SetLastError': SimTypeFunction([SimTypeInt(signed=False, label="WIN32_ERROR")], SimTypeBottom(label="Void"), arg_names=["dwErrCode"]),
        #
        'GlobalFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hMem"]),
        #
        'LocalFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hMem"]),
        #
        'GetDateFormatA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwFlags", "lpDate", "lpFormat", "lpDateStr", "cchDate"]),
        #
        'GetDateFormatW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwFlags", "lpDate", "lpFormat", "lpDateStr", "cchDate"]),
        #
        'GetTimeFormatA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwFlags", "lpTime", "lpFormat", "lpTimeStr", "cchTime"]),
        #
        'GetTimeFormatW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwFlags", "lpTime", "lpFormat", "lpTimeStr", "cchTime"]),
        #
        'GetTimeFormatEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="TIME_FORMAT_FLAGS"), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleName", "dwFlags", "lpTime", "lpFormat", "lpTimeStr", "cchTime"]),
        #
        'GetDateFormatEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="ENUM_DATE_FORMATS_FLAGS"), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleName", "dwFlags", "lpDate", "lpFormat", "lpDateStr", "cchDate", "lpCalendar"]),
        #
        'GetDurationFormatEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleName", "dwFlags", "lpDuration", "ullDuration", "lpFormat", "lpDurationStr", "cchDuration"]),
        #
        'CompareStringEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="COMPARE_STRING_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("NLSVERSIONINFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="COMPARESTRING_RESULT"), arg_names=["lpLocaleName", "dwCmpFlags", "lpString1", "cchCount1", "lpString2", "cchCount2", "lpVersionInformation", "lpReserved", "lParam"]),
        #
        'CompareStringOrdinal': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="COMPARESTRING_RESULT"), arg_names=["lpString1", "cchCount1", "lpString2", "cchCount2", "bIgnoreCase"]),
        #
        'CompareStringW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="COMPARESTRING_RESULT"), arg_names=["Locale", "dwCmpFlags", "lpString1", "cchCount1", "lpString2", "cchCount2"]),
        #
        'FoldStringW': SimTypeFunction([SimTypeInt(signed=False, label="FOLD_STRING_MAP_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwMapFlags", "lpSrcStr", "cchSrc", "lpDestStr", "cchDest"]),
        #
        'GetStringTypeExW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwInfoType", "lpSrcStr", "cchSrc", "lpCharType"]),
        #
        'GetStringTypeW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwInfoType", "lpSrcStr", "cchSrc", "lpCharType"]),
        #
        'MultiByteToWideChar': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MULTI_BYTE_TO_WIDE_CHAR_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CodePage", "dwFlags", "lpMultiByteStr", "cbMultiByte", "lpWideCharStr", "cchWideChar"]),
        #
        'WideCharToMultiByte': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CodePage", "dwFlags", "lpWideCharStr", "cchWideChar", "lpMultiByteStr", "cbMultiByte", "lpDefaultChar", "lpUsedDefaultChar"]),
        #
        'IsValidCodePage': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CodePage"]),
        #
        'GetACP': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'GetOEMCP': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'GetCPInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CPINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CodePage", "lpCPInfo"]),
        #
        'GetCPInfoExA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CPINFOEXA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CodePage", "dwFlags", "lpCPInfoEx"]),
        #
        'GetCPInfoExW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CPINFOEXW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CodePage", "dwFlags", "lpCPInfoEx"]),
        #
        'CompareStringA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="SByte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="SByte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="COMPARESTRING_RESULT"), arg_names=["Locale", "dwCmpFlags", "lpString1", "cchCount1", "lpString2", "cchCount2"]),
        #
        'FindNLSString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwFindNLSStringFlags", "lpStringSource", "cchSource", "lpStringValue", "cchValue", "pcchFound"]),
        #
        'LCMapStringW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwMapFlags", "lpSrcStr", "cchSrc", "lpDestStr", "cchDest"]),
        #
        'LCMapStringA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwMapFlags", "lpSrcStr", "cchSrc", "lpDestStr", "cchDest"]),
        #
        'GetLocaleInfoW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "LCType", "lpLCData", "cchData"]),
        #
        'GetLocaleInfoA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "LCType", "lpLCData", "cchData"]),
        #
        'SetLocaleInfoA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "LCType", "lpLCData"]),
        #
        'SetLocaleInfoW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "LCType", "lpLCData"]),
        #
        'GetCalendarInfoA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "Calendar", "CalType", "lpCalData", "cchData", "lpValue"]),
        #
        'GetCalendarInfoW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "Calendar", "CalType", "lpCalData", "cchData", "lpValue"]),
        #
        'SetCalendarInfoA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "Calendar", "CalType", "lpCalData"]),
        #
        'SetCalendarInfoW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "Calendar", "CalType", "lpCalData"]),
        #
        'IsDBCSLeadByte': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["TestChar"]),
        #
        'IsDBCSLeadByteEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["CodePage", "TestChar"]),
        #
        'LocaleNameToLCID': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpName", "dwFlags"]),
        #
        'LCIDToLocaleName': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "lpName", "cchName", "dwFlags"]),
        #
        'GetDurationFormat': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwFlags", "lpDuration", "ullDuration", "lpFormat", "lpDurationStr", "cchDuration"]),
        #
        'GetNumberFormatA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("NUMBERFMTA", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwFlags", "lpValue", "lpFormat", "lpNumberStr", "cchNumber"]),
        #
        'GetNumberFormatW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("NUMBERFMTW", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwFlags", "lpValue", "lpFormat", "lpNumberStr", "cchNumber"]),
        #
        'GetCurrencyFormatA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("CURRENCYFMTA", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwFlags", "lpValue", "lpFormat", "lpCurrencyStr", "cchCurrency"]),
        #
        'GetCurrencyFormatW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CURRENCYFMTW", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwFlags", "lpValue", "lpFormat", "lpCurrencyStr", "cchCurrency"]),
        #
        'EnumCalendarInfoA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCalInfoEnumProc", "Locale", "Calendar", "CalType"]),
        #
        'EnumCalendarInfoW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCalInfoEnumProc", "Locale", "Calendar", "CalType"]),
        #
        'EnumCalendarInfoExA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCalInfoEnumProcEx", "Locale", "Calendar", "CalType"]),
        #
        'EnumCalendarInfoExW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCalInfoEnumProcEx", "Locale", "Calendar", "CalType"]),
        #
        'EnumTimeFormatsA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="TIME_FORMAT_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTimeFmtEnumProc", "Locale", "dwFlags"]),
        #
        'EnumTimeFormatsW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="TIME_FORMAT_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTimeFmtEnumProc", "Locale", "dwFlags"]),
        #
        'EnumDateFormatsA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDateFmtEnumProc", "Locale", "dwFlags"]),
        #
        'EnumDateFormatsW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDateFmtEnumProc", "Locale", "dwFlags"]),
        #
        'EnumDateFormatsExA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDateFmtEnumProcEx", "Locale", "dwFlags"]),
        #
        'EnumDateFormatsExW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDateFmtEnumProcEx", "Locale", "dwFlags"]),
        #
        'IsValidLanguageGroup': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ENUM_SYSTEM_LANGUAGE_GROUPS_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["LanguageGroup", "dwFlags"]),
        #
        'GetNLSVersion': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("NLSVERSIONINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Function", "Locale", "lpVersionInformation"]),
        #
        'IsValidLocale': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="IS_VALID_LOCALE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwFlags"]),
        #
        'GetGeoInfoA': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="SYSGEOTYPE"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["Location", "GeoType", "lpGeoData", "cchData", "LangId"]),
        #
        'GetGeoInfoW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="SYSGEOTYPE"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["Location", "GeoType", "lpGeoData", "cchData", "LangId"]),
        #
        'GetGeoInfoEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="SYSGEOTYPE"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["location", "geoType", "geoData", "geoDataCount"]),
        #
        'EnumSystemGeoID': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["GeoClass", "ParentGeoId", "lpGeoEnumProc"]),
        #
        'EnumSystemGeoNames': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["geoClass", "geoEnumProc", "data"]),
        #
        'GetUserGeoID': SimTypeFunction([SimTypeInt(signed=False, label="SYSGEOCLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["GeoClass"]),
        #
        'GetUserDefaultGeoName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["geoName", "geoNameCount"]),
        #
        'SetUserGeoID': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["GeoId"]),
        #
        'SetUserGeoName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["geoName"]),
        #
        'ConvertDefaultLocale': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Locale"]),
        #
        'GetSystemDefaultUILanguage': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        #
        'GetThreadLocale': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'SetThreadLocale': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale"]),
        #
        'GetUserDefaultUILanguage': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        #
        'GetUserDefaultLangID': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        #
        'GetSystemDefaultLangID': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        #
        'GetSystemDefaultLCID': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'GetUserDefaultLCID': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'SetThreadUILanguage': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=False, label="UInt16"), arg_names=["LangId"]),
        #
        'GetThreadUILanguage': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        #
        'GetProcessPreferredUILanguages': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pulNumLanguages", "pwszLanguagesBuffer", "pcchLanguagesBuffer"]),
        #
        'SetProcessPreferredUILanguages': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pwszLanguagesBuffer", "pulNumLanguages"]),
        #
        'GetUserPreferredUILanguages': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pulNumLanguages", "pwszLanguagesBuffer", "pcchLanguagesBuffer"]),
        #
        'GetSystemPreferredUILanguages': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pulNumLanguages", "pwszLanguagesBuffer", "pcchLanguagesBuffer"]),
        #
        'GetThreadPreferredUILanguages': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pulNumLanguages", "pwszLanguagesBuffer", "pcchLanguagesBuffer"]),
        #
        'SetThreadPreferredUILanguages': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pwszLanguagesBuffer", "pulNumLanguages"]),
        #
        'GetFileMUIInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("FILEMUIINFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pcwszFilePath", "pFileMUIInfo", "pcbFileMUIInfo"]),
        #
        'GetFileMUIPath': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pcwszFilePath", "pwszLanguage", "pcchLanguage", "pwszFileMUIPath", "pcchFileMUIPath", "pululEnumerator"]),
        #
        'GetUILanguageInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pwmszLanguage", "pwszFallbackLanguages", "pcchFallbackLanguages", "pAttributes"]),
        #
        'SetThreadPreferredUILanguages2': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "languages", "numLanguagesSet", "snapshot"]),
        #
        'RestoreThreadPreferredUILanguages': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["snapshot"]),
        #
        'NotifyUILanguageChange': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pcwstrNewLanguage", "pcwstrPreviousLanguage", "dwReserved", "pdwStatusRtrn"]),
        #
        'GetStringTypeExA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwInfoType", "lpSrcStr", "cchSrc", "lpCharType"]),
        #
        'GetStringTypeA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Locale", "dwInfoType", "lpSrcStr", "cchSrc", "lpCharType"]),
        #
        'FoldStringA': SimTypeFunction([SimTypeInt(signed=False, label="FOLD_STRING_MAP_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwMapFlags", "lpSrcStr", "cchSrc", "lpDestStr", "cchDest"]),
        #
        'EnumSystemLocalesA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleEnumProc", "dwFlags"]),
        #
        'EnumSystemLocalesW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleEnumProc", "dwFlags"]),
        #
        'EnumSystemLanguageGroupsA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]), offset=0), SimTypeInt(signed=False, label="ENUM_SYSTEM_LANGUAGE_GROUPS_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLanguageGroupEnumProc", "dwFlags", "lParam"]),
        #
        'EnumSystemLanguageGroupsW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]), offset=0), SimTypeInt(signed=False, label="ENUM_SYSTEM_LANGUAGE_GROUPS_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLanguageGroupEnumProc", "dwFlags", "lParam"]),
        #
        'EnumLanguageGroupLocalesA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLangGroupLocaleEnumProc", "LanguageGroup", "dwFlags", "lParam"]),
        #
        'EnumLanguageGroupLocalesW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLangGroupLocaleEnumProc", "LanguageGroup", "dwFlags", "lParam"]),
        #
        'EnumUILanguagesA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpUILanguageEnumProc", "dwFlags", "lParam"]),
        #
        'EnumUILanguagesW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpUILanguageEnumProc", "dwFlags", "lParam"]),
        #
        'EnumSystemCodePagesA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=False, label="ENUM_SYSTEM_CODE_PAGES_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCodePageEnumProc", "dwFlags"]),
        #
        'EnumSystemCodePagesW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=False, label="ENUM_SYSTEM_CODE_PAGES_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCodePageEnumProc", "dwFlags"]),
        #
        'IdnToNameprepUnicode': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "lpUnicodeCharStr", "cchUnicodeChar", "lpNameprepCharStr", "cchNameprepChar"]),
        #
        'NormalizeString': SimTypeFunction([SimTypeInt(signed=False, label="NORM_FORM"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["NormForm", "lpSrcString", "cwSrcLength", "lpDstString", "cwDstLength"]),
        #
        'IsNormalizedString': SimTypeFunction([SimTypeInt(signed=False, label="NORM_FORM"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["NormForm", "lpString", "cwLength"]),
        #
        'VerifyScripts': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "lpLocaleScripts", "cchLocaleScripts", "lpTestScripts", "cchTestScripts"]),
        #
        'GetStringScripts': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "lpString", "cchString", "lpScripts", "cchScripts"]),
        #
        'GetLocaleInfoEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleName", "LCType", "lpLCData", "cchData"]),
        #
        'GetCalendarInfoEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleName", "Calendar", "lpReserved", "CalType", "lpCalData", "cchData", "lpValue"]),
        #
        'GetNumberFormatEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("NUMBERFMTW", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleName", "dwFlags", "lpValue", "lpFormat", "lpNumberStr", "cchNumber"]),
        #
        'GetCurrencyFormatEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CURRENCYFMTW", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleName", "dwFlags", "lpValue", "lpFormat", "lpCurrencyStr", "cchCurrency"]),
        #
        'GetUserDefaultLocaleName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleName", "cchLocaleName"]),
        #
        'GetSystemDefaultLocaleName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleName", "cchLocaleName"]),
        #
        'IsNLSDefinedString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("NLSVERSIONINFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Function", "dwFlags", "lpVersionInformation", "lpString", "cchStr"]),
        #
        'GetNLSVersionEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("NLSVERSIONINFOEX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["function", "lpLocaleName", "lpVersionInformation"]),
        #
        'IsValidNLSVersion': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("NLSVERSIONINFOEX", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["function", "lpLocaleName", "lpVersionInformation"]),
        #
        'FindNLSStringEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("NLSVERSIONINFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleName", "dwFindNLSStringFlags", "lpStringSource", "cchSource", "lpStringValue", "cchValue", "pcchFound", "lpVersionInformation", "lpReserved", "sortHandle"]),
        #
        'LCMapStringEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("NLSVERSIONINFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleName", "dwMapFlags", "lpSrcStr", "cchSrc", "lpDestStr", "cchDest", "lpVersionInformation", "lpReserved", "sortHandle"]),
        #
        'IsValidLocaleName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleName"]),
        #
        'EnumCalendarInfoExEx': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCalInfoEnumProcExEx", "lpLocaleName", "Calendar", "lpReserved", "CalType", "lParam"]),
        #
        'EnumDateFormatsExEx': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="ENUM_DATE_FORMATS_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDateFmtEnumProcExEx", "lpLocaleName", "dwFlags", "lParam"]),
        #
        'EnumTimeFormatsEx': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTimeFmtEnumProcEx", "lpLocaleName", "dwFlags", "lParam"]),
        #
        'EnumSystemLocalesEx': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocaleEnumProcEx", "dwFlags", "lParam", "lpReserved"]),
        #
        'ResolveLocaleName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpNameToResolve", "lpLocaleName", "cchLocaleName"]),
        #
        'GetCalendarSupportedDateRange': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CALDATETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("CALDATETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Calendar", "lpCalMinDateTime", "lpCalMaxDateTime"]),
        #
        'GetCalendarDateFormatEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CALDATETIME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszLocale", "dwFlags", "lpCalDateTime", "lpFormat", "lpDateStr", "cchDate"]),
        #
        'ConvertSystemTimeToCalDateTime': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CALDATETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSysTime", "calId", "lpCalDateTime"]),
        #
        'UpdateCalendarDayOfWeek': SimTypeFunction([SimTypePointer(SimTypeRef("CALDATETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCalDateTime"]),
        #
        'AdjustCalendarDate': SimTypeFunction([SimTypePointer(SimTypeRef("CALDATETIME", SimStruct), offset=0), SimTypeInt(signed=False, label="CALDATETIME_DATEUNIT"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCalDateTime", "calUnit", "amount"]),
        #
        'ConvertCalDateTimeToSystemTime': SimTypeFunction([SimTypePointer(SimTypeRef("CALDATETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCalDateTime", "lpSysTime"]),
        #
        'IsCalendarLeapYear': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["calId", "year", "era"]),
        #
        'FindStringOrdinal': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFindStringOrdinalFlags", "lpStringSource", "cchSource", "lpStringValue", "cchValue", "bIgnoreCase"]),
        #
        'lstrcmpA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpString1", "lpString2"]),
        #
        'lstrcmpW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpString1", "lpString2"]),
        #
        'lstrcmpiA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpString1", "lpString2"]),
        #
        'lstrcmpiW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpString1", "lpString2"]),
        #
        'lstrcpynA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["lpString1", "lpString2", "iMaxLength"]),
        #
        'lstrcpynW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["lpString1", "lpString2", "iMaxLength"]),
        #
        'lstrcpyA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["lpString1", "lpString2"]),
        #
        'lstrcpyW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["lpString1", "lpString2"]),
        #
        'lstrcatA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["lpString1", "lpString2"]),
        #
        'lstrcatW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["lpString1", "lpString2"]),
        #
        'lstrlenA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpString"]),
        #
        'lstrlenW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpString"]),
        #
        'GetAppContainerNamedObjectPath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Token", "AppContainerSid", "ObjectPathLength", "ObjectPath", "ReturnLength"]),
        #
        'AddResourceAttributeAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="ACE_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CLAIM_SECURITY_ATTRIBUTES_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "AceFlags", "AccessMask", "pSid", "pAttributeInfo", "pReturnLength"]),
        #
        'AddScopedPolicyIDAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="ACE_REVISION"), SimTypeInt(signed=False, label="ACE_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAcl", "dwAceRevision", "AceFlags", "AccessMask", "pSid"]),
        #
        'CheckTokenCapability': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "CapabilitySidToCheck", "HasCapability"]),
        #
        'GetAppContainerAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Acl", "StartingAceIndex", "AppContainerAce", "AppContainerAceIndex"]),
        #
        'CheckTokenMembershipEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "SidToCheck", "Flags", "IsMember"]),
        #
        'SetCachedSigningLevel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceFiles", "SourceFileCount", "Flags", "TargetFile"]),
        #
        'GetCachedSigningLevel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["File", "Flags", "SigningLevel", "Thumbprint", "ThumbprintSize", "ThumbprintAlgorithm"]),
        #
        'SearchPathW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpPath", "lpFileName", "lpExtension", "nBufferLength", "lpBuffer", "lpFilePart"]),
        #
        'SearchPathA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpPath", "lpFileName", "lpExtension", "nBufferLength", "lpBuffer", "lpFilePart"]),
        #
        'CompareFileTime': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileTime1", "lpFileTime2"]),
        #
        'CreateDirectoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName", "lpSecurityAttributes"]),
        #
        'CreateDirectoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName", "lpSecurityAttributes"]),
        #
        'CreateFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_SHARE_MODE"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="FILE_CREATION_DISPOSITION"), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile"]),
        #
        'CreateFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_SHARE_MODE"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="FILE_CREATION_DISPOSITION"), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile"]),
        #
        'DefineDosDeviceW': SimTypeFunction([SimTypeInt(signed=False, label="DEFINE_DOS_DEVICE_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "lpDeviceName", "lpTargetPath"]),
        #
        'DeleteFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName"]),
        #
        'DeleteFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName"]),
        #
        'DeleteVolumeMountPointW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszVolumeMountPoint"]),
        #
        'FileTimeToLocalFileTime': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileTime", "lpLocalFileTime"]),
        #
        'FindClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFindFile"]),
        #
        'FindCloseChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hChangeHandle"]),
        #
        'FindFirstChangeNotificationA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="FILE_NOTIFY_CHANGE")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpPathName", "bWatchSubtree", "dwNotifyFilter"]),
        #
        'FindFirstChangeNotificationW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="FILE_NOTIFY_CHANGE")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpPathName", "bWatchSubtree", "dwNotifyFilter"]),
        #
        'FindFirstFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("WIN32_FIND_DATAA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "lpFindFileData"]),
        #
        'FindFirstFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WIN32_FIND_DATAW", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "lpFindFileData"]),
        #
        'FindFirstFileExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="FINDEX_INFO_LEVELS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="FINDEX_SEARCH_OPS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="FIND_FIRST_EX_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "fInfoLevelId", "lpFindFileData", "fSearchOp", "lpSearchFilter", "dwAdditionalFlags"]),
        #
        'FindFirstFileExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="FINDEX_INFO_LEVELS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="FINDEX_SEARCH_OPS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="FIND_FIRST_EX_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "fInfoLevelId", "lpFindFileData", "fSearchOp", "lpSearchFilter", "dwAdditionalFlags"]),
        #
        'FindFirstVolumeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszVolumeName", "cchBufferLength"]),
        #
        'FindNextChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hChangeHandle"]),
        #
        'FindNextFileA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("WIN32_FIND_DATAA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFindFile", "lpFindFileData"]),
        #
        'FindNextFileW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("WIN32_FIND_DATAW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFindFile", "lpFindFileData"]),
        #
        'FindNextVolumeW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFindVolume", "lpszVolumeName", "cchBufferLength"]),
        #
        'FindVolumeClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFindVolume"]),
        #
        'FlushFileBuffers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile"]),
        #
        'GetDiskFreeSpaceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpRootPathName", "lpSectorsPerCluster", "lpBytesPerSector", "lpNumberOfFreeClusters", "lpTotalNumberOfClusters"]),
        #
        'GetDiskFreeSpaceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpRootPathName", "lpSectorsPerCluster", "lpBytesPerSector", "lpNumberOfFreeClusters", "lpTotalNumberOfClusters"]),
        #
        'GetDiskFreeSpaceExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDirectoryName", "lpFreeBytesAvailableToCaller", "lpTotalNumberOfBytes", "lpTotalNumberOfFreeBytes"]),
        #
        'GetDiskFreeSpaceExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDirectoryName", "lpFreeBytesAvailableToCaller", "lpTotalNumberOfBytes", "lpTotalNumberOfFreeBytes"]),
        #
        'GetDiskSpaceInformationA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("DISK_SPACE_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rootPath", "diskSpaceInfo"]),
        #
        'GetDiskSpaceInformationW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DISK_SPACE_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rootPath", "diskSpaceInfo"]),
        #
        'GetDriveTypeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpRootPathName"]),
        #
        'GetDriveTypeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpRootPathName"]),
        #
        'GetFileAttributesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName"]),
        #
        'GetFileAttributesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName"]),
        #
        'GetFileAttributesExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="GET_FILEEX_INFO_LEVELS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "fInfoLevelId", "lpFileInformation"]),
        #
        'GetFileAttributesExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="GET_FILEEX_INFO_LEVELS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "fInfoLevelId", "lpFileInformation"]),
        #
        'GetFileInformationByHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("BY_HANDLE_FILE_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpFileInformation"]),
        #
        'GetFileSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hFile", "lpFileSizeHigh"]),
        #
        'GetFileSizeEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpFileSize"]),
        #
        'GetFileType': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="FILE_TYPE"), arg_names=["hFile"]),
        #
        'GetFinalPathNameByHandleA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="GETFINALPATHNAMEBYHANDLE_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hFile", "lpszFilePath", "cchFilePath", "dwFlags"]),
        #
        'GetFinalPathNameByHandleW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="GETFINALPATHNAMEBYHANDLE_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hFile", "lpszFilePath", "cchFilePath", "dwFlags"]),
        #
        'GetFileTime': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpCreationTime", "lpLastAccessTime", "lpLastWriteTime"]),
        #
        'GetFullPathNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "nBufferLength", "lpBuffer", "lpFilePart"]),
        #
        'GetFullPathNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "nBufferLength", "lpBuffer", "lpFilePart"]),
        #
        'GetLogicalDrives': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'GetLogicalDriveStringsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["nBufferLength", "lpBuffer"]),
        #
        'GetLongPathNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszShortPath", "lpszLongPath", "cchBuffer"]),
        #
        'GetLongPathNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszShortPath", "lpszLongPath", "cchBuffer"]),
        #
        'AreShortNamesEnabled': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "Enabled"]),
        #
        'GetShortPathNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszLongPath", "lpszShortPath", "cchBuffer"]),
        #
        'GetTempFileNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpPathName", "lpPrefixString", "uUnique", "lpTempFileName"]),
        #
        'GetVolumeInformationByHandleW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpVolumeNameBuffer", "nVolumeNameSize", "lpVolumeSerialNumber", "lpMaximumComponentLength", "lpFileSystemFlags", "lpFileSystemNameBuffer", "nFileSystemNameSize"]),
        #
        'GetVolumeInformationW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpRootPathName", "lpVolumeNameBuffer", "nVolumeNameSize", "lpVolumeSerialNumber", "lpMaximumComponentLength", "lpFileSystemFlags", "lpFileSystemNameBuffer", "nFileSystemNameSize"]),
        #
        'GetVolumePathNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszFileName", "lpszVolumePathName", "cchBufferLength"]),
        #
        'LocalFileTimeToFileTime': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLocalFileTime", "lpFileTime"]),
        #
        'LockFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "dwFileOffsetLow", "dwFileOffsetHigh", "nNumberOfBytesToLockLow", "nNumberOfBytesToLockHigh"]),
        #
        'LockFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="LOCK_FILE_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "dwFlags", "dwReserved", "nNumberOfBytesToLockLow", "nNumberOfBytesToLockHigh", "lpOverlapped"]),
        #
        'QueryDosDeviceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpDeviceName", "lpTargetPath", "ucchMax"]),
        #
        'ReadFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffer", "nNumberOfBytesToRead", "lpNumberOfBytesRead", "lpOverlapped"]),
        #
        'ReadFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwErrorCode", "dwNumberOfBytesTransfered", "lpOverlapped"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffer", "nNumberOfBytesToRead", "lpOverlapped", "lpCompletionRoutine"]),
        #
        'ReadFileScatter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimUnion({"Buffer": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Alignment": SimTypeLongLong(signed=False, label="UInt64")}, name="<anon>", label="None"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "aSegmentArray", "nNumberOfBytesToRead", "lpReserved", "lpOverlapped"]),
        #
        'RemoveDirectoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName"]),
        #
        'RemoveDirectoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName"]),
        #
        'SetEndOfFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile"]),
        #
        'SetFileAttributesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "dwFileAttributes"]),
        #
        'SetFileAttributesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "dwFileAttributes"]),
        #
        'SetFileInformationByHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="FILE_INFO_BY_HANDLE_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "FileInformationClass", "lpFileInformation", "dwBufferSize"]),
        #
        'SetFilePointer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="SET_FILE_POINTER_MOVE_METHOD")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hFile", "lDistanceToMove", "lpDistanceToMoveHigh", "dwMoveMethod"]),
        #
        'SetFilePointerEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="SET_FILE_POINTER_MOVE_METHOD")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "liDistanceToMove", "lpNewFilePointer", "dwMoveMethod"]),
        #
        'SetFileTime': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpCreationTime", "lpLastAccessTime", "lpLastWriteTime"]),
        #
        'SetFileValidData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "ValidDataLength"]),
        #
        'UnlockFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "dwFileOffsetLow", "dwFileOffsetHigh", "nNumberOfBytesToUnlockLow", "nNumberOfBytesToUnlockHigh"]),
        #
        'UnlockFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "dwReserved", "nNumberOfBytesToUnlockLow", "nNumberOfBytesToUnlockHigh", "lpOverlapped"]),
        #
        'WriteFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffer", "nNumberOfBytesToWrite", "lpNumberOfBytesWritten", "lpOverlapped"]),
        #
        'WriteFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwErrorCode", "dwNumberOfBytesTransfered", "lpOverlapped"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffer", "nNumberOfBytesToWrite", "lpOverlapped", "lpCompletionRoutine"]),
        #
        'WriteFileGather': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimUnion({"Buffer": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Alignment": SimTypeLongLong(signed=False, label="UInt64")}, name="<anon>", label="None"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "aSegmentArray", "nNumberOfBytesToWrite", "lpReserved", "lpOverlapped"]),
        #
        'GetTempPathW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["nBufferLength", "lpBuffer"]),
        #
        'GetVolumeNameForVolumeMountPointW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszVolumeMountPoint", "lpszVolumeName", "cchBufferLength"]),
        #
        'GetVolumePathNamesForVolumeNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszVolumeName", "lpszVolumePathNames", "cchBufferLength", "lpcchReturnLength"]),
        #
        'CreateFile2': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_SHARE_MODE"), SimTypeInt(signed=False, label="FILE_CREATION_DISPOSITION"), SimTypePointer(SimTypeRef("CREATEFILE2_EXTENDED_PARAMETERS", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "dwDesiredAccess", "dwShareMode", "dwCreationDisposition", "pCreateExParams"]),
        #
        'SetFileIoOverlappedRange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "OverlappedRangeStart", "Length"]),
        #
        'GetCompressedFileSizeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "lpFileSizeHigh"]),
        #
        'GetCompressedFileSizeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "lpFileSizeHigh"]),
        #
        'FindFirstStreamW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="STREAM_INFO_LEVELS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "InfoLevel", "lpFindStreamData", "dwFlags"]),
        #
        'FindNextStreamW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFindStream", "lpFindStreamData"]),
        #
        'AreFileApisANSI': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'GetTempPathA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["nBufferLength", "lpBuffer"]),
        #
        'FindFirstFileNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "dwFlags", "StringLength", "LinkName"]),
        #
        'FindNextFileNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFindStream", "StringLength", "LinkName"]),
        #
        'GetVolumeInformationA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpRootPathName", "lpVolumeNameBuffer", "nVolumeNameSize", "lpVolumeSerialNumber", "lpMaximumComponentLength", "lpFileSystemFlags", "lpFileSystemNameBuffer", "nFileSystemNameSize"]),
        #
        'GetTempFileNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpPathName", "lpPrefixString", "uUnique", "lpTempFileName"]),
        #
        'SetFileApisToOEM': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'SetFileApisToANSI': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'GetTempPath2W': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferLength", "Buffer"]),
        #
        'GetTempPath2A': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BufferLength", "Buffer"]),
        #
        'VerLanguageNameA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["wLang", "szLang", "cchLang"]),
        #
        'VerLanguageNameW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["wLang", "szLang", "cchLang"]),
        #
        'LZStart': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'LZDone': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'CopyLZFile': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hfSource", "hfDest"]),
        #
        'LZCopy': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hfSource", "hfDest"]),
        #
        'LZInit': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hfSource"]),
        #
        'GetExpandedNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszSource", "lpszBuffer"]),
        #
        'GetExpandedNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszSource", "lpszBuffer"]),
        #
        'LZOpenFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("OFSTRUCT", SimStruct), offset=0), SimTypeInt(signed=False, label="LZOPENFILE_STYLE")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "lpReOpenBuf", "wStyle"]),
        #
        'LZOpenFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("OFSTRUCT", SimStruct), offset=0), SimTypeInt(signed=False, label="LZOPENFILE_STYLE")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "lpReOpenBuf", "wStyle"]),
        #
        'LZSeek': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lOffset", "iOrigin"]),
        #
        'LZRead': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffer", "cbRead"]),
        #
        'LZClose': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["hFile"]),
        #
        'BuildIoRingWriteFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("IORING_HANDLE_REF", SimStruct), SimTypeRef("IORING_BUFFER_REF", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="FILE_WRITE_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="IORING_SQE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["ioRing", "fileRef", "bufferRef", "numberOfBytesToWrite", "fileOffset", "writeFlags", "userData", "sqeFlags"]),
        #
        'BuildIoRingFlushFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("IORING_HANDLE_REF", SimStruct), SimTypeInt(signed=False, label="FILE_FLUSH_MODE"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="IORING_SQE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["ioRing", "fileRef", "flushMode", "userData", "sqeFlags"]),
        #
        'Wow64EnableWow64FsRedirection': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["Wow64FsEnableRedirection"]),
        #
        'Wow64DisableWow64FsRedirection': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OldValue"]),
        #
        'Wow64RevertWow64FsRedirection': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OlValue"]),
        #
        'GetBinaryTypeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpApplicationName", "lpBinaryType"]),
        #
        'GetBinaryTypeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpApplicationName", "lpBinaryType"]),
        #
        'GetShortPathNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszLongPath", "lpszShortPath", "cchBuffer"]),
        #
        'GetLongPathNameTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszShortPath", "lpszLongPath", "cchBuffer", "hTransaction"]),
        #
        'GetLongPathNameTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszShortPath", "lpszLongPath", "cchBuffer", "hTransaction"]),
        #
        'SetFileCompletionNotificationModes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Flags"]),
        #
        'SetFileShortNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpShortName"]),
        #
        'SetFileShortNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpShortName"]),
        #
        'SetTapePosition': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TAPE_POSITION_METHOD"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDevice", "dwPositionMethod", "dwPartition", "dwOffsetLow", "dwOffsetHigh", "bImmediate"]),
        #
        'GetTapePosition': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TAPE_POSITION_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDevice", "dwPositionType", "lpdwPartition", "lpdwOffsetLow", "lpdwOffsetHigh"]),
        #
        'PrepareTape': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PREPARE_TAPE_OPERATION"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDevice", "dwOperation", "bImmediate"]),
        #
        'EraseTape': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ERASE_TAPE_TYPE"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDevice", "dwEraseType", "bImmediate"]),
        #
        'CreateTapePartition': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CREATE_TAPE_PARTITION_METHOD"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDevice", "dwPartitionMethod", "dwCount", "dwSize"]),
        #
        'WriteTapemark': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TAPEMARK_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDevice", "dwTapemarkType", "dwTapemarkCount", "bImmediate"]),
        #
        'GetTapeStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDevice"]),
        #
        'GetTapeParameters': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="GET_TAPE_DRIVE_PARAMETERS_OPERATION"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDevice", "dwOperation", "lpdwSize", "lpTapeInformation"]),
        #
        'SetTapeParameters': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TAPE_INFORMATION_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDevice", "dwOperation", "lpTapeInformation"]),
        #
        'OpenFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("OFSTRUCT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "lpReOpenBuff", "uStyle"]),
        #
        'BackupRead': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffer", "nNumberOfBytesToRead", "lpNumberOfBytesRead", "bAbort", "bProcessSecurity", "lpContext"]),
        #
        'BackupSeek': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "dwLowBytesToSeek", "dwHighBytesToSeek", "lpdwLowByteSeeked", "lpdwHighByteSeeked", "lpContext"]),
        #
        'BackupWrite': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffer", "nNumberOfBytesToWrite", "lpNumberOfBytesWritten", "bAbort", "bProcessSecurity", "lpContext"]),
        #
        'GetLogicalDriveStringsA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["nBufferLength", "lpBuffer"]),
        #
        'SetSearchPathMode': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags"]),
        #
        'CreateDirectoryExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTemplateDirectory", "lpNewDirectory", "lpSecurityAttributes"]),
        #
        'CreateDirectoryExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTemplateDirectory", "lpNewDirectory", "lpSecurityAttributes"]),
        #
        'CreateDirectoryTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTemplateDirectory", "lpNewDirectory", "lpSecurityAttributes", "hTransaction"]),
        #
        'CreateDirectoryTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTemplateDirectory", "lpNewDirectory", "lpSecurityAttributes", "hTransaction"]),
        #
        'RemoveDirectoryTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName", "hTransaction"]),
        #
        'RemoveDirectoryTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName", "hTransaction"]),
        #
        'GetFullPathNameTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "nBufferLength", "lpBuffer", "lpFilePart", "hTransaction"]),
        #
        'GetFullPathNameTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "nBufferLength", "lpBuffer", "lpFilePart", "hTransaction"]),
        #
        'DefineDosDeviceA': SimTypeFunction([SimTypeInt(signed=False, label="DEFINE_DOS_DEVICE_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "lpDeviceName", "lpTargetPath"]),
        #
        'QueryDosDeviceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpDeviceName", "lpTargetPath", "ucchMax"]),
        #
        'CreateFileTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_SHARE_MODE"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="FILE_CREATION_DISPOSITION"), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="TXFS_MINIVERSION"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile", "hTransaction", "pusMiniVersion", "lpExtendedParameter"]),
        #
        'CreateFileTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_SHARE_MODE"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="FILE_CREATION_DISPOSITION"), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="TXFS_MINIVERSION"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwCreationDisposition", "dwFlagsAndAttributes", "hTemplateFile", "hTransaction", "pusMiniVersion", "lpExtendedParameter"]),
        #
        'ReOpenFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_SHARE_MODE"), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hOriginalFile", "dwDesiredAccess", "dwShareMode", "dwFlagsAndAttributes"]),
        #
        'SetFileAttributesTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "dwFileAttributes", "hTransaction"]),
        #
        'SetFileAttributesTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "dwFileAttributes", "hTransaction"]),
        #
        'GetFileAttributesTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="GET_FILEEX_INFO_LEVELS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "fInfoLevelId", "lpFileInformation", "hTransaction"]),
        #
        'GetFileAttributesTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="GET_FILEEX_INFO_LEVELS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "fInfoLevelId", "lpFileInformation", "hTransaction"]),
        #
        'GetCompressedFileSizeTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "lpFileSizeHigh", "hTransaction"]),
        #
        'GetCompressedFileSizeTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpFileName", "lpFileSizeHigh", "hTransaction"]),
        #
        'DeleteFileTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "hTransaction"]),
        #
        'DeleteFileTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "hTransaction"]),
        #
        'CheckNameLegalDOS8Dot3A': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpName", "lpOemName", "OemNameSize", "pbNameContainsSpaces", "pbNameLegal"]),
        #
        'CheckNameLegalDOS8Dot3W': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpName", "lpOemName", "OemNameSize", "pbNameContainsSpaces", "pbNameLegal"]),
        #
        'FindFirstFileTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="FINDEX_INFO_LEVELS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="FINDEX_SEARCH_OPS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "fInfoLevelId", "lpFindFileData", "fSearchOp", "lpSearchFilter", "dwAdditionalFlags", "hTransaction"]),
        #
        'FindFirstFileTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="FINDEX_INFO_LEVELS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="FINDEX_SEARCH_OPS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "fInfoLevelId", "lpFindFileData", "fSearchOp", "lpSearchFilter", "dwAdditionalFlags", "hTransaction"]),
        #
        'CopyFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName", "bFailIfExists"]),
        #
        'CopyFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName", "bFailIfExists"]),
        #
        'CopyFileExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="LPPROGRESS_ROUTINE_CALLBACK_REASON"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TotalFileSize", "TotalBytesTransferred", "StreamSize", "StreamBytesTransferred", "dwStreamNumber", "dwCallbackReason", "hSourceFile", "hDestinationFile", "lpData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName", "lpProgressRoutine", "lpData", "pbCancel", "dwCopyFlags"]),
        #
        'CopyFileExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="LPPROGRESS_ROUTINE_CALLBACK_REASON"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TotalFileSize", "TotalBytesTransferred", "StreamSize", "StreamBytesTransferred", "dwStreamNumber", "dwCallbackReason", "hSourceFile", "hDestinationFile", "lpData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName", "lpProgressRoutine", "lpData", "pbCancel", "dwCopyFlags"]),
        #
        'CopyFileTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="LPPROGRESS_ROUTINE_CALLBACK_REASON"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TotalFileSize", "TotalBytesTransferred", "StreamSize", "StreamBytesTransferred", "dwStreamNumber", "dwCallbackReason", "hSourceFile", "hDestinationFile", "lpData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName", "lpProgressRoutine", "lpData", "pbCancel", "dwCopyFlags", "hTransaction"]),
        #
        'CopyFileTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="LPPROGRESS_ROUTINE_CALLBACK_REASON"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TotalFileSize", "TotalBytesTransferred", "StreamSize", "StreamBytesTransferred", "dwStreamNumber", "dwCallbackReason", "hSourceFile", "hDestinationFile", "lpData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName", "lpProgressRoutine", "lpData", "pbCancel", "dwCopyFlags", "hTransaction"]),
        #
        'CopyFile2': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("COPYFILE2_EXTENDED_PARAMETERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszExistingFileName", "pwszNewFileName", "pExtendedParameters"]),
        #
        'MoveFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName"]),
        #
        'MoveFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName"]),
        #
        'MoveFileExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="MOVE_FILE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName", "dwFlags"]),
        #
        'MoveFileExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="MOVE_FILE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName", "dwFlags"]),
        #
        'MoveFileWithProgressA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="LPPROGRESS_ROUTINE_CALLBACK_REASON"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TotalFileSize", "TotalBytesTransferred", "StreamSize", "StreamBytesTransferred", "dwStreamNumber", "dwCallbackReason", "hSourceFile", "hDestinationFile", "lpData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="MOVE_FILE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName", "lpProgressRoutine", "lpData", "dwFlags"]),
        #
        'MoveFileWithProgressW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="LPPROGRESS_ROUTINE_CALLBACK_REASON"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TotalFileSize", "TotalBytesTransferred", "StreamSize", "StreamBytesTransferred", "dwStreamNumber", "dwCallbackReason", "hSourceFile", "hDestinationFile", "lpData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="MOVE_FILE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName", "lpProgressRoutine", "lpData", "dwFlags"]),
        #
        'MoveFileTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="LPPROGRESS_ROUTINE_CALLBACK_REASON"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TotalFileSize", "TotalBytesTransferred", "StreamSize", "StreamBytesTransferred", "dwStreamNumber", "dwCallbackReason", "hSourceFile", "hDestinationFile", "lpData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="MOVE_FILE_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName", "lpProgressRoutine", "lpData", "dwFlags", "hTransaction"]),
        #
        'MoveFileTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="LPPROGRESS_ROUTINE_CALLBACK_REASON"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["TotalFileSize", "TotalBytesTransferred", "StreamSize", "StreamBytesTransferred", "dwStreamNumber", "dwCallbackReason", "hSourceFile", "hDestinationFile", "lpData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="MOVE_FILE_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpExistingFileName", "lpNewFileName", "lpProgressRoutine", "lpData", "dwFlags", "hTransaction"]),
        #
        'ReplaceFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="REPLACE_FILE_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpReplacedFileName", "lpReplacementFileName", "lpBackupFileName", "dwReplaceFlags", "lpExclude", "lpReserved"]),
        #
        'ReplaceFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="REPLACE_FILE_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpReplacedFileName", "lpReplacementFileName", "lpBackupFileName", "dwReplaceFlags", "lpExclude", "lpReserved"]),
        #
        'CreateHardLinkA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "lpExistingFileName", "lpSecurityAttributes"]),
        #
        'CreateHardLinkW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "lpExistingFileName", "lpSecurityAttributes"]),
        #
        'CreateHardLinkTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "lpExistingFileName", "lpSecurityAttributes", "hTransaction"]),
        #
        'CreateHardLinkTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileName", "lpExistingFileName", "lpSecurityAttributes", "hTransaction"]),
        #
        'FindFirstStreamTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="STREAM_INFO_LEVELS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "InfoLevel", "lpFindStreamData", "dwFlags", "hTransaction"]),
        #
        'FindFirstFileNameTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFileName", "dwFlags", "StringLength", "LinkName", "hTransaction"]),
        #
        'SetVolumeLabelA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpRootPathName", "lpVolumeName"]),
        #
        'SetVolumeLabelW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpRootPathName", "lpVolumeName"]),
        #
        'SetFileBandwidthReservation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "nPeriodMilliseconds", "nBytesPerPeriod", "bDiscardable", "lpTransferSize", "lpNumOutstandingRequests"]),
        #
        'GetFileBandwidthReservation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpPeriodMilliseconds", "lpBytesPerPeriod", "pDiscardable", "lpTransferSize", "lpNumOutstandingRequests"]),
        #
        'ReadDirectoryChangesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="FILE_NOTIFY_CHANGE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwErrorCode", "dwNumberOfBytesTransfered", "lpOverlapped"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDirectory", "lpBuffer", "nBufferLength", "bWatchSubtree", "dwNotifyFilter", "lpBytesReturned", "lpOverlapped", "lpCompletionRoutine"]),
        #
        'ReadDirectoryChangesExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="FILE_NOTIFY_CHANGE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwErrorCode", "dwNumberOfBytesTransfered", "lpOverlapped"]), offset=0), SimTypeInt(signed=False, label="READ_DIRECTORY_NOTIFY_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hDirectory", "lpBuffer", "nBufferLength", "bWatchSubtree", "dwNotifyFilter", "lpBytesReturned", "lpOverlapped", "lpCompletionRoutine", "ReadDirectoryNotifyInformationClass"]),
        #
        'FindFirstVolumeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszVolumeName", "cchBufferLength"]),
        #
        'FindNextVolumeA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFindVolume", "lpszVolumeName", "cchBufferLength"]),
        #
        'FindFirstVolumeMountPointA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszRootPathName", "lpszVolumeMountPoint", "cchBufferLength"]),
        #
        'FindFirstVolumeMountPointW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszRootPathName", "lpszVolumeMountPoint", "cchBufferLength"]),
        #
        'FindNextVolumeMountPointA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFindVolumeMountPoint", "lpszVolumeMountPoint", "cchBufferLength"]),
        #
        'FindNextVolumeMountPointW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFindVolumeMountPoint", "lpszVolumeMountPoint", "cchBufferLength"]),
        #
        'FindVolumeMountPointClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFindVolumeMountPoint"]),
        #
        'SetVolumeMountPointA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszVolumeMountPoint", "lpszVolumeName"]),
        #
        'SetVolumeMountPointW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszVolumeMountPoint", "lpszVolumeName"]),
        #
        'DeleteVolumeMountPointA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszVolumeMountPoint"]),
        #
        'GetVolumeNameForVolumeMountPointA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszVolumeMountPoint", "lpszVolumeName", "cchBufferLength"]),
        #
        'GetVolumePathNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszFileName", "lpszVolumePathName", "cchBufferLength"]),
        #
        'GetVolumePathNamesForVolumeNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszVolumeName", "lpszVolumePathNames", "cchBufferLength", "lpcchReturnLength"]),
        #
        'GetFileInformationByHandleEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="FILE_INFO_BY_HANDLE_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "FileInformationClass", "lpFileInformation", "dwBufferSize"]),
        #
        'OpenFileById': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILE_ID_DESCRIPTOR", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_SHARE_MODE"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hVolumeHint", "lpFileId", "dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwFlagsAndAttributes"]),
        #
        'CreateSymbolicLinkA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="SYMBOLIC_LINK_FLAGS")], SimTypeChar(label="Byte"), arg_names=["lpSymlinkFileName", "lpTargetFileName", "dwFlags"]),
        #
        'CreateSymbolicLinkW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="SYMBOLIC_LINK_FLAGS")], SimTypeChar(label="Byte"), arg_names=["lpSymlinkFileName", "lpTargetFileName", "dwFlags"]),
        #
        'CreateSymbolicLinkTransactedA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="SYMBOLIC_LINK_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["lpSymlinkFileName", "lpTargetFileName", "dwFlags", "hTransaction"]),
        #
        'CreateSymbolicLinkTransactedW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="SYMBOLIC_LINK_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["lpSymlinkFileName", "lpTargetFileName", "dwFlags", "hTransaction"]),
        #
        'GetCurrentPackageId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["bufferLength", "buffer"]),
        #
        'GetCurrentPackageFullName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFullNameLength", "packageFullName"]),
        #
        'GetCurrentPackageFamilyName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFamilyNameLength", "packageFamilyName"]),
        #
        'GetCurrentPackagePath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pathLength", "path"]),
        #
        'GetPackageId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hProcess", "bufferLength", "buffer"]),
        #
        'GetPackageFullName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hProcess", "packageFullNameLength", "packageFullName"]),
        #
        'GetPackageFamilyName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hProcess", "packageFamilyNameLength", "packageFamilyName"]),
        #
        'GetPackagePath': SimTypeFunction([SimTypePointer(SimTypeRef("PACKAGE_ID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageId", "reserved", "pathLength", "path"]),
        #
        'GetPackagePathByFullName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFullName", "pathLength", "path"]),
        #
        'GetStagedPackagePathByFullName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFullName", "pathLength", "path"]),
        #
        'GetCurrentApplicationUserModelId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["applicationUserModelIdLength", "applicationUserModelId"]),
        #
        'GetApplicationUserModelId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hProcess", "applicationUserModelIdLength", "applicationUserModelId"]),
        #
        'PackageIdFromFullName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFullName", "flags", "bufferLength", "buffer"]),
        #
        'PackageFullNameFromId': SimTypeFunction([SimTypePointer(SimTypeRef("PACKAGE_ID", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageId", "packageFullNameLength", "packageFullName"]),
        #
        'PackageFamilyNameFromId': SimTypeFunction([SimTypePointer(SimTypeRef("PACKAGE_ID", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageId", "packageFamilyNameLength", "packageFamilyName"]),
        #
        'PackageFamilyNameFromFullName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFullName", "packageFamilyNameLength", "packageFamilyName"]),
        #
        'PackageNameAndPublisherIdFromFamilyName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFamilyName", "packageNameLength", "packageName", "packagePublisherIdLength", "packagePublisherId"]),
        #
        'FormatApplicationUserModelId': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFamilyName", "packageRelativeApplicationId", "applicationUserModelIdLength", "applicationUserModelId"]),
        #
        'ParseApplicationUserModelId': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["applicationUserModelId", "packageFamilyNameLength", "packageFamilyName", "packageRelativeApplicationIdLength", "packageRelativeApplicationId"]),
        #
        'GetPackagesByPackageFamily': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFamilyName", "count", "packageFullNames", "bufferLength", "buffer"]),
        #
        'FindPackagesByPackageFamily': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFamilyName", "packageFilters", "count", "packageFullNames", "bufferLength", "buffer", "packageProperties"]),
        #
        'GetCurrentPackageInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["flags", "bufferLength", "buffer", "count"]),
        #
        'OpenPackageInfoByFullName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("_PACKAGE_INFO_REFERENCE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageFullName", "reserved", "packageInfoReference"]),
        #
        'ClosePackageInfo': SimTypeFunction([SimTypePointer(SimTypeRef("_PACKAGE_INFO_REFERENCE", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageInfoReference"]),
        #
        'GetPackageInfo': SimTypeFunction([SimTypePointer(SimTypeRef("_PACKAGE_INFO_REFERENCE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageInfoReference", "flags", "bufferLength", "buffer", "count"]),
        #
        'GetPackageApplicationIds': SimTypeFunction([SimTypePointer(SimTypeRef("_PACKAGE_INFO_REFERENCE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["packageInfoReference", "bufferLength", "buffer", "count"]),
        #
        'CheckIsMSIXPackage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageFullName", "isMSIXPackage"]),
        #
        'AppPolicyGetLifecycleManagement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="AppPolicyLifecycleManagement"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["processToken", "policy"]),
        #
        'AppPolicyGetWindowingModel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="AppPolicyWindowingModel"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["processToken", "policy"]),
        #
        'AppPolicyGetMediaFoundationCodecLoading': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="AppPolicyMediaFoundationCodecLoading"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["processToken", "policy"]),
        #
        'AppPolicyGetClrCompat': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="AppPolicyClrCompat"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["processToken", "policy"]),
        #
        'AppPolicyGetThreadInitializationType': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="AppPolicyThreadInitializationType"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["processToken", "policy"]),
        #
        'AppPolicyGetShowDeveloperDiagnostic': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="AppPolicyShowDeveloperDiagnostic"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["processToken", "policy"]),
        #
        'AppPolicyGetProcessTerminationMethod': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="AppPolicyProcessTerminationMethod"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["processToken", "policy"]),
        #
        'AppPolicyGetCreateFileAccess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="AppPolicyCreateFileAccess"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["processToken", "policy"]),
        #
        'CreatePackageVirtualizationContext': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageFamilyName", "context"]),
        #
        'ActivatePackageVirtualizationContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["context", "cookie"]),
        #
        'ReleasePackageVirtualizationContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]),
        #
        'DeactivatePackageVirtualizationContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["cookie"]),
        #
        'DuplicatePackageVirtualizationContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sourceContext", "destContext"]),
        #
        'GetCurrentPackageVirtualizationContext': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'GetProcessesInVirtualizationContext': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageFamilyName", "count", "processes"]),
        #
        'GetCurrentPackageInfo3': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="PackageInfo3Type"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "packageInfoType", "bufferLength", "buffer", "count"]),
        #
        'InstallELAMCertificateInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ELAMFile"]),
        #
        'CreateActCtxA': SimTypeFunction([SimTypePointer(SimTypeRef("ACTCTXA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pActCtx"]),
        #
        'CreateActCtxW': SimTypeFunction([SimTypePointer(SimTypeRef("ACTCTXW", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pActCtx"]),
        #
        'AddRefActCtx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hActCtx"]),
        #
        'ReleaseActCtx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hActCtx"]),
        #
        'ZombifyActCtx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hActCtx"]),
        #
        'ActivateActCtx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hActCtx", "lpCookie"]),
        #
        'DeactivateActCtx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "ulCookie"]),
        #
        'GetCurrentActCtx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lphActCtx"]),
        #
        'FindActCtxSectionStringA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("ACTCTX_SECTION_KEYED_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "lpExtensionGuid", "ulSectionId", "lpStringToFind", "ReturnedData"]),
        #
        'FindActCtxSectionStringW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("ACTCTX_SECTION_KEYED_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "lpExtensionGuid", "ulSectionId", "lpStringToFind", "ReturnedData"]),
        #
        'FindActCtxSectionGuid': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("ACTCTX_SECTION_KEYED_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "lpExtensionGuid", "ulSectionId", "lpGuidToFind", "ReturnedData"]),
        #
        'QueryActCtxW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "hActCtx", "pvSubInstance", "ulInfoClass", "pvBuffer", "cbBuffer", "pcbWrittenOrRequired"]),
        #
        'QueryActCtxSettingsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "hActCtx", "settingsNameSpace", "settingName", "pvBuffer", "dwBuffer", "pdwWrittenOrRequired"]),
        #
        'AllocConsole': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'FreeConsole': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'AttachConsole': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwProcessId"]),
        #
        'GetConsoleCP': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'GetConsoleOutputCP': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'GetConsoleMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="CONSOLE_MODE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleHandle", "lpMode"]),
        #
        'SetConsoleMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CONSOLE_MODE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleHandle", "dwMode"]),
        #
        'GetNumberOfConsoleInputEvents': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleInput", "lpNumberOfEvents"]),
        #
        'ReadConsoleInputA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("INPUT_RECORD", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleInput", "lpBuffer", "nLength", "lpNumberOfEventsRead"]),
        #
        'ReadConsoleInputW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("INPUT_RECORD", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleInput", "lpBuffer", "nLength", "lpNumberOfEventsRead"]),
        #
        'PeekConsoleInputA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("INPUT_RECORD", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleInput", "lpBuffer", "nLength", "lpNumberOfEventsRead"]),
        #
        'PeekConsoleInputW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("INPUT_RECORD", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleInput", "lpBuffer", "nLength", "lpNumberOfEventsRead"]),
        #
        'ReadConsoleA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("CONSOLE_READCONSOLE_CONTROL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleInput", "lpBuffer", "nNumberOfCharsToRead", "lpNumberOfCharsRead", "pInputControl"]),
        #
        'ReadConsoleW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("CONSOLE_READCONSOLE_CONTROL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleInput", "lpBuffer", "nNumberOfCharsToRead", "lpNumberOfCharsRead", "pInputControl"]),
        #
        'WriteConsoleA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpBuffer", "nNumberOfCharsToWrite", "lpNumberOfCharsWritten", "lpReserved"]),
        #
        'WriteConsoleW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpBuffer", "nNumberOfCharsToWrite", "lpNumberOfCharsWritten", "lpReserved"]),
        #
        'SetConsoleCtrlHandler': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CtrlType"]), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["HandlerRoutine", "Add"]),
        #
        'CreatePseudoConsole': SimTypeFunction([SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["size", "hInput", "hOutput", "dwFlags", "phPC"]),
        #
        'ResizePseudoConsole': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("COORD", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPC", "size"]),
        #
        'ClosePseudoConsole': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hPC"]),
        #
        'FillConsoleOutputCharacterA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="SByte"), SimTypeInt(signed=False, label="UInt32"), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "cCharacter", "nLength", "dwWriteCoord", "lpNumberOfCharsWritten"]),
        #
        'FillConsoleOutputCharacterW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Char"), SimTypeInt(signed=False, label="UInt32"), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "cCharacter", "nLength", "dwWriteCoord", "lpNumberOfCharsWritten"]),
        #
        'FillConsoleOutputAttribute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "wAttribute", "nLength", "dwWriteCoord", "lpNumberOfAttrsWritten"]),
        #
        'GenerateConsoleCtrlEvent': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwCtrlEvent", "dwProcessGroupId"]),
        #
        'CreateConsoleScreenBuffer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "dwShareMode", "lpSecurityAttributes", "dwFlags", "lpScreenBufferData"]),
        #
        'SetConsoleActiveScreenBuffer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput"]),
        #
        'FlushConsoleInputBuffer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleInput"]),
        #
        'SetConsoleCP': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["wCodePageID"]),
        #
        'SetConsoleOutputCP': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["wCodePageID"]),
        #
        'GetConsoleCursorInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CONSOLE_CURSOR_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpConsoleCursorInfo"]),
        #
        'SetConsoleCursorInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CONSOLE_CURSOR_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpConsoleCursorInfo"]),
        #
        'GetConsoleScreenBufferInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CONSOLE_SCREEN_BUFFER_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpConsoleScreenBufferInfo"]),
        #
        'GetConsoleScreenBufferInfoEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CONSOLE_SCREEN_BUFFER_INFOEX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpConsoleScreenBufferInfoEx"]),
        #
        'SetConsoleScreenBufferInfoEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CONSOLE_SCREEN_BUFFER_INFOEX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpConsoleScreenBufferInfoEx"]),
        #
        'SetConsoleScreenBufferSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("COORD", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "dwSize"]),
        #
        'SetConsoleCursorPosition': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("COORD", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "dwCursorPosition"]),
        #
        'GetLargestConsoleWindowSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeRef("COORD", SimStruct), arg_names=["hConsoleOutput"]),
        #
        'SetConsoleTextAttribute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CONSOLE_CHARACTER_ATTRIBUTES")], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "wAttributes"]),
        #
        'SetConsoleWindowInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SMALL_RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "bAbsolute", "lpConsoleWindow"]),
        #
        'WriteConsoleOutputCharacterA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpCharacter", "nLength", "dwWriteCoord", "lpNumberOfCharsWritten"]),
        #
        'WriteConsoleOutputCharacterW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpCharacter", "nLength", "dwWriteCoord", "lpNumberOfCharsWritten"]),
        #
        'WriteConsoleOutputAttribute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpAttribute", "nLength", "dwWriteCoord", "lpNumberOfAttrsWritten"]),
        #
        'ReadConsoleOutputCharacterA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpCharacter", "nLength", "dwReadCoord", "lpNumberOfCharsRead"]),
        #
        'ReadConsoleOutputCharacterW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpCharacter", "nLength", "dwReadCoord", "lpNumberOfCharsRead"]),
        #
        'ReadConsoleOutputAttribute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpAttribute", "nLength", "dwReadCoord", "lpNumberOfAttrsRead"]),
        #
        'WriteConsoleInputA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("INPUT_RECORD", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleInput", "lpBuffer", "nLength", "lpNumberOfEventsWritten"]),
        #
        'WriteConsoleInputW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("INPUT_RECORD", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleInput", "lpBuffer", "nLength", "lpNumberOfEventsWritten"]),
        #
        'ScrollConsoleScreenBufferA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SMALL_RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SMALL_RECT", SimStruct), offset=0), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeRef("CHAR_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpScrollRectangle", "lpClipRectangle", "dwDestinationOrigin", "lpFill"]),
        #
        'ScrollConsoleScreenBufferW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SMALL_RECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SMALL_RECT", SimStruct), offset=0), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeRef("CHAR_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpScrollRectangle", "lpClipRectangle", "dwDestinationOrigin", "lpFill"]),
        #
        'WriteConsoleOutputA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CHAR_INFO", SimStruct), offset=0), SimTypeRef("COORD", SimStruct), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeRef("SMALL_RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpBuffer", "dwBufferSize", "dwBufferCoord", "lpWriteRegion"]),
        #
        'WriteConsoleOutputW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CHAR_INFO", SimStruct), offset=0), SimTypeRef("COORD", SimStruct), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeRef("SMALL_RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpBuffer", "dwBufferSize", "dwBufferCoord", "lpWriteRegion"]),
        #
        'ReadConsoleOutputA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CHAR_INFO", SimStruct), offset=0), SimTypeRef("COORD", SimStruct), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeRef("SMALL_RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpBuffer", "dwBufferSize", "dwBufferCoord", "lpReadRegion"]),
        #
        'ReadConsoleOutputW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CHAR_INFO", SimStruct), offset=0), SimTypeRef("COORD", SimStruct), SimTypeRef("COORD", SimStruct), SimTypePointer(SimTypeRef("SMALL_RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "lpBuffer", "dwBufferSize", "dwBufferCoord", "lpReadRegion"]),
        #
        'GetConsoleTitleA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpConsoleTitle", "nSize"]),
        #
        'GetConsoleTitleW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpConsoleTitle", "nSize"]),
        #
        'GetConsoleOriginalTitleA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpConsoleTitle", "nSize"]),
        #
        'GetConsoleOriginalTitleW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpConsoleTitle", "nSize"]),
        #
        'SetConsoleTitleA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpConsoleTitle"]),
        #
        'SetConsoleTitleW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpConsoleTitle"]),
        #
        'GetNumberOfConsoleMouseButtons': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpNumberOfMouseButtons"]),
        #
        'GetConsoleFontSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeRef("COORD", SimStruct), arg_names=["hConsoleOutput", "nFont"]),
        #
        'GetCurrentConsoleFont': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("CONSOLE_FONT_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "bMaximumWindow", "lpConsoleCurrentFont"]),
        #
        'GetCurrentConsoleFontEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("CONSOLE_FONT_INFOEX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "bMaximumWindow", "lpConsoleCurrentFontEx"]),
        #
        'SetCurrentConsoleFontEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("CONSOLE_FONT_INFOEX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "bMaximumWindow", "lpConsoleCurrentFontEx"]),
        #
        'GetConsoleSelectionInfo': SimTypeFunction([SimTypePointer(SimTypeRef("CONSOLE_SELECTION_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpConsoleSelectionInfo"]),
        #
        'GetConsoleHistoryInfo': SimTypeFunction([SimTypePointer(SimTypeRef("CONSOLE_HISTORY_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpConsoleHistoryInfo"]),
        #
        'SetConsoleHistoryInfo': SimTypeFunction([SimTypePointer(SimTypeRef("CONSOLE_HISTORY_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpConsoleHistoryInfo"]),
        #
        'GetConsoleDisplayMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpModeFlags"]),
        #
        'SetConsoleDisplayMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("COORD", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConsoleOutput", "dwFlags", "lpNewScreenBufferDimensions"]),
        #
        'GetConsoleWindow': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'AddConsoleAliasA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Source", "Target", "ExeName"]),
        #
        'AddConsoleAliasW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Source", "Target", "ExeName"]),
        #
        'GetConsoleAliasA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Source", "TargetBuffer", "TargetBufferLength", "ExeName"]),
        #
        'GetConsoleAliasW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Source", "TargetBuffer", "TargetBufferLength", "ExeName"]),
        #
        'GetConsoleAliasesLengthA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExeName"]),
        #
        'GetConsoleAliasesLengthW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExeName"]),
        #
        'GetConsoleAliasExesLengthA': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'GetConsoleAliasExesLengthW': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'GetConsoleAliasesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AliasBuffer", "AliasBufferLength", "ExeName"]),
        #
        'GetConsoleAliasesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AliasBuffer", "AliasBufferLength", "ExeName"]),
        #
        'GetConsoleAliasExesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExeNameBuffer", "ExeNameBufferLength"]),
        #
        'GetConsoleAliasExesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExeNameBuffer", "ExeNameBufferLength"]),
        #
        'ExpungeConsoleCommandHistoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ExeName"]),
        #
        'ExpungeConsoleCommandHistoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ExeName"]),
        #
        'SetConsoleNumberOfCommandsA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Number", "ExeName"]),
        #
        'SetConsoleNumberOfCommandsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Number", "ExeName"]),
        #
        'GetConsoleCommandHistoryLengthA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExeName"]),
        #
        'GetConsoleCommandHistoryLengthW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ExeName"]),
        #
        'GetConsoleCommandHistoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Commands", "CommandBufferLength", "ExeName"]),
        #
        'GetConsoleCommandHistoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Commands", "CommandBufferLength", "ExeName"]),
        #
        'GetConsoleProcessList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpdwProcessList", "dwProcessCount"]),
        #
        'GetStdHandle': SimTypeFunction([SimTypeInt(signed=False, label="STD_HANDLE")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["nStdHandle"]),
        #
        'SetStdHandle': SimTypeFunction([SimTypeInt(signed=False, label="STD_HANDLE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nStdHandle", "hHandle"]),
        #
        'SetStdHandleEx': SimTypeFunction([SimTypeInt(signed=False, label="STD_HANDLE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nStdHandle", "hHandle", "phPrevValue"]),
        #
        'GlobalDeleteAtom': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=False, label="UInt16"), arg_names=["nAtom"]),
        #
        'InitAtomTable': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["nSize"]),
        #
        'DeleteAtom': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=False, label="UInt16"), arg_names=["nAtom"]),
        #
        'GlobalAddAtomA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["lpString"]),
        #
        'GlobalAddAtomW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["lpString"]),
        #
        'GlobalAddAtomExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeShort(signed=False, label="UInt16"), arg_names=["lpString", "Flags"]),
        #
        'GlobalAddAtomExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeShort(signed=False, label="UInt16"), arg_names=["lpString", "Flags"]),
        #
        'GlobalFindAtomA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["lpString"]),
        #
        'GlobalFindAtomW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["lpString"]),
        #
        'GlobalGetAtomNameA': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["nAtom", "lpBuffer", "nSize"]),
        #
        'GlobalGetAtomNameW': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["nAtom", "lpBuffer", "nSize"]),
        #
        'AddAtomA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["lpString"]),
        #
        'AddAtomW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["lpString"]),
        #
        'FindAtomA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["lpString"]),
        #
        'FindAtomW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["lpString"]),
        #
        'GetAtomNameA': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["nAtom", "lpBuffer", "nSize"]),
        #
        'GetAtomNameW': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["nAtom", "lpBuffer", "nSize"]),
        #
        'CeipIsOptedIn': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'RtlAddFunctionTable': SimTypeFunction([SimTypePointer(SimTypeRef("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["FunctionTable", "EntryCount", "BaseAddress"]),
        #
        'RtlDeleteFunctionTable': SimTypeFunction([SimTypePointer(SimTypeRef("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FunctionTable"]),
        #
        'RtlInstallFunctionTableCallback': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("IMAGE_RUNTIME_FUNCTION_ENTRY", SimStruct), offset=0), arg_names=["ControlPc", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeChar(label="Byte"), arg_names=["TableIdentifier", "BaseAddress", "Length", "Callback", "Context", "OutOfProcessCallbackDll"]),
        #
        'RtlLookupFunctionEntry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UNWIND_HISTORY_TABLE", SimStruct), offset=0)], SimTypePointer(SimTypeRef("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY", SimStruct), offset=0), arg_names=["ControlPc", "ImageBase", "HistoryTable"]),
        #
        'RtlVirtualUnwind': SimTypeFunction([SimTypeInt(signed=False, label="RTL_VIRTUAL_UNWIND_HANDLER_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY", SimStruct), offset=0), SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("KNONVOLATILE_CONTEXT_POINTERS_ARM64", SimStruct), offset=0)], SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("EXCEPTION_RECORD", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="EXCEPTION_DISPOSITION"), arg_names=["ExceptionRecord", "EstablisherFrame", "ContextRecord", "DispatcherContext"]), offset=0), arg_names=["HandlerType", "ImageBase", "ControlPc", "FunctionEntry", "ContextRecord", "HandlerData", "EstablisherFrame", "ContextPointers"]),
        #
        'ReadProcessMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpBaseAddress", "lpBuffer", "nSize", "lpNumberOfBytesRead"]),
        #
        'WriteProcessMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpBaseAddress", "lpBuffer", "nSize", "lpNumberOfBytesWritten"]),
        #
        'GetThreadContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "lpContext"]),
        #
        'SetThreadContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "lpContext"]),
        #
        'FlushInstructionCache': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpBaseAddress", "dwSize"]),
        #
        'Wow64GetThreadContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("WOW64_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "lpContext"]),
        #
        'Wow64SetThreadContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("WOW64_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "lpContext"]),
        #
        'RtlCaptureContext2': SimTypeFunction([SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ContextRecord"]),
        #
        'RtlAddFunctionTable': SimTypeFunction([SimTypePointer(SimTypeRef("IMAGE_RUNTIME_FUNCTION_ENTRY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeChar(label="Byte"), arg_names=["FunctionTable", "EntryCount", "BaseAddress"]),
        #
        'RtlDeleteFunctionTable': SimTypeFunction([SimTypePointer(SimTypeRef("IMAGE_RUNTIME_FUNCTION_ENTRY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FunctionTable"]),
        #
        'RtlInstallFunctionTableCallback': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("IMAGE_RUNTIME_FUNCTION_ENTRY", SimStruct), offset=0), arg_names=["ControlPc", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeChar(label="Byte"), arg_names=["TableIdentifier", "BaseAddress", "Length", "Callback", "Context", "OutOfProcessCallbackDll"]),
        #
        'RtlLookupFunctionEntry': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeRef("UNWIND_HISTORY_TABLE", SimStruct), offset=0)], SimTypePointer(SimTypeRef("IMAGE_RUNTIME_FUNCTION_ENTRY", SimStruct), offset=0), arg_names=["ControlPc", "ImageBase", "HistoryTable"]),
        #
        'RtlUnwindEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("EXCEPTION_RECORD", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNWIND_HISTORY_TABLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["TargetFrame", "TargetIp", "ExceptionRecord", "ReturnValue", "ContextRecord", "HistoryTable"]),
        #
        'RtlVirtualUnwind': SimTypeFunction([SimTypeInt(signed=False, label="RTL_VIRTUAL_UNWIND_HANDLER_TYPE"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("IMAGE_RUNTIME_FUNCTION_ENTRY", SimStruct), offset=0), SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeRef("KNONVOLATILE_CONTEXT_POINTERS", SimStruct), offset=0)], SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("EXCEPTION_RECORD", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="EXCEPTION_DISPOSITION"), arg_names=["ExceptionRecord", "EstablisherFrame", "ContextRecord", "DispatcherContext"]), offset=0), arg_names=["HandlerType", "ImageBase", "ControlPc", "FunctionEntry", "ContextRecord", "HandlerData", "EstablisherFrame", "ContextPointers"]),
        #
        'RtlCaptureStackBackTrace': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["FramesToSkip", "FramesToCapture", "BackTrace", "BackTraceHash"]),
        #
        'RtlCaptureContext': SimTypeFunction([SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ContextRecord"]),
        #
        'RtlUnwind': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("EXCEPTION_RECORD", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["TargetFrame", "TargetIp", "ExceptionRecord", "ReturnValue"]),
        #
        'RtlRestoreContext': SimTypeFunction([SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeRef("EXCEPTION_RECORD", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ContextRecord", "ExceptionRecord"]),
        #
        'RtlRaiseException': SimTypeFunction([SimTypePointer(SimTypeRef("EXCEPTION_RECORD", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ExceptionRecord"]),
        #
        'RtlPcToFileHeader': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["PcValue", "BaseOfImage"]),
        #
        'IsDebuggerPresent': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'DebugBreak': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'OutputDebugStringA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpOutputString"]),
        #
        'OutputDebugStringW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpOutputString"]),
        #
        'ContinueDebugEvent': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwProcessId", "dwThreadId", "dwContinueStatus"]),
        #
        'WaitForDebugEvent': SimTypeFunction([SimTypePointer(SimTypeRef("DEBUG_EVENT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDebugEvent", "dwMilliseconds"]),
        #
        'DebugActiveProcess': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwProcessId"]),
        #
        'DebugActiveProcessStop': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwProcessId"]),
        #
        'CheckRemoteDebuggerPresent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "pbDebuggerPresent"]),
        #
        'WaitForDebugEventEx': SimTypeFunction([SimTypePointer(SimTypeRef("DEBUG_EVENT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpDebugEvent", "dwMilliseconds"]),
        #
        'EncodePointer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Ptr"]),
        #
        'DecodePointer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Ptr"]),
        #
        'EncodeSystemPointer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Ptr"]),
        #
        'DecodeSystemPointer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Ptr"]),
        #
        'Beep': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFreq", "dwDuration"]),
        #
        'RaiseException': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), label="LPArray", offset=0)], SimTypeBottom(label="Void"), arg_names=["dwExceptionCode", "dwExceptionFlags", "nNumberOfArguments", "lpArguments"]),
        #
        'UnhandledExceptionFilter': SimTypeFunction([SimTypePointer(SimTypeRef("EXCEPTION_POINTERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExceptionInfo"]),
        #
        'SetUnhandledExceptionFilter': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("EXCEPTION_POINTERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExceptionInfo"]), offset=0)], SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("EXCEPTION_POINTERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExceptionInfo"]), offset=0), arg_names=["lpTopLevelExceptionFilter"]),
        #
        'GetErrorMode': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'SetErrorMode': SimTypeFunction([SimTypeInt(signed=False, label="THREAD_ERROR_MODE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["uMode"]),
        #
        'AddVectoredExceptionHandler': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("EXCEPTION_POINTERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExceptionInfo"]), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["First", "Handler"]),
        #
        'RemoveVectoredExceptionHandler': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Handle"]),
        #
        'AddVectoredContinueHandler': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("EXCEPTION_POINTERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExceptionInfo"]), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["First", "Handler"]),
        #
        'RemoveVectoredContinueHandler': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Handle"]),
        #
        'RaiseFailFastException': SimTypeFunction([SimTypePointer(SimTypeRef("EXCEPTION_RECORD", SimStruct), offset=0), SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pExceptionRecord", "pContextRecord", "dwFlags"]),
        #
        'FatalAppExitA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["uAction", "lpMessageText"]),
        #
        'FatalAppExitW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["uAction", "lpMessageText"]),
        #
        'GetThreadErrorMode': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'SetThreadErrorMode': SimTypeFunction([SimTypeInt(signed=False, label="THREAD_ERROR_MODE"), SimTypePointer(SimTypeInt(signed=False, label="THREAD_ERROR_MODE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwNewMode", "lpOldMode"]),
        #
        'FatalExit': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["ExitCode"]),
        #
        'GetThreadSelectorEntry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LDT_ENTRY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "dwSelector", "lpSelectorEntry"]),
        #
        'Wow64GetThreadSelectorEntry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WOW64_LDT_ENTRY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "dwSelector", "lpSelectorEntry"]),
        #
        'DebugSetProcessKillOnExit': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["KillOnExit"]),
        #
        'DebugBreakProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Process"]),
        #
        'FormatMessageA': SimTypeFunction([SimTypeInt(signed=False, label="FORMAT_MESSAGE_OPTIONS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwFlags", "lpSource", "dwMessageId", "dwLanguageId", "lpBuffer", "nSize", "Arguments"]),
        #
        'FormatMessageW': SimTypeFunction([SimTypeInt(signed=False, label="FORMAT_MESSAGE_OPTIONS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwFlags", "lpSource", "dwMessageId", "dwLanguageId", "lpBuffer", "nSize", "Arguments"]),
        #
        'CopyContext': SimTypeFunction([SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0), SimTypeInt(signed=False, label="CONTEXT_FLAGS"), SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Destination", "ContextFlags", "Source"]),
        #
        'InitializeContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="CONTEXT_FLAGS"), SimTypePointer(SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Buffer", "ContextFlags", "Context", "ContextLength"]),
        #
        'InitializeContext2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="CONTEXT_FLAGS"), SimTypePointer(SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["Buffer", "ContextFlags", "Context", "ContextLength", "XStateCompactionMask"]),
        #
        'GetEnabledXStateFeatures': SimTypeFunction([], SimTypeLongLong(signed=False, label="UInt64")),
        #
        'GetXStateFeaturesMask': SimTypeFunction([SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Context", "FeatureMask"]),
        #
        'LocateXStateFeature': SimTypeFunction([SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Context", "FeatureId", "Length"]),
        #
        'SetXStateFeaturesMask': SimTypeFunction([SimTypePointer(SimTypeRef("CONTEXT", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["Context", "FeatureMask"]),
        #
        'PssCaptureSnapshot': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PSS_CAPTURE_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProcessHandle", "CaptureFlags", "ThreadContextFlags", "SnapshotHandle"]),
        #
        'PssFreeSnapshot': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProcessHandle", "SnapshotHandle"]),
        #
        'PssQuerySnapshot': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PSS_QUERY_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["SnapshotHandle", "InformationClass", "Buffer", "BufferLength"]),
        #
        'PssWalkSnapshot': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PSS_WALK_INFORMATION_CLASS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["SnapshotHandle", "InformationClass", "WalkMarkerHandle", "Buffer", "BufferLength"]),
        #
        'PssDuplicateSnapshot': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="PSS_DUPLICATE_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["SourceProcessHandle", "SnapshotHandle", "TargetProcessHandle", "TargetSnapshotHandle", "Flags"]),
        #
        'PssWalkMarkerCreate': SimTypeFunction([SimTypePointer(SimTypeRef("PSS_ALLOCATOR", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Allocator", "WalkMarkerHandle"]),
        #
        'PssWalkMarkerFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["WalkMarkerHandle"]),
        #
        'PssWalkMarkerGetPosition': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["WalkMarkerHandle", "Position"]),
        #
        'PssWalkMarkerSetPosition': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["WalkMarkerHandle", "Position"]),
        #
        'PssWalkMarkerSeekToBeginning': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["WalkMarkerHandle"]),
        #
        'CreateToolhelp32Snapshot': SimTypeFunction([SimTypeInt(signed=False, label="CREATE_TOOLHELP_SNAPSHOT_FLAGS"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwFlags", "th32ProcessID"]),
        #
        'Heap32ListFirst': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("HEAPLIST32", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSnapshot", "lphl"]),
        #
        'Heap32ListNext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("HEAPLIST32", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSnapshot", "lphl"]),
        #
        'Heap32First': SimTypeFunction([SimTypePointer(SimTypeRef("HEAPENTRY32", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lphe", "th32ProcessID", "th32HeapID"]),
        #
        'Heap32Next': SimTypeFunction([SimTypePointer(SimTypeRef("HEAPENTRY32", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lphe"]),
        #
        'Toolhelp32ReadProcessMemory': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["th32ProcessID", "lpBaseAddress", "lpBuffer", "cbRead", "lpNumberOfBytesRead"]),
        #
        'Process32FirstW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PROCESSENTRY32W", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSnapshot", "lppe"]),
        #
        'Process32NextW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PROCESSENTRY32W", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSnapshot", "lppe"]),
        #
        'Process32First': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PROCESSENTRY32", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSnapshot", "lppe"]),
        #
        'Process32Next': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PROCESSENTRY32", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSnapshot", "lppe"]),
        #
        'Thread32First': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("THREADENTRY32", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSnapshot", "lpte"]),
        #
        'Thread32Next': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("THREADENTRY32", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSnapshot", "lpte"]),
        #
        'Module32FirstW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MODULEENTRY32W", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSnapshot", "lpme"]),
        #
        'Module32NextW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MODULEENTRY32W", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSnapshot", "lpme"]),
        #
        'Module32First': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MODULEENTRY32", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSnapshot", "lpme"]),
        #
        'Module32Next': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MODULEENTRY32", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSnapshot", "lpme"]),
        #
        'SetEnvironmentStringsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NewEnvironment"]),
        #
        'GetCommandLineA': SimTypeFunction([], SimTypePointer(SimTypeChar(label="Byte"), offset=0)),
        #
        'GetCommandLineW': SimTypeFunction([], SimTypePointer(SimTypeChar(label="Char"), offset=0)),
        #
        'GetEnvironmentStrings': SimTypeFunction([], SimTypePointer(SimTypeChar(label="Byte"), offset=0)),
        #
        'GetEnvironmentStringsW': SimTypeFunction([], SimTypePointer(SimTypeChar(label="Char"), offset=0)),
        #
        'FreeEnvironmentStringsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["penv"]),
        #
        'FreeEnvironmentStringsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["penv"]),
        #
        'GetEnvironmentVariableA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpName", "lpBuffer", "nSize"]),
        #
        'GetEnvironmentVariableW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpName", "lpBuffer", "nSize"]),
        #
        'SetEnvironmentVariableA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpName", "lpValue"]),
        #
        'SetEnvironmentVariableW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpName", "lpValue"]),
        #
        'ExpandEnvironmentStringsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpSrc", "lpDst", "nSize"]),
        #
        'ExpandEnvironmentStringsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpSrc", "lpDst", "nSize"]),
        #
        'SetCurrentDirectoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName"]),
        #
        'SetCurrentDirectoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName"]),
        #
        'GetCurrentDirectoryA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["nBufferLength", "lpBuffer"]),
        #
        'GetCurrentDirectoryW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["nBufferLength", "lpBuffer"]),
        #
        'NeedCurrentDirectoryForExePathA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExeName"]),
        #
        'NeedCurrentDirectoryForExePathW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExeName"]),
        #
        'IsEnclaveTypeSupported': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["flEnclaveType"]),
        #
        'CreateEnclave': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hProcess", "lpAddress", "dwSize", "dwInitialCommitment", "flEnclaveType", "lpEnclaveInformation", "dwInfoLength", "lpEnclaveError"]),
        #
        'LoadEnclaveData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpAddress", "lpBuffer", "nSize", "flProtect", "lpPageInformation", "dwInfoLength", "lpNumberOfBytesWritten", "lpEnclaveError"]),
        #
        'InitializeEnclave': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpAddress", "lpEnclaveInformation", "dwInfoLength", "lpEnclaveError"]),
        #
        'WerRegisterFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="WER_REGISTER_FILE_TYPE"), SimTypeInt(signed=False, label="WER_FILE")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzFile", "regFileType", "dwFlags"]),
        #
        'WerUnregisterFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzFilePath"]),
        #
        'WerRegisterMemoryBlock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pvAddress", "dwSize"]),
        #
        'WerUnregisterMemoryBlock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvAddress"]),
        #
        'WerRegisterExcludedMemoryBlock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["address", "size"]),
        #
        'WerUnregisterExcludedMemoryBlock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["address"]),
        #
        'WerRegisterCustomMetadata': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["key", "value"]),
        #
        'WerUnregisterCustomMetadata': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["key"]),
        #
        'WerRegisterAdditionalProcess': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["processId", "captureExtraInfoForThreadId"]),
        #
        'WerUnregisterAdditionalProcess': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["processId"]),
        #
        'WerRegisterAppLocalDump': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["localAppDataRelativePath"]),
        #
        'WerUnregisterAppLocalDump': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'WerSetFlags': SimTypeFunction([SimTypeInt(signed=False, label="WER_FAULT_REPORTING")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags"]),
        #
        'WerGetFlags': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="WER_FAULT_REPORTING"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "pdwFlags"]),
        #
        'WerRegisterRuntimeExceptionModule': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszOutOfProcessCallbackDll", "pContext"]),
        #
        'WerUnregisterRuntimeExceptionModule': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszOutOfProcessCallbackDll", "pContext"]),
        #
        'CreateIoCompletionPort': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["FileHandle", "ExistingCompletionPort", "CompletionKey", "NumberOfConcurrentThreads"]),
        #
        'GetQueuedCompletionStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CompletionPort", "lpNumberOfBytesTransferred", "lpCompletionKey", "lpOverlapped", "dwMilliseconds"]),
        #
        'GetQueuedCompletionStatusEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED_ENTRY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CompletionPort", "lpCompletionPortEntries", "ulCount", "ulNumEntriesRemoved", "dwMilliseconds", "fAlertable"]),
        #
        'PostQueuedCompletionStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompletionPort", "dwNumberOfBytesTransferred", "dwCompletionKey", "lpOverlapped"]),
        #
        'DeviceIoControl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice", "dwIoControlCode", "lpInBuffer", "nInBufferSize", "lpOutBuffer", "nOutBufferSize", "lpBytesReturned", "lpOverlapped"]),
        #
        'GetOverlappedResult': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpOverlapped", "lpNumberOfBytesTransferred", "bWait"]),
        #
        'CancelIoEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpOverlapped"]),
        #
        'CancelIo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile"]),
        #
        'GetOverlappedResultEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpOverlapped", "lpNumberOfBytesTransferred", "dwMilliseconds", "bAlertable"]),
        #
        'CancelSynchronousIo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread"]),
        #
        'BindIoCompletionCallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwErrorCode", "dwNumberOfBytesTransfered", "lpOverlapped"]), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Function", "Flags"]),
        #
        'IsProcessInJob': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "JobHandle", "Result"]),
        #
        'CreateJobObjectW': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpJobAttributes", "lpName"]),
        #
        'FreeMemoryJobObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Buffer"]),
        #
        'OpenJobObjectW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "lpName"]),
        #
        'AssignProcessToJobObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hJob", "hProcess"]),
        #
        'TerminateJobObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hJob", "uExitCode"]),
        #
        'SetInformationJobObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="JOBOBJECTINFOCLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hJob", "JobObjectInformationClass", "lpJobObjectInformation", "cbJobObjectInformationLength"]),
        #
        'SetIoRateControlInformationJobObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("JOBOBJECT_IO_RATE_CONTROL_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hJob", "IoRateControlInfo"]),
        #
        'QueryInformationJobObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="JOBOBJECTINFOCLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hJob", "JobObjectInformationClass", "lpJobObjectInformation", "cbJobObjectInformationLength", "lpReturnLength"]),
        #
        'QueryIoRateControlInformationJobObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("JOBOBJECT_IO_RATE_CONTROL_INFORMATION", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hJob", "VolumeName", "InfoBlocks", "InfoBlockCount"]),
        #
        'CreateJobObjectA': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpJobAttributes", "lpName"]),
        #
        'OpenJobObjectA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "lpName"]),
        #
        'CreateJobSet': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("JOB_SET_ARRAY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["NumJob", "UserJobSet", "Flags"]),
        #
        'DisableThreadLibraryCalls': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLibModule"]),
        #
        'FindResourceExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hModule", "lpType", "lpName", "wLanguage"]),
        #
        'FreeLibraryAndExitThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["hLibModule", "dwExitCode"]),
        #
        'FreeResource': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hResData"]),
        #
        'GetModuleFileNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hModule", "lpFilename", "nSize"]),
        #
        'GetModuleFileNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hModule", "lpFilename", "nSize"]),
        #
        'GetModuleHandleA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpModuleName"]),
        #
        'GetModuleHandleW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpModuleName"]),
        #
        'GetModuleHandleExA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "lpModuleName", "phModule"]),
        #
        'GetModuleHandleExW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "lpModuleName", "phModule"]),
        #
        'GetProcAddress': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)), offset=0), arg_names=["hModule", "lpProcName"]),
        #
        'LoadLibraryExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="LOAD_LIBRARY_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpLibFileName", "hFile", "dwFlags"]),
        #
        'LoadLibraryExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="LOAD_LIBRARY_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpLibFileName", "hFile", "dwFlags"]),
        #
        'LoadResource': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hModule", "hResInfo"]),
        #
        'LockResource': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hResData"]),
        #
        'SizeofResource': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hModule", "hResInfo"]),
        #
        'AddDllDirectory': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["NewDirectory"]),
        #
        'RemoveDllDirectory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Cookie"]),
        #
        'SetDefaultDllDirectories': SimTypeFunction([SimTypeInt(signed=False, label="LOAD_LIBRARY_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["DirectoryFlags"]),
        #
        'EnumResourceLanguagesExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpName", "wLanguage", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpName", "lpEnumFunc", "lParam", "dwFlags", "LangId"]),
        #
        'EnumResourceLanguagesExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpName", "wLanguage", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpName", "lpEnumFunc", "lParam", "dwFlags", "LangId"]),
        #
        'EnumResourceNamesExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpName", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpEnumFunc", "lParam", "dwFlags", "LangId"]),
        #
        'EnumResourceNamesExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpName", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpEnumFunc", "lParam", "dwFlags", "LangId"]),
        #
        'EnumResourceTypesExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpEnumFunc", "lParam", "dwFlags", "LangId"]),
        #
        'EnumResourceTypesExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpEnumFunc", "lParam", "dwFlags", "LangId"]),
        #
        'FindResourceW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hModule", "lpName", "lpType"]),
        #
        'LoadLibraryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpLibFileName"]),
        #
        'LoadLibraryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpLibFileName"]),
        #
        'EnumResourceNamesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpName", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpEnumFunc", "lParam"]),
        #
        'EnumResourceNamesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpName", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpEnumFunc", "lParam"]),
        #
        'LoadModule': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpModuleName", "lpParameterBlock"]),
        #
        'LoadPackagedLibrary': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpwLibFileName", "Reserved"]),
        #
        'FindResourceA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hModule", "lpName", "lpType"]),
        #
        'FindResourceExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hModule", "lpType", "lpName", "wLanguage"]),
        #
        'EnumResourceTypesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpEnumFunc", "lParam"]),
        #
        'EnumResourceTypesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpEnumFunc", "lParam"]),
        #
        'EnumResourceLanguagesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpName", "wLanguage", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpName", "lpEnumFunc", "lParam"]),
        #
        'EnumResourceLanguagesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpName", "wLanguage", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hModule", "lpType", "lpName", "lpEnumFunc", "lParam"]),
        #
        'BeginUpdateResourceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pFileName", "bDeleteExistingResources"]),
        #
        'BeginUpdateResourceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pFileName", "bDeleteExistingResources"]),
        #
        'UpdateResourceA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUpdate", "lpType", "lpName", "wLanguage", "lpData", "cb"]),
        #
        'UpdateResourceW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUpdate", "lpType", "lpName", "wLanguage", "lpData", "cb"]),
        #
        'EndUpdateResourceA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUpdate", "fDiscard"]),
        #
        'EndUpdateResourceW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUpdate", "fDiscard"]),
        #
        'SetDllDirectoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName"]),
        #
        'SetDllDirectoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName"]),
        #
        'GetDllDirectoryA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["nBufferLength", "lpBuffer"]),
        #
        'GetDllDirectoryW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["nBufferLength", "lpBuffer"]),
        #
        'CreateMailslotA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpName", "nMaxMessageSize", "lReadTimeout", "lpSecurityAttributes"]),
        #
        'CreateMailslotW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpName", "nMaxMessageSize", "lReadTimeout", "lpSecurityAttributes"]),
        #
        'GetMailslotInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMailslot", "lpMaxMessageSize", "lpNextSize", "lpMessageCount", "lpReadTimeout"]),
        #
        'SetMailslotInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMailslot", "lReadTimeout"]),
        #
        'HeapCreate': SimTypeFunction([SimTypeInt(signed=False, label="HEAP_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["flOptions", "dwInitialSize", "dwMaximumSize"]),
        #
        'HeapDestroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hHeap"]),
        #
        'HeapAlloc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HEAP_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hHeap", "dwFlags", "dwBytes"]),
        #
        'HeapReAlloc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HEAP_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hHeap", "dwFlags", "lpMem", "dwBytes"]),
        #
        'HeapFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HEAP_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hHeap", "dwFlags", "lpMem"]),
        #
        'HeapSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HEAP_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hHeap", "dwFlags", "lpMem"]),
        #
        'GetProcessHeap': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'HeapCompact': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HEAP_FLAGS")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hHeap", "dwFlags"]),
        #
        'HeapSetInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HEAP_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["HeapHandle", "HeapInformationClass", "HeapInformation", "HeapInformationLength"]),
        #
        'HeapValidate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HEAP_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hHeap", "dwFlags", "lpMem"]),
        #
        'HeapSummary': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("HEAP_SUMMARY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hHeap", "dwFlags", "lpSummary"]),
        #
        'GetProcessHeaps': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["NumberOfHeaps", "ProcessHeaps"]),
        #
        'HeapLock': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hHeap"]),
        #
        'HeapUnlock': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hHeap"]),
        #
        'HeapWalk': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PROCESS_HEAP_ENTRY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hHeap", "lpEntry"]),
        #
        'HeapQueryInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HEAP_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["HeapHandle", "HeapInformationClass", "HeapInformation", "HeapInformationLength", "ReturnLength"]),
        #
        'VirtualAlloc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="VIRTUAL_ALLOCATION_TYPE"), SimTypeInt(signed=False, label="PAGE_PROTECTION_FLAGS")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["lpAddress", "dwSize", "flAllocationType", "flProtect"]),
        #
        'VirtualProtect': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="PAGE_PROTECTION_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="PAGE_PROTECTION_FLAGS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"]),
        #
        'VirtualFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="VIRTUAL_FREE_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAddress", "dwSize", "dwFreeType"]),
        #
        'VirtualQuery': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MEMORY_BASIC_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["lpAddress", "lpBuffer", "dwLength"]),
        #
        'VirtualAllocEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="VIRTUAL_ALLOCATION_TYPE"), SimTypeInt(signed=False, label="PAGE_PROTECTION_FLAGS")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hProcess", "lpAddress", "dwSize", "flAllocationType", "flProtect"]),
        #
        'VirtualProtectEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="PAGE_PROTECTION_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="PAGE_PROTECTION_FLAGS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"]),
        #
        'VirtualQueryEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MEMORY_BASIC_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hProcess", "lpAddress", "lpBuffer", "dwLength"]),
        #
        'CreateFileMappingW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="PAGE_PROTECTION_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hFile", "lpFileMappingAttributes", "flProtect", "dwMaximumSizeHigh", "dwMaximumSizeLow", "lpName"]),
        #
        'OpenFileMappingW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "lpName"]),
        #
        'MapViewOfFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="FILE_MAP"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeRef("MEMORY_MAPPED_VIEW_ADDRESS", SimStruct), arg_names=["hFileMappingObject", "dwDesiredAccess", "dwFileOffsetHigh", "dwFileOffsetLow", "dwNumberOfBytesToMap"]),
        #
        'MapViewOfFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="FILE_MAP"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeRef("MEMORY_MAPPED_VIEW_ADDRESS", SimStruct), arg_names=["hFileMappingObject", "dwDesiredAccess", "dwFileOffsetHigh", "dwFileOffsetLow", "dwNumberOfBytesToMap", "lpBaseAddress"]),
        #
        'VirtualFreeEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="VIRTUAL_FREE_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpAddress", "dwSize", "dwFreeType"]),
        #
        'FlushViewOfFile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpBaseAddress", "dwNumberOfBytesToFlush"]),
        #
        'UnmapViewOfFile': SimTypeFunction([SimTypeRef("MEMORY_MAPPED_VIEW_ADDRESS", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpBaseAddress"]),
        #
        'GetLargePageMinimum': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)),
        #
        'GetProcessWorkingSetSizeEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpMinimumWorkingSetSize", "lpMaximumWorkingSetSize", "Flags"]),
        #
        'SetProcessWorkingSetSizeEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="SETPROCESSWORKINGSETSIZEEX_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "dwMinimumWorkingSetSize", "dwMaximumWorkingSetSize", "Flags"]),
        #
        'VirtualLock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAddress", "dwSize"]),
        #
        'VirtualUnlock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAddress", "dwSize"]),
        #
        'GetWriteWatch': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwFlags", "lpBaseAddress", "dwRegionSize", "lpAddresses", "lpdwCount", "lpdwGranularity"]),
        #
        'ResetWriteWatch': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBaseAddress", "dwRegionSize"]),
        #
        'CreateMemoryResourceNotification': SimTypeFunction([SimTypeInt(signed=False, label="MEMORY_RESOURCE_NOTIFICATION_TYPE")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["NotificationType"]),
        #
        'QueryMemoryResourceNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceNotificationHandle", "ResourceState"]),
        #
        'GetSystemFileCacheSize': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMinimumFileCacheSize", "lpMaximumFileCacheSize", "lpFlags"]),
        #
        'SetSystemFileCacheSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["MinimumFileCacheSize", "MaximumFileCacheSize", "Flags"]),
        #
        'CreateFileMappingNumaW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="PAGE_PROTECTION_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hFile", "lpFileMappingAttributes", "flProtect", "dwMaximumSizeHigh", "dwMaximumSizeLow", "lpName", "nndPreferred"]),
        #
        'PrefetchVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("WIN32_MEMORY_RANGE_ENTRY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "NumberOfEntries", "VirtualAddresses", "Flags"]),
        #
        'CreateFileMappingFromApp': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="PAGE_PROTECTION_FLAGS"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hFile", "SecurityAttributes", "PageProtection", "MaximumSize", "Name"]),
        #
        'MapViewOfFileFromApp': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="FILE_MAP"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeRef("MEMORY_MAPPED_VIEW_ADDRESS", SimStruct), arg_names=["hFileMappingObject", "DesiredAccess", "FileOffset", "NumberOfBytesToMap"]),
        #
        'UnmapViewOfFileEx': SimTypeFunction([SimTypeRef("MEMORY_MAPPED_VIEW_ADDRESS", SimStruct), SimTypeInt(signed=False, label="UNMAP_VIEW_OF_FILE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["BaseAddress", "UnmapFlags"]),
        #
        'AllocateUserPhysicalPages': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "NumberOfPages", "PageArray"]),
        #
        'FreeUserPhysicalPages': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "NumberOfPages", "PageArray"]),
        #
        'MapUserPhysicalPages': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VirtualAddress", "NumberOfPages", "PageArray"]),
        #
        'AllocateUserPhysicalPagesNuma': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "NumberOfPages", "PageArray", "nndPreferred"]),
        #
        'VirtualAllocExNuma': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="VIRTUAL_ALLOCATION_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hProcess", "lpAddress", "dwSize", "flAllocationType", "flProtect", "nndPreferred"]),
        #
        'GetMemoryErrorHandlingCapabilities': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Capabilities"]),
        #
        'RegisterBadMemoryNotification': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Callback"]),
        #
        'UnregisterBadMemoryNotification': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RegistrationHandle"]),
        #
        'OfferVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="OFFER_PRIORITY")], SimTypeInt(signed=False, label="UInt32"), arg_names=["VirtualAddress", "Size", "Priority"]),
        #
        'ReclaimVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["VirtualAddress", "Size"]),
        #
        'DiscardVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["VirtualAddress", "Size"]),
        #
        'RtlCompareMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["Source1", "Source2", "Length"]),
        #
        'GlobalAlloc': SimTypeFunction([SimTypeInt(signed=False, label="GLOBAL_ALLOC_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["uFlags", "dwBytes"]),
        #
        'GlobalReAlloc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hMem", "dwBytes", "uFlags"]),
        #
        'GlobalSize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hMem"]),
        #
        'GlobalUnlock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMem"]),
        #
        'GlobalLock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hMem"]),
        #
        'GlobalFlags': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hMem"]),
        #
        'GlobalHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pMem"]),
        #
        'LocalAlloc': SimTypeFunction([SimTypeInt(signed=False, label="LOCAL_ALLOC_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["uFlags", "uBytes"]),
        #
        'LocalReAlloc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hMem", "uBytes", "uFlags"]),
        #
        'LocalLock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hMem"]),
        #
        'LocalHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pMem"]),
        #
        'LocalUnlock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMem"]),
        #
        'LocalSize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hMem"]),
        #
        'LocalFlags': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hMem"]),
        #
        'CreateFileMappingA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="PAGE_PROTECTION_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hFile", "lpFileMappingAttributes", "flProtect", "dwMaximumSizeHigh", "dwMaximumSizeLow", "lpName"]),
        #
        'CreateFileMappingNumaA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="PAGE_PROTECTION_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hFile", "lpFileMappingAttributes", "flProtect", "dwMaximumSizeHigh", "dwMaximumSizeLow", "lpName", "nndPreferred"]),
        #
        'OpenFileMappingA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "lpName"]),
        #
        'MapViewOfFileExNuma': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="FILE_MAP"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeRef("MEMORY_MAPPED_VIEW_ADDRESS", SimStruct), arg_names=["hFileMappingObject", "dwDesiredAccess", "dwFileOffsetHigh", "dwFileOffsetLow", "dwNumberOfBytesToMap", "lpBaseAddress", "nndPreferred"]),
        #
        'IsBadReadPtr': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lp", "ucb"]),
        #
        'IsBadWritePtr': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lp", "ucb"]),
        #
        'IsBadCodePtr': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpfn"]),
        #
        'IsBadStringPtrA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpsz", "ucchMax"]),
        #
        'IsBadStringPtrW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpsz", "ucchMax"]),
        #
        'MapUserPhysicalPagesScatter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VirtualAddresses", "NumberOfPages", "PageArray"]),
        #
        'AddSecureMemoryCacheCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["Addr", "Range"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfnCallBack"]),
        #
        'RemoveSecureMemoryCacheCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["Addr", "Range"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfnCallBack"]),
        #
        'EnableThreadProfiling': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ThreadHandle", "Flags", "HardwareCounters", "PerformanceDataHandle"]),
        #
        'DisableThreadProfiling': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PerformanceDataHandle"]),
        #
        'QueryThreadProfiling': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ThreadHandle", "Enabled"]),
        #
        'ReadThreadProfilingData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PERFORMANCE_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PerformanceDataHandle", "Flags", "PerformanceData"]),
        #
        'QueryPerformanceCounter': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPerformanceCount"]),
        #
        'QueryPerformanceFrequency': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFrequency"]),
        #
        'CreatePipe': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hReadPipe", "hWritePipe", "lpPipeAttributes", "nSize"]),
        #
        'ConnectNamedPipe': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hNamedPipe", "lpOverlapped"]),
        #
        'DisconnectNamedPipe': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hNamedPipe"]),
        #
        'SetNamedPipeHandleState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="NAMED_PIPE_MODE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hNamedPipe", "lpMode", "lpMaxCollectionCount", "lpCollectDataTimeout"]),
        #
        'PeekNamedPipe': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hNamedPipe", "lpBuffer", "nBufferSize", "lpBytesRead", "lpTotalBytesAvail", "lpBytesLeftThisMessage"]),
        #
        'TransactNamedPipe': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hNamedPipe", "lpInBuffer", "nInBufferSize", "lpOutBuffer", "nOutBufferSize", "lpBytesRead", "lpOverlapped"]),
        #
        'CreateNamedPipeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES"), SimTypeInt(signed=False, label="NAMED_PIPE_MODE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpName", "dwOpenMode", "dwPipeMode", "nMaxInstances", "nOutBufferSize", "nInBufferSize", "nDefaultTimeOut", "lpSecurityAttributes"]),
        #
        'WaitNamedPipeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpNamedPipeName", "nTimeOut"]),
        #
        'GetNamedPipeClientComputerNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Pipe", "ClientComputerName", "ClientComputerNameLength"]),
        #
        'GetNamedPipeInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="NAMED_PIPE_MODE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hNamedPipe", "lpFlags", "lpOutBufferSize", "lpInBufferSize", "lpMaxInstances"]),
        #
        'GetNamedPipeHandleStateW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="NAMED_PIPE_MODE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hNamedPipe", "lpState", "lpCurInstances", "lpMaxCollectionCount", "lpCollectDataTimeout", "lpUserName", "nMaxUserNameSize"]),
        #
        'CallNamedPipeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpNamedPipeName", "lpInBuffer", "nInBufferSize", "lpOutBuffer", "nOutBufferSize", "lpBytesRead", "nTimeOut"]),
        #
        'CreateNamedPipeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES"), SimTypeInt(signed=False, label="NAMED_PIPE_MODE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpName", "dwOpenMode", "dwPipeMode", "nMaxInstances", "nOutBufferSize", "nInBufferSize", "nDefaultTimeOut", "lpSecurityAttributes"]),
        #
        'GetNamedPipeHandleStateA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="NAMED_PIPE_MODE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hNamedPipe", "lpState", "lpCurInstances", "lpMaxCollectionCount", "lpCollectDataTimeout", "lpUserName", "nMaxUserNameSize"]),
        #
        'CallNamedPipeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpNamedPipeName", "lpInBuffer", "nInBufferSize", "lpOutBuffer", "nOutBufferSize", "lpBytesRead", "nTimeOut"]),
        #
        'WaitNamedPipeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpNamedPipeName", "nTimeOut"]),
        #
        'GetNamedPipeClientComputerNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Pipe", "ClientComputerName", "ClientComputerNameLength"]),
        #
        'GetNamedPipeClientProcessId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Pipe", "ClientProcessId"]),
        #
        'GetNamedPipeClientSessionId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Pipe", "ClientSessionId"]),
        #
        'GetNamedPipeServerProcessId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Pipe", "ServerProcessId"]),
        #
        'GetNamedPipeServerSessionId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Pipe", "ServerSessionId"]),
        #
        'RequestWakeupLatency': SimTypeFunction([SimTypeInt(signed=False, label="LATENCY_TIME")], SimTypeInt(signed=True, label="Int32"), arg_names=["latency"]),
        #
        'IsSystemResumeAutomatic': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'SetThreadExecutionState': SimTypeFunction([SimTypeInt(signed=False, label="EXECUTION_STATE")], SimTypeInt(signed=False, label="EXECUTION_STATE"), arg_names=["esFlags"]),
        #
        'PowerCreateRequest': SimTypeFunction([SimTypePointer(SimTypeRef("REASON_CONTEXT", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Context"]),
        #
        'PowerSetRequest': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POWER_REQUEST_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["PowerRequest", "RequestType"]),
        #
        'PowerClearRequest': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POWER_REQUEST_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["PowerRequest", "RequestType"]),
        #
        'GetDevicePowerState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice", "pfOn"]),
        #
        'SetSystemPowerState': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fSuspend", "fForce"]),
        #
        'GetSystemPowerStatus': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEM_POWER_STATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemPowerStatus"]),
        #
        'K32EnumProcesses': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpidProcess", "cb", "lpcbNeeded"]),
        #
        'K32EnumProcessModules': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lphModule", "cb", "lpcbNeeded"]),
        #
        'K32EnumProcessModulesEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lphModule", "cb", "lpcbNeeded", "dwFilterFlag"]),
        #
        'K32GetModuleBaseNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProcess", "hModule", "lpBaseName", "nSize"]),
        #
        'K32GetModuleBaseNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProcess", "hModule", "lpBaseName", "nSize"]),
        #
        'K32GetModuleFileNameExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProcess", "hModule", "lpFilename", "nSize"]),
        #
        'K32GetModuleFileNameExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProcess", "hModule", "lpFilename", "nSize"]),
        #
        'K32GetModuleInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MODULEINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "hModule", "lpmodinfo", "cb"]),
        #
        'K32EmptyWorkingSet': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess"]),
        #
        'K32InitializeProcessForWsWatch': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess"]),
        #
        'K32GetWsChanges': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PSAPI_WS_WATCH_INFORMATION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpWatchInfo", "cb"]),
        #
        'K32GetWsChangesEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PSAPI_WS_WATCH_INFORMATION_EX", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpWatchInfoEx", "cb"]),
        #
        'K32GetMappedFileNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProcess", "lpv", "lpFilename", "nSize"]),
        #
        'K32GetMappedFileNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProcess", "lpv", "lpFilename", "nSize"]),
        #
        'K32EnumDeviceDrivers': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpImageBase", "cb", "lpcbNeeded"]),
        #
        'K32GetDeviceDriverBaseNameA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ImageBase", "lpFilename", "nSize"]),
        #
        'K32GetDeviceDriverBaseNameW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ImageBase", "lpBaseName", "nSize"]),
        #
        'K32GetDeviceDriverFileNameA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ImageBase", "lpFilename", "nSize"]),
        #
        'K32GetDeviceDriverFileNameW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ImageBase", "lpFilename", "nSize"]),
        #
        'K32QueryWorkingSet': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "pv", "cb"]),
        #
        'K32QueryWorkingSetEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "pv", "cb"]),
        #
        'K32GetProcessMemoryInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PROCESS_MEMORY_COUNTERS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Process", "ppsmemCounters", "cb"]),
        #
        'K32GetPerformanceInfo': SimTypeFunction([SimTypePointer(SimTypeRef("PERFORMANCE_INFORMATION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pPerformanceInformation", "cb"]),
        #
        'K32EnumPageFilesW': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ENUM_PAGE_FILE_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pContext", "pPageFileInfo", "lpFilename"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCallBackRoutine", "pContext"]),
        #
        'K32EnumPageFilesA': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ENUM_PAGE_FILE_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pContext", "pPageFileInfo", "lpFilename"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCallBackRoutine", "pContext"]),
        #
        'K32GetProcessImageFileNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProcess", "lpImageFileName", "nSize"]),
        #
        'K32GetProcessImageFileNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProcess", "lpImageFileName", "nSize"]),
        #
        'RegisterApplicationRecoveryCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pvParameter"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pRecoveyCallback", "pvParameter", "dwPingInterval", "dwFlags"]),
        #
        'UnregisterApplicationRecoveryCallback': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'RegisterApplicationRestart': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="REGISTER_APPLICATION_RESTART_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzCommandline", "dwFlags"]),
        #
        'UnregisterApplicationRestart': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'GetApplicationRecoveryCallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pvParameter"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "pRecoveryCallback", "ppvParameter", "pdwPingInterval", "pdwFlags"]),
        #
        'GetApplicationRestartSettings': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "pwzCommandline", "pcchSize", "pdwFlags"]),
        #
        'ApplicationRecoveryInProgress': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbCancelled"]),
        #
        'ApplicationRecoveryFinished': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["bSuccess"]),
        #
        'ProcessIdToSessionId': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwProcessId", "pSessionId"]),
        #
        'WTSGetActiveConsoleSessionId': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'OOBEComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["isOOBEComplete"]),
        #
        'RegisterWaitUntilOOBECompleted': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackContext"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OOBECompletedCallback", "CallbackContext", "WaitHandle"]),
        #
        'UnregisterWaitUntilOOBECompleted': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["WaitHandle"]),
        #
        'GlobalMemoryStatusEx': SimTypeFunction([SimTypePointer(SimTypeRef("MEMORYSTATUSEX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpBuffer"]),
        #
        'GetSystemInfo': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEM_INFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpSystemInfo"]),
        #
        'GetSystemTime': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpSystemTime"]),
        #
        'GetSystemTimeAsFileTime': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpSystemTimeAsFileTime"]),
        #
        'GetLocalTime': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpSystemTime"]),
        #
        'IsUserCetAvailableInEnvironment': SimTypeFunction([SimTypeInt(signed=False, label="USER_CET_ENVIRONMENT")], SimTypeInt(signed=True, label="Int32"), arg_names=["UserCetEnvironment"]),
        #
        'GetSystemLeapSecondInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enabled", "Flags"]),
        #
        'GetVersion': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'SetLocalTime': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemTime"]),
        #
        'GetTickCount': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'GetTickCount64': SimTypeFunction([], SimTypeLongLong(signed=False, label="UInt64")),
        #
        'GetSystemTimeAdjustment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTimeAdjustment", "lpTimeIncrement", "lpTimeAdjustmentDisabled"]),
        #
        'GetSystemDirectoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer", "uSize"]),
        #
        'GetSystemDirectoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer", "uSize"]),
        #
        'GetWindowsDirectoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer", "uSize"]),
        #
        'GetWindowsDirectoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer", "uSize"]),
        #
        'GetSystemWindowsDirectoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer", "uSize"]),
        #
        'GetSystemWindowsDirectoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer", "uSize"]),
        #
        'GetComputerNameExA': SimTypeFunction([SimTypeInt(signed=False, label="COMPUTER_NAME_FORMAT"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NameType", "lpBuffer", "nSize"]),
        #
        'GetComputerNameExW': SimTypeFunction([SimTypeInt(signed=False, label="COMPUTER_NAME_FORMAT"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NameType", "lpBuffer", "nSize"]),
        #
        'SetComputerNameExW': SimTypeFunction([SimTypeInt(signed=False, label="COMPUTER_NAME_FORMAT"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NameType", "lpBuffer"]),
        #
        'SetSystemTime': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemTime"]),
        #
        'GetVersionExA': SimTypeFunction([SimTypePointer(SimTypeRef("OSVERSIONINFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpVersionInformation"]),
        #
        'GetVersionExW': SimTypeFunction([SimTypePointer(SimTypeRef("OSVERSIONINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpVersionInformation"]),
        #
        'GetLogicalProcessorInformation': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEM_LOGICAL_PROCESSOR_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Buffer", "ReturnedLength"]),
        #
        'GetLogicalProcessorInformationEx': SimTypeFunction([SimTypeInt(signed=False, label="LOGICAL_PROCESSOR_RELATIONSHIP"), SimTypePointer(SimTypeRef("SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RelationshipType", "Buffer", "ReturnedLength"]),
        #
        'GetNativeSystemInfo': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEM_INFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpSystemInfo"]),
        #
        'GetSystemTimePreciseAsFileTime': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpSystemTimeAsFileTime"]),
        #
        'GetProductInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="OS_PRODUCT_TYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwOSMajorVersion", "dwOSMinorVersion", "dwSpMajorVersion", "dwSpMinorVersion", "pdwReturnedProductType"]),
        #
        'VerSetConditionMask': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="VER_FLAGS"), SimTypeChar(label="Byte")], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["ConditionMask", "TypeMask", "Condition"]),
        #
        'EnumSystemFirmwareTables': SimTypeFunction([SimTypeInt(signed=False, label="FIRMWARE_TABLE_PROVIDER"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["FirmwareTableProviderSignature", "pFirmwareTableEnumBuffer", "BufferSize"]),
        #
        'GetSystemFirmwareTable': SimTypeFunction([SimTypeInt(signed=False, label="FIRMWARE_TABLE_PROVIDER"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["FirmwareTableProviderSignature", "FirmwareTableID", "pFirmwareTableBuffer", "BufferSize"]),
        #
        'DnsHostnameToComputerNameExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Hostname", "ComputerName", "nSize"]),
        #
        'GetPhysicallyInstalledSystemMemory': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TotalMemoryInKilobytes"]),
        #
        'SetComputerNameEx2W': SimTypeFunction([SimTypeInt(signed=False, label="COMPUTER_NAME_FORMAT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NameType", "Flags", "lpBuffer"]),
        #
        'SetSystemTimeAdjustment': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTimeAdjustment", "bTimeAdjustmentDisabled"]),
        #
        'GetProcessorSystemCycleTime': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Group", "Buffer", "ReturnedLength"]),
        #
        'SetComputerNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpComputerName"]),
        #
        'SetComputerNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpComputerName"]),
        #
        'SetComputerNameExA': SimTypeFunction([SimTypeInt(signed=False, label="COMPUTER_NAME_FORMAT"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NameType", "lpBuffer"]),
        #
        'GetSystemCpuSetInformation': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEM_CPU_SET_INFORMATION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Information", "BufferLength", "ReturnedLength", "Process", "Flags"]),
        #
        'GetSystemWow64DirectoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer", "uSize"]),
        #
        'GetSystemWow64DirectoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer", "uSize"]),
        #
        'IsWow64GuestMachineSupported': SimTypeFunction([SimTypeInt(signed=False, label="IMAGE_FILE_MACHINE"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["WowGuestMachine", "MachineIsSupported"]),
        #
        'GlobalMemoryStatus': SimTypeFunction([SimTypePointer(SimTypeRef("MEMORYSTATUS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpBuffer"]),
        #
        'GetSystemDEPPolicy': SimTypeFunction([], SimTypeInt(signed=False, label="DEP_SYSTEM_POLICY_TYPE")),
        #
        'GetFirmwareType': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="FIRMWARE_TYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FirmwareType"]),
        #
        'VerifyVersionInfoA': SimTypeFunction([SimTypePointer(SimTypeRef("OSVERSIONINFOEXA", SimStruct), offset=0), SimTypeInt(signed=False, label="VER_FLAGS"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpVersionInformation", "dwTypeMask", "dwlConditionMask"]),
        #
        'VerifyVersionInfoW': SimTypeFunction([SimTypePointer(SimTypeRef("OSVERSIONINFOEXW", SimStruct), offset=0), SimTypeInt(signed=False, label="VER_FLAGS"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpVersionInformation", "dwTypeMask", "dwlConditionMask"]),
        #
        'GetProcessWorkingSetSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpMinimumWorkingSetSize", "lpMaximumWorkingSetSize"]),
        #
        'SetProcessWorkingSetSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "dwMinimumWorkingSetSize", "dwMaximumWorkingSetSize"]),
        #
        'FlsAlloc': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpFlsData"]), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpCallback"]),
        #
        'FlsGetValue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["dwFlsIndex"]),
        #
        'FlsSetValue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlsIndex", "lpFlsData"]),
        #
        'FlsFree': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlsIndex"]),
        #
        'IsThreadAFiber': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'InitializeSRWLock': SimTypeFunction([SimTypePointer(SimTypeRef("SRWLOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["SRWLock"]),
        #
        'ReleaseSRWLockExclusive': SimTypeFunction([SimTypePointer(SimTypeRef("SRWLOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["SRWLock"]),
        #
        'ReleaseSRWLockShared': SimTypeFunction([SimTypePointer(SimTypeRef("SRWLOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["SRWLock"]),
        #
        'AcquireSRWLockExclusive': SimTypeFunction([SimTypePointer(SimTypeRef("SRWLOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["SRWLock"]),
        #
        'AcquireSRWLockShared': SimTypeFunction([SimTypePointer(SimTypeRef("SRWLOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["SRWLock"]),
        #
        'TryAcquireSRWLockExclusive': SimTypeFunction([SimTypePointer(SimTypeRef("SRWLOCK", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["SRWLock"]),
        #
        'TryAcquireSRWLockShared': SimTypeFunction([SimTypePointer(SimTypeRef("SRWLOCK", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["SRWLock"]),
        #
        'InitializeCriticalSection': SimTypeFunction([SimTypePointer(SimTypeRef("CRITICAL_SECTION", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpCriticalSection"]),
        #
        'EnterCriticalSection': SimTypeFunction([SimTypePointer(SimTypeRef("CRITICAL_SECTION", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpCriticalSection"]),
        #
        'LeaveCriticalSection': SimTypeFunction([SimTypePointer(SimTypeRef("CRITICAL_SECTION", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpCriticalSection"]),
        #
        'InitializeCriticalSectionAndSpinCount': SimTypeFunction([SimTypePointer(SimTypeRef("CRITICAL_SECTION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCriticalSection", "dwSpinCount"]),
        #
        'InitializeCriticalSectionEx': SimTypeFunction([SimTypePointer(SimTypeRef("CRITICAL_SECTION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCriticalSection", "dwSpinCount", "Flags"]),
        #
        'SetCriticalSectionSpinCount': SimTypeFunction([SimTypePointer(SimTypeRef("CRITICAL_SECTION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpCriticalSection", "dwSpinCount"]),
        #
        'TryEnterCriticalSection': SimTypeFunction([SimTypePointer(SimTypeRef("CRITICAL_SECTION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCriticalSection"]),
        #
        'DeleteCriticalSection': SimTypeFunction([SimTypePointer(SimTypeRef("CRITICAL_SECTION", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpCriticalSection"]),
        #
        'InitOnceInitialize': SimTypeFunction([SimTypePointer(SimUnion({"Ptr": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), offset=0)], SimTypeBottom(label="Void"), arg_names=["InitOnce"]),
        #
        'InitOnceExecuteOnce': SimTypeFunction([SimTypePointer(SimUnion({"Ptr": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimUnion({"Ptr": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InitOnce", "Parameter", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InitOnce", "InitFn", "Parameter", "Context"]),
        #
        'InitOnceBeginInitialize': SimTypeFunction([SimTypePointer(SimUnion({"Ptr": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpInitOnce", "dwFlags", "fPending", "lpContext"]),
        #
        'InitOnceComplete': SimTypeFunction([SimTypePointer(SimUnion({"Ptr": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpInitOnce", "dwFlags", "lpContext"]),
        #
        'InitializeConditionVariable': SimTypeFunction([SimTypePointer(SimTypeRef("CONDITION_VARIABLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ConditionVariable"]),
        #
        'WakeConditionVariable': SimTypeFunction([SimTypePointer(SimTypeRef("CONDITION_VARIABLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ConditionVariable"]),
        #
        'WakeAllConditionVariable': SimTypeFunction([SimTypePointer(SimTypeRef("CONDITION_VARIABLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ConditionVariable"]),
        #
        'SleepConditionVariableCS': SimTypeFunction([SimTypePointer(SimTypeRef("CONDITION_VARIABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("CRITICAL_SECTION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ConditionVariable", "CriticalSection", "dwMilliseconds"]),
        #
        'SleepConditionVariableSRW': SimTypeFunction([SimTypePointer(SimTypeRef("CONDITION_VARIABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("SRWLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ConditionVariable", "SRWLock", "dwMilliseconds", "Flags"]),
        #
        'SetEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent"]),
        #
        'ResetEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent"]),
        #
        'ReleaseSemaphore': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSemaphore", "lReleaseCount", "lpPreviousCount"]),
        #
        'ReleaseMutex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMutex"]),
        #
        'WaitForSingleObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WAIT_EVENT"), arg_names=["hHandle", "dwMilliseconds"]),
        #
        'SleepEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwMilliseconds", "bAlertable"]),
        #
        'WaitForSingleObjectEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="WAIT_EVENT"), arg_names=["hHandle", "dwMilliseconds", "bAlertable"]),
        #
        'WaitForMultipleObjectsEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="WAIT_EVENT"), arg_names=["nCount", "lpHandles", "bWaitAll", "dwMilliseconds", "bAlertable"]),
        #
        'CreateMutexA': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpMutexAttributes", "bInitialOwner", "lpName"]),
        #
        'CreateMutexW': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpMutexAttributes", "bInitialOwner", "lpName"]),
        #
        'OpenMutexW': SimTypeFunction([SimTypeInt(signed=False, label="SYNCHRONIZATION_ACCESS_RIGHTS"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "lpName"]),
        #
        'CreateEventA': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpEventAttributes", "bManualReset", "bInitialState", "lpName"]),
        #
        'CreateEventW': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpEventAttributes", "bManualReset", "bInitialState", "lpName"]),
        #
        'OpenEventA': SimTypeFunction([SimTypeInt(signed=False, label="SYNCHRONIZATION_ACCESS_RIGHTS"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "lpName"]),
        #
        'OpenEventW': SimTypeFunction([SimTypeInt(signed=False, label="SYNCHRONIZATION_ACCESS_RIGHTS"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "lpName"]),
        #
        'OpenSemaphoreW': SimTypeFunction([SimTypeInt(signed=False, label="SYNCHRONIZATION_ACCESS_RIGHTS"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "lpName"]),
        #
        'OpenWaitableTimerW': SimTypeFunction([SimTypeInt(signed=False, label="SYNCHRONIZATION_ACCESS_RIGHTS"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "lpTimerName"]),
        #
        'SetWaitableTimerEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["lpArgToCompletionRoutine", "dwTimerLowValue", "dwTimerHighValue"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("REASON_CONTEXT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hTimer", "lpDueTime", "lPeriod", "pfnCompletionRoutine", "lpArgToCompletionRoutine", "WakeContext", "TolerableDelay"]),
        #
        'SetWaitableTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["lpArgToCompletionRoutine", "dwTimerLowValue", "dwTimerHighValue"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hTimer", "lpDueTime", "lPeriod", "pfnCompletionRoutine", "lpArgToCompletionRoutine", "fResume"]),
        #
        'CancelWaitableTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hTimer"]),
        #
        'CreateMutexExA': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpMutexAttributes", "lpName", "dwFlags", "dwDesiredAccess"]),
        #
        'CreateMutexExW': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpMutexAttributes", "lpName", "dwFlags", "dwDesiredAccess"]),
        #
        'CreateEventExA': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="CREATE_EVENT"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpEventAttributes", "lpName", "dwFlags", "dwDesiredAccess"]),
        #
        'CreateEventExW': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="CREATE_EVENT"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpEventAttributes", "lpName", "dwFlags", "dwDesiredAccess"]),
        #
        'CreateSemaphoreExW': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpSemaphoreAttributes", "lInitialCount", "lMaximumCount", "lpName", "dwFlags", "dwDesiredAccess"]),
        #
        'CreateWaitableTimerExW': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpTimerAttributes", "lpTimerName", "dwFlags", "dwDesiredAccess"]),
        #
        'EnterSynchronizationBarrier': SimTypeFunction([SimTypePointer(SimTypeRef("SYNCHRONIZATION_BARRIER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpBarrier", "dwFlags"]),
        #
        'InitializeSynchronizationBarrier': SimTypeFunction([SimTypePointer(SimTypeRef("SYNCHRONIZATION_BARRIER", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpBarrier", "lTotalThreads", "lSpinCount"]),
        #
        'DeleteSynchronizationBarrier': SimTypeFunction([SimTypePointer(SimTypeRef("SYNCHRONIZATION_BARRIER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpBarrier"]),
        #
        'Sleep': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwMilliseconds"]),
        #
        'WaitForMultipleObjects': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WAIT_EVENT"), arg_names=["nCount", "lpHandles", "bWaitAll", "dwMilliseconds"]),
        #
        'CreateSemaphoreW': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpSemaphoreAttributes", "lInitialCount", "lMaximumCount", "lpName"]),
        #
        'CreateWaitableTimerW': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpTimerAttributes", "bManualReset", "lpTimerName"]),
        #
        'InitializeSListHead': SimTypeFunction([SimTypePointer(SimUnion({"Alignment": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct(OrderedDict((("Next", SimTypeRef("SINGLE_LIST_ENTRY", SimStruct)), ("Depth", SimTypeShort(signed=False, label="UInt16")), ("CpuId", SimTypeShort(signed=False, label="UInt16")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ListHead"]),
        #
        'InterlockedPopEntrySList': SimTypeFunction([SimTypePointer(SimUnion({"Alignment": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct(OrderedDict((("Next", SimTypeRef("SINGLE_LIST_ENTRY", SimStruct)), ("Depth", SimTypeShort(signed=False, label="UInt16")), ("CpuId", SimTypeShort(signed=False, label="UInt16")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0)], SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0), arg_names=["ListHead"]),
        #
        'InterlockedPushEntrySList': SimTypeFunction([SimTypePointer(SimUnion({"Alignment": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct(OrderedDict((("Next", SimTypeRef("SINGLE_LIST_ENTRY", SimStruct)), ("Depth", SimTypeShort(signed=False, label="UInt16")), ("CpuId", SimTypeShort(signed=False, label="UInt16")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0)], SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0), arg_names=["ListHead", "ListEntry"]),
        #
        'InterlockedPushListSListEx': SimTypeFunction([SimTypePointer(SimUnion({"Alignment": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct(OrderedDict((("Next", SimTypeRef("SINGLE_LIST_ENTRY", SimStruct)), ("Depth", SimTypeShort(signed=False, label="UInt16")), ("CpuId", SimTypeShort(signed=False, label="UInt16")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0), SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0), arg_names=["ListHead", "List", "ListEnd", "Count"]),
        #
        'InterlockedFlushSList': SimTypeFunction([SimTypePointer(SimUnion({"Alignment": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct(OrderedDict((("Next", SimTypeRef("SINGLE_LIST_ENTRY", SimStruct)), ("Depth", SimTypeShort(signed=False, label="UInt16")), ("CpuId", SimTypeShort(signed=False, label="UInt16")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0)], SimTypePointer(SimTypeRef("SLIST_ENTRY", SimStruct), offset=0), arg_names=["ListHead"]),
        #
        'QueryDepthSList': SimTypeFunction([SimTypePointer(SimUnion({"Alignment": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct(OrderedDict((("Next", SimTypeRef("SINGLE_LIST_ENTRY", SimStruct)), ("Depth", SimTypeShort(signed=False, label="UInt16")), ("CpuId", SimTypeShort(signed=False, label="UInt16")),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["ListHead"]),
        #
        'QueueUserAPC': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Parameter"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pfnAPC", "hThread", "dwData"]),
        #
        'QueueUserAPC2': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Parameter"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="QUEUE_USER_APC_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["ApcRoutine", "Thread", "Data", "Flags"]),
        #
        'GetProcessTimes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpCreationTime", "lpExitTime", "lpKernelTime", "lpUserTime"]),
        #
        'GetCurrentProcess': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'GetCurrentProcessId': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'ExitProcess': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["uExitCode"]),
        #
        'TerminateProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "uExitCode"]),
        #
        'GetExitCodeProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpExitCode"]),
        #
        'SwitchToThread': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'CreateThread': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpThreadParameter"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="THREAD_CREATION_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpThreadAttributes", "dwStackSize", "lpStartAddress", "lpParameter", "dwCreationFlags", "lpThreadId"]),
        #
        'CreateRemoteThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpThreadParameter"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hProcess", "lpThreadAttributes", "dwStackSize", "lpStartAddress", "lpParameter", "dwCreationFlags", "lpThreadId"]),
        #
        'GetCurrentThread': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'GetCurrentThreadId': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'OpenThread': SimTypeFunction([SimTypeInt(signed=False, label="THREAD_ACCESS_RIGHTS"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "dwThreadId"]),
        #
        'SetThreadPriority': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="THREAD_PRIORITY")], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "nPriority"]),
        #
        'SetThreadPriorityBoost': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "bDisablePriorityBoost"]),
        #
        'GetThreadPriorityBoost': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "pDisablePriorityBoost"]),
        #
        'GetThreadPriority': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread"]),
        #
        'ExitThread': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwExitCode"]),
        #
        'TerminateThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "dwExitCode"]),
        #
        'GetExitCodeThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "lpExitCode"]),
        #
        'SuspendThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hThread"]),
        #
        'ResumeThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hThread"]),
        #
        'TlsAlloc': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'TlsGetValue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["dwTlsIndex"]),
        #
        'TlsSetValue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTlsIndex", "lpTlsValue"]),
        #
        'TlsFree': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTlsIndex"]),
        #
        'CreateProcessA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="PROCESS_CREATION_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("STARTUPINFOA", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROCESS_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpApplicationName", "lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"]),
        #
        'CreateProcessW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="PROCESS_CREATION_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("STARTUPINFOW", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROCESS_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpApplicationName", "lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"]),
        #
        'SetProcessShutdownParameters': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwLevel", "dwFlags"]),
        #
        'GetProcessVersion': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProcessId"]),
        #
        'GetStartupInfoW': SimTypeFunction([SimTypePointer(SimTypeRef("STARTUPINFOW", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpStartupInfo"]),
        #
        'SetPriorityClass': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PROCESS_CREATION_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "dwPriorityClass"]),
        #
        'GetPriorityClass': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hProcess"]),
        #
        'SetThreadStackGuarantee': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["StackSizeInBytes"]),
        #
        'GetProcessId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Process"]),
        #
        'GetThreadId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Thread"]),
        #
        'FlushProcessWriteBuffers': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'GetProcessIdOfThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Thread"]),
        #
        'InitializeProcThreadAttributeList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAttributeList", "dwAttributeCount", "dwFlags", "lpSize"]),
        #
        'DeleteProcThreadAttributeList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpAttributeList"]),
        #
        'UpdateProcThreadAttribute': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAttributeList", "dwFlags", "Attribute", "lpValue", "cbSize", "lpPreviousValue", "lpReturnSize"]),
        #
        'SetProcessDynamicEHContinuationTargets': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("PROCESS_DYNAMIC_EH_CONTINUATION_TARGET", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Process", "NumberOfTargets", "Targets"]),
        #
        'SetProcessDynamicEnforcedCetCompatibleRanges': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Process", "NumberOfRanges", "Ranges"]),
        #
        'SetProcessAffinityUpdateMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PROCESS_AFFINITY_AUTO_UPDATE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "dwFlags"]),
        #
        'QueryProcessAffinityUpdateMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="PROCESS_AFFINITY_AUTO_UPDATE_FLAGS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpdwFlags"]),
        #
        'CreateRemoteThreadEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpThreadParameter"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hProcess", "lpThreadAttributes", "dwStackSize", "lpStartAddress", "lpParameter", "dwCreationFlags", "lpAttributeList", "lpThreadId"]),
        #
        'GetCurrentThreadStackLimits': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["LowLimit", "HighLimit"]),
        #
        'GetProcessMitigationPolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PROCESS_MITIGATION_POLICY"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "MitigationPolicy", "lpBuffer", "dwLength"]),
        #
        'SetProcessMitigationPolicy': SimTypeFunction([SimTypeInt(signed=False, label="PROCESS_MITIGATION_POLICY"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MitigationPolicy", "lpBuffer", "dwLength"]),
        #
        'GetThreadTimes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "lpCreationTime", "lpExitTime", "lpKernelTime", "lpUserTime"]),
        #
        'OpenProcess': SimTypeFunction([SimTypeInt(signed=False, label="PROCESS_ACCESS_RIGHTS"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "dwProcessId"]),
        #
        'IsProcessorFeaturePresent': SimTypeFunction([SimTypeInt(signed=False, label="PROCESSOR_FEATURE_ID")], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessorFeature"]),
        #
        'GetProcessHandleCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "pdwHandleCount"]),
        #
        'GetCurrentProcessorNumber': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'SetThreadIdealProcessorEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PROCESSOR_NUMBER", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROCESSOR_NUMBER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "lpIdealProcessor", "lpPreviousIdealProcessor"]),
        #
        'GetThreadIdealProcessorEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PROCESSOR_NUMBER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "lpIdealProcessor"]),
        #
        'GetCurrentProcessorNumberEx': SimTypeFunction([SimTypePointer(SimTypeRef("PROCESSOR_NUMBER", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ProcNumber"]),
        #
        'GetProcessPriorityBoost': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "pDisablePriorityBoost"]),
        #
        'SetProcessPriorityBoost': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "bDisablePriorityBoost"]),
        #
        'GetThreadIOPendingFlag': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "lpIOIsPending"]),
        #
        'GetSystemTimes': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpIdleTime", "lpKernelTime", "lpUserTime"]),
        #
        'GetThreadInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="THREAD_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "ThreadInformationClass", "ThreadInformation", "ThreadInformationSize"]),
        #
        'SetThreadInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="THREAD_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "ThreadInformationClass", "ThreadInformation", "ThreadInformationSize"]),
        #
        'IsProcessCritical': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "Critical"]),
        #
        'SetProtectedPolicy': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyGuid", "PolicyValue", "OldPolicyValue"]),
        #
        'QueryProtectedPolicy': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PolicyGuid", "PolicyValue"]),
        #
        'SetThreadIdealProcessor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hThread", "dwIdealProcessor"]),
        #
        'SetProcessInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PROCESS_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "ProcessInformationClass", "ProcessInformation", "ProcessInformationSize"]),
        #
        'GetProcessInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PROCESS_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "ProcessInformationClass", "ProcessInformation", "ProcessInformationSize"]),
        #
        'GetProcessDefaultCpuSets': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Process", "CpuSetIds", "CpuSetIdCount", "RequiredIdCount"]),
        #
        'SetProcessDefaultCpuSets': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Process", "CpuSetIds", "CpuSetIdCount"]),
        #
        'GetThreadSelectedCpuSets': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Thread", "CpuSetIds", "CpuSetIdCount", "RequiredIdCount"]),
        #
        'SetThreadSelectedCpuSets': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Thread", "CpuSetIds", "CpuSetIdCount"]),
        #
        'GetProcessShutdownParameters': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwLevel", "lpdwFlags"]),
        #
        'GetProcessDefaultCpuSetMasks': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Process", "CpuSetMasks", "CpuSetMaskCount", "RequiredMaskCount"]),
        #
        'SetProcessDefaultCpuSetMasks': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["Process", "CpuSetMasks", "CpuSetMaskCount"]),
        #
        'GetThreadSelectedCpuSetMasks': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Thread", "CpuSetMasks", "CpuSetMaskCount", "RequiredMaskCount"]),
        #
        'SetThreadSelectedCpuSetMasks': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["Thread", "CpuSetMasks", "CpuSetMaskCount"]),
        #
        'GetMachineTypeAttributes': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=False, label="MACHINE_ATTRIBUTES"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Machine", "MachineTypeAttributes"]),
        #
        'SetThreadDescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "lpThreadDescription"]),
        #
        'GetThreadDescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "ppszThreadDescription"]),
        #
        'QueueUserWorkItem': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpThreadParameter"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="WORKER_THREAD_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["Function", "Context", "Flags"]),
        #
        'UnregisterWaitEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["WaitHandle", "CompletionEvent"]),
        #
        'CreateTimerQueue': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'CreateTimerQueueTimer': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="WORKER_THREAD_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["phNewTimer", "TimerQueue", "Callback", "Parameter", "DueTime", "Period", "Flags"]),
        #
        'ChangeTimerQueueTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TimerQueue", "Timer", "DueTime", "Period"]),
        #
        'DeleteTimerQueueTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TimerQueue", "Timer", "CompletionEvent"]),
        #
        'DeleteTimerQueue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TimerQueue"]),
        #
        'DeleteTimerQueueEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TimerQueue", "CompletionEvent"]),
        #
        'CreateThreadpool': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["reserved"]),
        #
        'SetThreadpoolThreadMaximum': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ptpp", "cthrdMost"]),
        #
        'SetThreadpoolThreadMinimum': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ptpp", "cthrdMic"]),
        #
        'SetThreadpoolStackInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TP_POOL_STACK_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ptpp", "ptpsi"]),
        #
        'QueryThreadpoolStackInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TP_POOL_STACK_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ptpp", "ptpsi"]),
        #
        'CloseThreadpool': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["ptpp"]),
        #
        'CreateThreadpoolCleanupGroup': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'CloseThreadpoolCleanupGroupMembers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ptpcg", "fCancelPendingCallbacks", "pvCleanupContext"]),
        #
        'CloseThreadpoolCleanupGroup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["ptpcg"]),
        #
        'SetEventWhenCallbackReturns': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["pci", "evt"]),
        #
        'ReleaseSemaphoreWhenCallbackReturns': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pci", "sem", "crel"]),
        #
        'ReleaseMutexWhenCallbackReturns': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["pci", "mut"]),
        #
        'LeaveCriticalSectionWhenCallbackReturns': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CRITICAL_SECTION", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pci", "pcs"]),
        #
        'FreeLibraryWhenCallbackReturns': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["pci", "mod"]),
        #
        'CallbackMayRunLong': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pci"]),
        #
        'DisassociateCurrentThreadFromCallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["pci"]),
        #
        'TrySubmitThreadpoolCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Instance", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("TP_CALLBACK_ENVIRON_V3", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfns", "pv", "pcbe"]),
        #
        'CreateThreadpoolWork': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Instance", "Context", "Work"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("TP_CALLBACK_ENVIRON_V3", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pfnwk", "pv", "pcbe"]),
        #
        'SubmitThreadpoolWork': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["pwk"]),
        #
        'WaitForThreadpoolWorkCallbacks': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pwk", "fCancelPendingCallbacks"]),
        #
        'CloseThreadpoolWork': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["pwk"]),
        #
        'CreateThreadpoolTimer': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Instance", "Context", "Timer"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("TP_CALLBACK_ENVIRON_V3", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pfnti", "pv", "pcbe"]),
        #
        'SetThreadpoolTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pti", "pftDueTime", "msPeriod", "msWindowLength"]),
        #
        'IsThreadpoolTimerSet': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pti"]),
        #
        'WaitForThreadpoolTimerCallbacks': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pti", "fCancelPendingCallbacks"]),
        #
        'CloseThreadpoolTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["pti"]),
        #
        'CreateThreadpoolWait': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Instance", "Context", "Wait", "WaitResult"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("TP_CALLBACK_ENVIRON_V3", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pfnwa", "pv", "pcbe"]),
        #
        'SetThreadpoolWait': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pwa", "h", "pftTimeout"]),
        #
        'WaitForThreadpoolWaitCallbacks': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pwa", "fCancelPendingCallbacks"]),
        #
        'CloseThreadpoolWait': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["pwa"]),
        #
        'CreateThreadpoolIo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Instance", "Context", "Overlapped", "IoResult", "NumberOfBytesTransferred", "Io"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("TP_CALLBACK_ENVIRON_V3", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["fl", "pfnio", "pv", "pcbe"]),
        #
        'StartThreadpoolIo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["pio"]),
        #
        'CancelThreadpoolIo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["pio"]),
        #
        'WaitForThreadpoolIoCallbacks': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pio", "fCancelPendingCallbacks"]),
        #
        'CloseThreadpoolIo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["pio"]),
        #
        'SetThreadpoolTimerEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pti", "pftDueTime", "msPeriod", "msWindowLength"]),
        #
        'SetThreadpoolWaitEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwa", "h", "pftTimeout", "Reserved"]),
        #
        'IsWow64Process': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "Wow64Process"]),
        #
        'IsWow64Process2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="IMAGE_FILE_MACHINE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="IMAGE_FILE_MACHINE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "pProcessMachine", "pNativeMachine"]),
        #
        'Wow64SuspendThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hThread"]),
        #
        'CreatePrivateNamespaceW': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpPrivateNamespaceAttributes", "lpBoundaryDescriptor", "lpAliasPrefix"]),
        #
        'OpenPrivateNamespaceW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpBoundaryDescriptor", "lpAliasPrefix"]),
        #
        'ClosePrivateNamespace': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["Handle", "Flags"]),
        #
        'CreateBoundaryDescriptorW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Name", "Flags"]),
        #
        'AddSIDToBoundaryDescriptor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["BoundaryDescriptor", "RequiredSid"]),
        #
        'DeleteBoundaryDescriptor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["BoundaryDescriptor"]),
        #
        'GetNumaHighestNodeNumber': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["HighestNodeNumber"]),
        #
        'GetNumaNodeProcessorMaskEx': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Node", "ProcessorMask"]),
        #
        'GetNumaNodeProcessorMask2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NodeNumber", "ProcessorMasks", "ProcessorMaskCount", "RequiredMaskCount"]),
        #
        'GetNumaProximityNodeEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProximityId", "NodeNumber"]),
        #
        'GetProcessGroupAffinity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "GroupCount", "GroupArray"]),
        #
        'GetThreadGroupAffinity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "GroupAffinity"]),
        #
        'SetThreadGroupAffinity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), offset=0), SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hThread", "GroupAffinity", "PreviousGroupAffinity"]),
        #
        'GetProcessAffinityMask': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpProcessAffinityMask", "lpSystemAffinityMask"]),
        #
        'SetProcessAffinityMask': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "dwProcessAffinityMask"]),
        #
        'GetProcessIoCounters': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_COUNTERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpIoCounters"]),
        #
        'SwitchToFiber': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpFiber"]),
        #
        'DeleteFiber': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpFiber"]),
        #
        'ConvertFiberToThread': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'CreateFiberEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpFiberParameter"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["dwStackCommitSize", "dwStackReserveSize", "dwFlags", "lpStartAddress", "lpParameter"]),
        #
        'ConvertThreadToFiberEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["lpParameter", "dwFlags"]),
        #
        'CreateFiber': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpFiberParameter"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["dwStackSize", "lpStartAddress", "lpParameter"]),
        #
        'ConvertThreadToFiber': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["lpParameter"]),
        #
        'CreateUmsCompletionList': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["UmsCompletionList"]),
        #
        'DequeueUmsCompletionListItems': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["UmsCompletionList", "WaitTimeOut", "UmsThreadList"]),
        #
        'GetUmsCompletionListEvent': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["UmsCompletionList", "UmsCompletionEvent"]),
        #
        'ExecuteUmsThread': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["UmsThread"]),
        #
        'UmsThreadYield': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SchedulerParam"]),
        #
        'DeleteUmsCompletionList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["UmsCompletionList"]),
        #
        'GetCurrentUmsThread': SimTypeFunction([], SimTypePointer(SimTypeBottom(label="Void"), offset=0)),
        #
        'GetNextUmsListItem': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["UmsContext"]),
        #
        'QueryUmsThreadInformation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UMS_THREAD_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["UmsThread", "UmsThreadInfoClass", "UmsThreadInformation", "UmsThreadInformationLength", "ReturnLength"]),
        #
        'SetUmsThreadInformation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UMS_THREAD_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["UmsThread", "UmsThreadInfoClass", "UmsThreadInformation", "UmsThreadInformationLength"]),
        #
        'DeleteUmsThreadContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["UmsThread"]),
        #
        'CreateUmsThreadContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpUmsThread"]),
        #
        'EnterUmsSchedulingMode': SimTypeFunction([SimTypePointer(SimTypeRef("UMS_SCHEDULER_STARTUP_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SchedulerStartupInfo"]),
        #
        'GetUmsSystemThreadInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UMS_SYSTEM_THREAD_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ThreadHandle", "SystemThreadInfo"]),
        #
        'SetThreadAffinityMask': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hThread", "dwThreadAffinityMask"]),
        #
        'SetProcessDEPPolicy': SimTypeFunction([SimTypeInt(signed=False, label="PROCESS_DEP_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags"]),
        #
        'GetProcessDEPPolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "lpFlags", "lpPermanent"]),
        #
        'PulseEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent"]),
        #
        'WinExec': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpCmdLine", "uCmdShow"]),
        #
        'SignalObjectAndWait': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="WAIT_EVENT"), arg_names=["hObjectToSignal", "hObjectToWaitOn", "dwMilliseconds", "bAlertable"]),
        #
        'CreateSemaphoreA': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpSemaphoreAttributes", "lInitialCount", "lMaximumCount", "lpName"]),
        #
        'CreateWaitableTimerA': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpTimerAttributes", "bManualReset", "lpTimerName"]),
        #
        'OpenWaitableTimerA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "lpTimerName"]),
        #
        'CreateSemaphoreExA': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpSemaphoreAttributes", "lInitialCount", "lMaximumCount", "lpName", "dwFlags", "dwDesiredAccess"]),
        #
        'CreateWaitableTimerExA': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpTimerAttributes", "lpTimerName", "dwFlags", "dwDesiredAccess"]),
        #
        'QueryFullProcessImageNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PROCESS_NAME_FORMAT"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "dwFlags", "lpExeName", "lpdwSize"]),
        #
        'QueryFullProcessImageNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PROCESS_NAME_FORMAT"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "dwFlags", "lpExeName", "lpdwSize"]),
        #
        'GetStartupInfoA': SimTypeFunction([SimTypePointer(SimTypeRef("STARTUPINFOA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpStartupInfo"]),
        #
        'RegisterWaitForSingleObject': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="WORKER_THREAD_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["phNewWaitObject", "hObject", "Callback", "Context", "dwMilliseconds", "dwFlags"]),
        #
        'UnregisterWait': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["WaitHandle"]),
        #
        'SetTimerQueueTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["TimerQueue", "Callback", "Parameter", "DueTime", "Period", "PreferIo"]),
        #
        'CancelTimerQueueTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TimerQueue", "Timer"]),
        #
        'CreatePrivateNamespaceA': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpPrivateNamespaceAttributes", "lpBoundaryDescriptor", "lpAliasPrefix"]),
        #
        'OpenPrivateNamespaceA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpBoundaryDescriptor", "lpAliasPrefix"]),
        #
        'CreateBoundaryDescriptorA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Name", "Flags"]),
        #
        'AddIntegrityLabelToBoundaryDescriptor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["BoundaryDescriptor", "IntegrityLabel"]),
        #
        'GetActiveProcessorGroupCount': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        #
        'GetMaximumProcessorGroupCount': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        #
        'GetActiveProcessorCount': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["GroupNumber"]),
        #
        'GetMaximumProcessorCount': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["GroupNumber"]),
        #
        'GetNumaProcessorNode': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Processor", "NodeNumber"]),
        #
        'GetNumaNodeNumberFromHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "NodeNumber"]),
        #
        'GetNumaProcessorNodeEx': SimTypeFunction([SimTypePointer(SimTypeRef("PROCESSOR_NUMBER", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Processor", "NodeNumber"]),
        #
        'GetNumaNodeProcessorMask': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Node", "ProcessorMask"]),
        #
        'GetNumaAvailableMemoryNode': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Node", "AvailableBytes"]),
        #
        'GetNumaAvailableMemoryNodeEx': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Node", "AvailableBytes"]),
        #
        'GetNumaProximityNode': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProximityId", "NodeNumber"]),
        #
        'SystemTimeToTzSpecificLocalTime': SimTypeFunction([SimTypePointer(SimTypeRef("TIME_ZONE_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTimeZoneInformation", "lpUniversalTime", "lpLocalTime"]),
        #
        'TzSpecificLocalTimeToSystemTime': SimTypeFunction([SimTypePointer(SimTypeRef("TIME_ZONE_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTimeZoneInformation", "lpLocalTime", "lpUniversalTime"]),
        #
        'FileTimeToSystemTime': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileTime", "lpSystemTime"]),
        #
        'SystemTimeToFileTime': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemTime", "lpFileTime"]),
        #
        'GetTimeZoneInformation': SimTypeFunction([SimTypePointer(SimTypeRef("TIME_ZONE_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpTimeZoneInformation"]),
        #
        'SetTimeZoneInformation': SimTypeFunction([SimTypePointer(SimTypeRef("TIME_ZONE_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTimeZoneInformation"]),
        #
        'SetDynamicTimeZoneInformation': SimTypeFunction([SimTypePointer(SimTypeRef("DYNAMIC_TIME_ZONE_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTimeZoneInformation"]),
        #
        'GetDynamicTimeZoneInformation': SimTypeFunction([SimTypePointer(SimTypeRef("DYNAMIC_TIME_ZONE_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pTimeZoneInformation"]),
        #
        'GetTimeZoneInformationForYear': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("DYNAMIC_TIME_ZONE_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("TIME_ZONE_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["wYear", "pdtzi", "ptzi"]),
        #
        'SystemTimeToTzSpecificLocalTimeEx': SimTypeFunction([SimTypePointer(SimTypeRef("DYNAMIC_TIME_ZONE_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTimeZoneInformation", "lpUniversalTime", "lpLocalTime"]),
        #
        'TzSpecificLocalTimeToSystemTimeEx': SimTypeFunction([SimTypePointer(SimTypeRef("DYNAMIC_TIME_ZONE_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTimeZoneInformation", "lpLocalTime", "lpUniversalTime"]),
        #
        'LocalFileTimeToLocalSystemTime': SimTypeFunction([SimTypePointer(SimTypeRef("TIME_ZONE_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["timeZoneInformation", "localFileTime", "localSystemTime"]),
        #
        'LocalSystemTimeToLocalFileTime': SimTypeFunction([SimTypePointer(SimTypeRef("TIME_ZONE_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["timeZoneInformation", "localSystemTime", "localFileTime"]),
        #
        'uaw_lstrcmpW': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["String1", "String2"]),
        #
        'uaw_lstrcmpiW': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["String1", "String2"]),
        #
        'uaw_lstrlenW': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["String"]),
        #
        'uaw_wcschr': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeChar(label="Char")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["String", "Character"]),
        #
        'uaw_wcscpy': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["Destination", "Source"]),
        #
        'uaw_wcsicmp': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["String1", "String2"]),
        #
        'uaw_wcslen': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["String"]),
        #
        'uaw_wcsrchr': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeChar(label="Char")], SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), arg_names=["String", "Character"]),
        #
        'QueryThreadCycleTime': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ThreadHandle", "CycleTime"]),
        #
        'QueryProcessCycleTime': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "CycleTime"]),
        #
        'QueryIdleProcessorCycleTime': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["BufferLength", "ProcessorIdleCycleTime"]),
        #
        'QueryIdleProcessorCycleTimeEx': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Group", "BufferLength", "ProcessorIdleCycleTime"]),
        #
        'QueryUnbiasedInterruptTime': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["UnbiasedTime"]),
        #
        'GlobalCompact': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["dwMinFree"]),
        #
        'GlobalFix': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["hMem"]),
        #
        'GlobalUnfix': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["hMem"]),
        #
        'GlobalWire': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hMem"]),
        #
        'GlobalUnWire': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMem"]),
        #
        'LocalShrink': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hMem", "cbNewSize"]),
        #
        'LocalCompact': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["uMinFree"]),
        #
        'SetEnvironmentStringsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NewEnvironment"]),
        #
        'SetHandleCount': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["uNumber"]),
        #
        'RequestDeviceWakeup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice"]),
        #
        'CancelDeviceWakeupRequest': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDevice"]),
        #
        'SetMessageWaitingIndicator': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMsgIndicator", "ulMsgCount"]),
        #
        'MulDiv': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["nNumber", "nNumerator", "nDenominator"]),
        #
        'GetSystemRegistryQuota': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdwQuotaAllowed", "pdwQuotaUsed"]),
        #
        'FileTimeToDosDateTime': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileTime", "lpFatDate", "lpFatTime"]),
        #
        'DosDateTimeToFileTime': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["wFatDate", "wFatTime", "lpFileTime"]),
        #
        '_lopen': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName", "iReadWrite"]),
        #
        '_lcreat': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPathName", "iAttribute"]),
        #
        '_lread': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hFile", "lpBuffer", "uBytes"]),
        #
        '_lwrite': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hFile", "lpBuffer", "uBytes"]),
        #
        '_hread': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffer", "lBytes"]),
        #
        '_hwrite': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffer", "lBytes"]),
        #
        '_lclose': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile"]),
        #
        '_llseek': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lOffset", "iOrigin"]),
        #
        'OpenMutexA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "lpName"]),
        #
        'OpenSemaphoreA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwDesiredAccess", "bInheritHandle", "lpName"]),
        #
        'GetFirmwareEnvironmentVariableA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpName", "lpGuid", "pBuffer", "nSize"]),
        #
        'GetFirmwareEnvironmentVariableW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpName", "lpGuid", "pBuffer", "nSize"]),
        #
        'GetFirmwareEnvironmentVariableExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpName", "lpGuid", "pBuffer", "nSize", "pdwAttribubutes"]),
        #
        'GetFirmwareEnvironmentVariableExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpName", "lpGuid", "pBuffer", "nSize", "pdwAttribubutes"]),
        #
        'SetFirmwareEnvironmentVariableA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpName", "lpGuid", "pValue", "nSize"]),
        #
        'SetFirmwareEnvironmentVariableW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpName", "lpGuid", "pValue", "nSize"]),
        #
        'SetFirmwareEnvironmentVariableExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpName", "lpGuid", "pValue", "nSize", "dwAttributes"]),
        #
        'SetFirmwareEnvironmentVariableExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpName", "lpGuid", "pValue", "nSize", "dwAttributes"]),
        #
        'IsNativeVhdBoot': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NativeVhdBoot"]),
        #
        'GetProfileIntA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpAppName", "lpKeyName", "nDefault"]),
        #
        'GetProfileIntW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpAppName", "lpKeyName", "nDefault"]),
        #
        'GetProfileStringA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpAppName", "lpKeyName", "lpDefault", "lpReturnedString", "nSize"]),
        #
        'GetProfileStringW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpAppName", "lpKeyName", "lpDefault", "lpReturnedString", "nSize"]),
        #
        'WriteProfileStringA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAppName", "lpKeyName", "lpString"]),
        #
        'WriteProfileStringW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAppName", "lpKeyName", "lpString"]),
        #
        'GetProfileSectionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpAppName", "lpReturnedString", "nSize"]),
        #
        'GetProfileSectionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpAppName", "lpReturnedString", "nSize"]),
        #
        'WriteProfileSectionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAppName", "lpString"]),
        #
        'WriteProfileSectionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAppName", "lpString"]),
        #
        'GetPrivateProfileIntA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpAppName", "lpKeyName", "nDefault", "lpFileName"]),
        #
        'GetPrivateProfileIntW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAppName", "lpKeyName", "nDefault", "lpFileName"]),
        #
        'GetPrivateProfileStringA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpAppName", "lpKeyName", "lpDefault", "lpReturnedString", "nSize", "lpFileName"]),
        #
        'GetPrivateProfileStringW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpAppName", "lpKeyName", "lpDefault", "lpReturnedString", "nSize", "lpFileName"]),
        #
        'WritePrivateProfileStringA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAppName", "lpKeyName", "lpString", "lpFileName"]),
        #
        'WritePrivateProfileStringW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAppName", "lpKeyName", "lpString", "lpFileName"]),
        #
        'GetPrivateProfileSectionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpAppName", "lpReturnedString", "nSize", "lpFileName"]),
        #
        'GetPrivateProfileSectionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpAppName", "lpReturnedString", "nSize", "lpFileName"]),
        #
        'WritePrivateProfileSectionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAppName", "lpString", "lpFileName"]),
        #
        'WritePrivateProfileSectionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAppName", "lpString", "lpFileName"]),
        #
        'GetPrivateProfileSectionNamesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszReturnBuffer", "nSize", "lpFileName"]),
        #
        'GetPrivateProfileSectionNamesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszReturnBuffer", "nSize", "lpFileName"]),
        #
        'GetPrivateProfileStructA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszSection", "lpszKey", "lpStruct", "uSizeStruct", "szFile"]),
        #
        'GetPrivateProfileStructW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszSection", "lpszKey", "lpStruct", "uSizeStruct", "szFile"]),
        #
        'WritePrivateProfileStructA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszSection", "lpszKey", "lpStruct", "uSizeStruct", "szFile"]),
        #
        'WritePrivateProfileStructW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszSection", "lpszKey", "lpStruct", "uSizeStruct", "szFile"]),
        #
        'IsBadHugeReadPtr': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lp", "ucb"]),
        #
        'IsBadHugeWritePtr': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lp", "ucb"]),
        #
        'GetComputerNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpBuffer", "nSize"]),
        #
        'GetComputerNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpBuffer", "nSize"]),
        #
        'DnsHostnameToComputerNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Hostname", "ComputerName", "nSize"]),
        #
        'DnsHostnameToComputerNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Hostname", "ComputerName", "nSize"]),
        #
        'ReplacePartitionUnit': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetPartition", "SparePartition", "Flags"]),
        #
        'GetThreadEnabledXStateFeatures': SimTypeFunction([], SimTypeLongLong(signed=False, label="UInt64")),
        #
        'EnableProcessOptionalXStateFeatures': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["Features"]),
        #
        'InterlockedCompareExchange': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'InterlockedCompareExchange64': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'InterlockedDecrement': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'InterlockedExchange': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'InterlockedExchangeAdd': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'InterlockedIncrement': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'UTRegister': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegisterConsoleVDM': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegOpenUserClassesRoot': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SortCloseHandle': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WriteConsoleInputVDMW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegEnumValueW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseDllReadWriteIniFile': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'NlsCheckPolicy': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegGetKeySecurity': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'lstrlen': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'NlsGetCacheUpdateCount': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'OpenThreadToken': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetTermsrvAppInstallMode': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetConsoleFontInfo': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetCalendarMonthsInYear': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WerpNotifyLoadStringResourceEx': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RemoveLocalAlternateComputerNameW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetVDMCurrentDirectories': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsoleInputExeNameA': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegDisablePredefinedCacheEx': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'IdnToAscii': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LoadAppInitDlls': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'OpenConsoleW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ExitVDM': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegNotifyChangeKeyValue': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'AddLocalAlternateComputerNameW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegOpenKeyExA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RtlMoveMemory': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegFlushKey': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegUnLoadKeyA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegisterConsoleIME': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegLoadMUIStringA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegCreateKeyExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CheckForReadOnlyResource': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegRestoreKeyW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'lstrcpy': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegEnumKeyExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CreateProcessAsUserW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RtlZeroMemory': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetConsoleNlsMode': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegGetValueA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'AdjustCalendarDate': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseSetLastNTError': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ShowConsoleCursor': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BasepCheckWinSaferRestrictions': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ReadConsoleInputExA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegSetValueExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegQueryValueExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegDeleteValueA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegOpenCurrentUser': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CtrlRoutine': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RtlFillMemory': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'VerifyConsoleIoHandle': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'EnumerateLocalComputerNamesW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CloseProfileUserMapping': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'GetEraNameCountedString': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegisterWaitForSingleObjectEx': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'DosPathToSessionPathW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegSaveKeyExA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CreateProcessInternalW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'OpenProfileUserMapping': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'GetConsoleHardwareState': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsoleNlsMode': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'AddLocalAlternateComputerNameA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BasepCheckBadapp': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetConsoleKeyboardLayoutNameA': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'lstrcmpi': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseFormatObjectAttributes': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LZCloseFile': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetNamedPipeAttribute': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BasepMapModuleHandle': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetNamedPipeAttribute': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegCreateKeyExA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsoleOS2OemFormat': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'TermsrvAppInstallMode': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'RemoveLocalAlternateComputerNameA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LZCreateFileW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'NlsUpdateLocale': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegisterWowBaseHandlers': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetClientTimeZoneInformation': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseCheckRunApp': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseThreadInitThunk': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'UpdateCalendarDayOfWeek': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsoleMaximumWindowSize': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertNLSDayOfWeekToWin32DayOfWeek': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertCalDateTimeToSystemTime': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegDeleteKeyExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ReplaceFile': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetConsoleCharType': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetConsoleInputWaitHandle': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'RestoreLastError': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CompareCalendarDates': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegLoadKeyA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetLocalPrimaryComputerNameW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'UnregisterConsoleIME': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'lstrcat': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseInitAppcompatCacheSupport': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'InterlockedPushListSList': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetEnvironmentStringsA': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'CreateSocketHandle': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'RegSetKeySecurity': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetThreadToken': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegQueryInfoKeyW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetNumberOfConsoleFonts': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'GetCalendarSupportedDateRange': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegOpenKeyExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegKrnGetGlobalState': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'WerpNotifyUseStringResource': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsoleFont': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseGetNamedObjectDirectory': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'IsCalendarLeapMonth': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegDeleteTreeW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'IsValidCalDateTime': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegQueryValueExA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsoleCursor': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegDeleteTreeA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SortGetHandle': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WerpInitiateRemoteRecovery': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'VDMOperationStarted': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'OpenProcessToken': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'VDMConsoleOperation': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseVerifyUnicodeString': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegUnLoadKeyW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetProcessUserModeExceptionPolicy': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetNextVDMCommand': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LoadStringBaseW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'DuplicateConsoleHandle': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseCheckAppcompatCache': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WerpStringLookup': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseDumpAppcompatCache': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'CreateProcessInternalA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'NlsEventDataDescCreate': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegRestoreKeyA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'NlsWriteEtwEvent': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegCloseKey': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'NotifyMountMgr': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'IsCalendarLeapYear': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'DosPathToSessionPathA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BasepAnsiStringToDynamicUnicodeString': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetLocalPrimaryComputerNameA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'lstrcpyn': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsoleLocalEUDC': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'PrivCopyFileExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsoleCursorMode': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegisterConsoleOS2': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsoleIcon': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegDeleteValueW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsoleInputExeNameW': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsoleHardwareState': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetConsoleCursorMode': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ReadConsoleInputExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WerpNotifyLoadStringResource': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseCheckAppcompatCacheEx': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'PrivMoveFileIdentityW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CmdBatNotification': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseFormatTimeOut': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'InvalidateConsoleDIBits': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegSaveKeyExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'IsCalendarLeapDay': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseCleanupAppcompatCacheSupport': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BasepAllocateActivationContextActivationBlock': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'DelayLoadFailureHook': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'WriteConsoleInputVDMA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegLoadKeyW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'lstrcmp': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConsoleMenuControl': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseQueryModuleData': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegDeleteKeyExA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegLoadMUIStringW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetHandleContext': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'IdnToUnicode': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegKrnInitialize': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseFlushAppcompatCache': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'GetCalendarWeekNumber': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'NlsUpdateSystemLocale': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetComPlusPackageInstallStatus': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'BaseIsAppcompatInfrastructureDisabled': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'WerpCleanupMessageMapping': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'RegisterWowExec': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BasepCheckAppCompat': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsoleMenuClose': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetCalendarDifferenceInDays': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'LoadStringBaseExW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetConsoleInputExeNameA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsolePalette': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetCalendarDaysInMonth': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseGenerateAppCompatData': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetLastConsoleEventActive': SimTypeFunction([], SimTypeLong(signed=True)),
        #
        'GetConsoleInputExeNameW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegGetValueW': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetHandleContext': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetConsoleKeyShortcuts': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BaseUpdateAppcompatCache': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BasepFreeActivationContextActivationBlock': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetBinaryType': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'Basep8BitStringToDynamicUnicodeString': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegQueryInfoKeyA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'BasepFreeAppCompatData': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegEnumKeyExA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CheckElevationEnabled': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetCalendarDateFormatEx': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegSetValueExA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegEnumValueA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetConsoleKeyboardLayoutNameW': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetComPlusPackageInstallStatus': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetVDMCurrentDirectories': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CloseConsoleHandle': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'EnumerateLocalComputerNamesA': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'UTUnRegister': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'GetCalendarDateFormat': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'SetProcessUserModeExceptionPolicy': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'CheckElevation': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'RegisterWaitForInputIdle': SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'ConvertSystemTimeToCalDateTime': SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        #
        'IsTimeZoneRedirectionEnabled': SimTypeFunction([], SimTypeLong(signed=True)),
    }

lib.set_prototypes(prototypes)
