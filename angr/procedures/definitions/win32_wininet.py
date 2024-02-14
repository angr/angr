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
lib.set_library_names("wininet.dll")
prototypes = \
    {
        #
        'InternetTimeFromSystemTimeA': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pst", "dwRFC", "lpszTime", "cbTime"]),
        #
        'InternetTimeFromSystemTimeW': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pst", "dwRFC", "lpszTime", "cbTime"]),
        #
        'InternetTimeFromSystemTime': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pst", "dwRFC", "lpszTime", "cbTime"]),
        #
        'InternetTimeToSystemTimeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszTime", "pst", "dwReserved"]),
        #
        'InternetTimeToSystemTimeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszTime", "pst", "dwReserved"]),
        #
        'InternetTimeToSystemTime': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszTime", "pst", "dwReserved"]),
        #
        'InternetCrackUrlA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="WIN_HTTP_CREATE_URL_FLAGS"), SimTypePointer(SimTypeRef("URL_COMPONENTSA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "dwUrlLength", "dwFlags", "lpUrlComponents"]),
        #
        'InternetCrackUrlW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="WIN_HTTP_CREATE_URL_FLAGS"), SimTypePointer(SimTypeRef("URL_COMPONENTSW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "dwUrlLength", "dwFlags", "lpUrlComponents"]),
        #
        'InternetCreateUrlA': SimTypeFunction([SimTypePointer(SimTypeRef("URL_COMPONENTSA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpUrlComponents", "dwFlags", "lpszUrl", "lpdwUrlLength"]),
        #
        'InternetCreateUrlW': SimTypeFunction([SimTypePointer(SimTypeRef("URL_COMPONENTSW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpUrlComponents", "dwFlags", "lpszUrl", "lpdwUrlLength"]),
        #
        'InternetCanonicalizeUrlA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "lpszBuffer", "lpdwBufferLength", "dwFlags"]),
        #
        'InternetCanonicalizeUrlW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "lpszBuffer", "lpdwBufferLength", "dwFlags"]),
        #
        'InternetCombineUrlA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszBaseUrl", "lpszRelativeUrl", "lpszBuffer", "lpdwBufferLength", "dwFlags"]),
        #
        'InternetCombineUrlW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszBaseUrl", "lpszRelativeUrl", "lpszBuffer", "lpdwBufferLength", "dwFlags"]),
        #
        'InternetOpenA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["lpszAgent", "dwAccessType", "lpszProxy", "lpszProxyBypass", "dwFlags"]),
        #
        'InternetOpenW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["lpszAgent", "dwAccessType", "lpszProxy", "lpszProxyBypass", "dwFlags"]),
        #
        'InternetCloseHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hInternet"]),
        #
        'InternetConnectA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hInternet", "lpszServerName", "nServerPort", "lpszUserName", "lpszPassword", "dwService", "dwFlags", "dwContext"]),
        #
        'InternetConnectW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hInternet", "lpszServerName", "nServerPort", "lpszUserName", "lpszPassword", "dwService", "dwFlags", "dwContext"]),
        #
        'InternetOpenUrlA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hInternet", "lpszUrl", "lpszHeaders", "dwHeadersLength", "dwFlags", "dwContext"]),
        #
        'InternetOpenUrlW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hInternet", "lpszUrl", "lpszHeaders", "dwHeadersLength", "dwFlags", "dwContext"]),
        #
        'InternetReadFile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffer", "dwNumberOfBytesToRead", "lpdwNumberOfBytesRead"]),
        #
        'InternetReadFileExA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("INTERNET_BUFFERSA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffersOut", "dwFlags", "dwContext"]),
        #
        'InternetReadFileExW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("INTERNET_BUFFERSW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffersOut", "dwFlags", "dwContext"]),
        #
        'InternetSetFilePointer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hFile", "lDistanceToMove", "lpDistanceToMoveHigh", "dwMoveMethod", "dwContext"]),
        #
        'InternetWriteFile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffer", "dwNumberOfBytesToWrite", "lpdwNumberOfBytesWritten"]),
        #
        'InternetQueryDataAvailable': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpdwNumberOfBytesAvailable", "dwFlags", "dwContext"]),
        #
        'InternetFindNextFileA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFind", "lpvFindData"]),
        #
        'InternetFindNextFileW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFind", "lpvFindData"]),
        #
        'InternetQueryOptionA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hInternet", "dwOption", "lpBuffer", "lpdwBufferLength"]),
        #
        'InternetQueryOptionW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hInternet", "dwOption", "lpBuffer", "lpdwBufferLength"]),
        #
        'InternetSetOptionA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hInternet", "dwOption", "lpBuffer", "dwBufferLength"]),
        #
        'InternetSetOptionW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hInternet", "dwOption", "lpBuffer", "dwBufferLength"]),
        #
        'InternetSetOptionExA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hInternet", "dwOption", "lpBuffer", "dwBufferLength", "dwFlags"]),
        #
        'InternetSetOptionExW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hInternet", "dwOption", "lpBuffer", "dwBufferLength", "dwFlags"]),
        #
        'InternetLockRequestFile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hInternet", "lphLockRequestInfo"]),
        #
        'InternetUnlockRequestFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLockRequestInfo"]),
        #
        'InternetGetLastResponseInfoA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwError", "lpszBuffer", "lpdwBufferLength"]),
        #
        'InternetGetLastResponseInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwError", "lpszBuffer", "lpdwBufferLength"]),
        #
        'InternetSetStatusCallbackA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["hInternet", "dwContext", "dwInternetStatus", "lpvStatusInformation", "dwStatusInformationLength"]), offset=0)], SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["hInternet", "dwContext", "dwInternetStatus", "lpvStatusInformation", "dwStatusInformationLength"]), offset=0), arg_names=["hInternet", "lpfnInternetCallback"]),
        #
        'InternetSetStatusCallbackW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["hInternet", "dwContext", "dwInternetStatus", "lpvStatusInformation", "dwStatusInformationLength"]), offset=0)], SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["hInternet", "dwContext", "dwInternetStatus", "lpvStatusInformation", "dwStatusInformationLength"]), offset=0), arg_names=["hInternet", "lpfnInternetCallback"]),
        #
        'InternetSetStatusCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["hInternet", "dwContext", "dwInternetStatus", "lpvStatusInformation", "dwStatusInformationLength"]), offset=0)], SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["hInternet", "dwContext", "dwInternetStatus", "lpvStatusInformation", "dwStatusInformationLength"]), offset=0), arg_names=["hInternet", "lpfnInternetCallback"]),
        #
        'FtpFindFirstFileA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("WIN32_FIND_DATAA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hConnect", "lpszSearchFile", "lpFindFileData", "dwFlags", "dwContext"]),
        #
        'FtpFindFirstFileW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WIN32_FIND_DATAW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hConnect", "lpszSearchFile", "lpFindFileData", "dwFlags", "dwContext"]),
        #
        'FtpGetFileA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszRemoteFile", "lpszNewFile", "fFailIfExists", "dwFlagsAndAttributes", "dwFlags", "dwContext"]),
        #
        'FtpGetFileW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszRemoteFile", "lpszNewFile", "fFailIfExists", "dwFlagsAndAttributes", "dwFlags", "dwContext"]),
        #
        'FtpPutFileA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="FTP_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszLocalFile", "lpszNewRemoteFile", "dwFlags", "dwContext"]),
        #
        'FtpPutFileW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="FTP_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszLocalFile", "lpszNewRemoteFile", "dwFlags", "dwContext"]),
        #
        'FtpGetFileEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFtpSession", "lpszRemoteFile", "lpszNewFile", "fFailIfExists", "dwFlagsAndAttributes", "dwFlags", "dwContext"]),
        #
        'FtpPutFileEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFtpSession", "lpszLocalFile", "lpszNewRemoteFile", "dwFlags", "dwContext"]),
        #
        'FtpDeleteFileA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszFileName"]),
        #
        'FtpDeleteFileW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszFileName"]),
        #
        'FtpRenameFileA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszExisting", "lpszNew"]),
        #
        'FtpRenameFileW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszExisting", "lpszNew"]),
        #
        'FtpOpenFileA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FTP_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hConnect", "lpszFileName", "dwAccess", "dwFlags", "dwContext"]),
        #
        'FtpOpenFileW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FTP_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hConnect", "lpszFileName", "dwAccess", "dwFlags", "dwContext"]),
        #
        'FtpCreateDirectoryA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszDirectory"]),
        #
        'FtpCreateDirectoryW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszDirectory"]),
        #
        'FtpRemoveDirectoryA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszDirectory"]),
        #
        'FtpRemoveDirectoryW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszDirectory"]),
        #
        'FtpSetCurrentDirectoryA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszDirectory"]),
        #
        'FtpSetCurrentDirectoryW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszDirectory"]),
        #
        'FtpGetCurrentDirectoryA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszCurrentDirectory", "lpdwCurrentDirectory"]),
        #
        'FtpGetCurrentDirectoryW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszCurrentDirectory", "lpdwCurrentDirectory"]),
        #
        'FtpCommandA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="FTP_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "fExpectResponse", "dwFlags", "lpszCommand", "dwContext", "phFtpCommand"]),
        #
        'FtpCommandW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="FTP_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "fExpectResponse", "dwFlags", "lpszCommand", "dwContext", "phFtpCommand"]),
        #
        'FtpGetFileSize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hFile", "lpdwFileSizeHigh"]),
        #
        'GopherCreateLocatorA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszHost", "nServerPort", "lpszDisplayString", "lpszSelectorString", "dwGopherType", "lpszLocator", "lpdwBufferLength"]),
        #
        'GopherCreateLocatorW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszHost", "nServerPort", "lpszDisplayString", "lpszSelectorString", "dwGopherType", "lpszLocator", "lpdwBufferLength"]),
        #
        'GopherGetLocatorTypeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszLocator", "lpdwGopherType"]),
        #
        'GopherGetLocatorTypeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszLocator", "lpdwGopherType"]),
        #
        'GopherFindFirstFileA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("GOPHER_FIND_DATAA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hConnect", "lpszLocator", "lpszSearchString", "lpFindData", "dwFlags", "dwContext"]),
        #
        'GopherFindFirstFileW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("GOPHER_FIND_DATAW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hConnect", "lpszLocator", "lpszSearchString", "lpFindData", "dwFlags", "dwContext"]),
        #
        'GopherOpenFileA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hConnect", "lpszLocator", "lpszView", "dwFlags", "dwContext"]),
        #
        'GopherOpenFileW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hConnect", "lpszLocator", "lpszView", "dwFlags", "dwContext"]),
        #
        'GopherGetAttributeA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("GOPHER_ATTRIBUTE_TYPE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAttributeInfo", "dwError"]), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszLocator", "lpszAttributeName", "lpBuffer", "dwBufferLength", "lpdwCharactersReturned", "lpfnEnumerator", "dwContext"]),
        #
        'GopherGetAttributeW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("GOPHER_ATTRIBUTE_TYPE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAttributeInfo", "dwError"]), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConnect", "lpszLocator", "lpszAttributeName", "lpBuffer", "dwBufferLength", "lpdwCharactersReturned", "lpfnEnumerator", "dwContext"]),
        #
        'HttpOpenRequestA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hConnect", "lpszVerb", "lpszObjectName", "lpszVersion", "lpszReferrer", "lplpszAcceptTypes", "dwFlags", "dwContext"]),
        #
        'HttpOpenRequestW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hConnect", "lpszVerb", "lpszObjectName", "lpszVersion", "lpszReferrer", "lplpszAcceptTypes", "dwFlags", "dwContext"]),
        #
        'HttpAddRequestHeadersA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="HTTP_ADDREQ_FLAG")], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpszHeaders", "dwHeadersLength", "dwModifiers"]),
        #
        'HttpAddRequestHeadersW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="HTTP_ADDREQ_FLAG")], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpszHeaders", "dwHeadersLength", "dwModifiers"]),
        #
        'HttpSendRequestA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpszHeaders", "dwHeadersLength", "lpOptional", "dwOptionalLength"]),
        #
        'HttpSendRequestW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpszHeaders", "dwHeadersLength", "lpOptional", "dwOptionalLength"]),
        #
        'HttpSendRequestExA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("INTERNET_BUFFERSA", SimStruct), offset=0), SimTypePointer(SimTypeRef("INTERNET_BUFFERSA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpBuffersIn", "lpBuffersOut", "dwFlags", "dwContext"]),
        #
        'HttpSendRequestExW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("INTERNET_BUFFERSW", SimStruct), offset=0), SimTypePointer(SimTypeRef("INTERNET_BUFFERSW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpBuffersIn", "lpBuffersOut", "dwFlags", "dwContext"]),
        #
        'HttpEndRequestA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("INTERNET_BUFFERSA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpBuffersOut", "dwFlags", "dwContext"]),
        #
        'HttpEndRequestW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("INTERNET_BUFFERSW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpBuffersOut", "dwFlags", "dwContext"]),
        #
        'HttpQueryInfoA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "dwInfoLevel", "lpBuffer", "lpdwBufferLength", "lpdwIndex"]),
        #
        'HttpQueryInfoW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "dwInfoLevel", "lpBuffer", "lpdwBufferLength", "lpdwIndex"]),
        #
        'InternetSetCookieA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "lpszCookieName", "lpszCookieData"]),
        #
        'InternetSetCookieW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "lpszCookieName", "lpszCookieData"]),
        #
        'InternetGetCookieA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "lpszCookieName", "lpszCookieData", "lpdwSize"]),
        #
        'InternetGetCookieW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "lpszCookieName", "lpszCookieData", "lpdwSize"]),
        #
        'InternetSetCookieExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszUrl", "lpszCookieName", "lpszCookieData", "dwFlags", "dwReserved"]),
        #
        'InternetSetCookieExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszUrl", "lpszCookieName", "lpszCookieData", "dwFlags", "dwReserved"]),
        #
        'InternetGetCookieExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="INTERNET_COOKIE_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "lpszCookieName", "lpszCookieData", "lpdwSize", "dwFlags", "lpReserved"]),
        #
        'InternetGetCookieExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="INTERNET_COOKIE_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "lpszCookieName", "lpszCookieData", "lpdwSize", "dwFlags", "lpReserved"]),
        #
        'InternetFreeCookies': SimTypeFunction([SimTypePointer(SimTypeRef("INTERNET_COOKIE2", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pCookies", "dwCookieCount"]),
        #
        'InternetGetCookieEx2': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("INTERNET_COOKIE2", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pcwszUrl", "pcwszCookieName", "dwFlags", "ppCookies", "pdwCookieCount"]),
        #
        'InternetSetCookieEx2': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("INTERNET_COOKIE2", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pcwszUrl", "pCookie", "pcwszP3PPolicy", "dwFlags", "pdwCookieState"]),
        #
        'InternetAttemptConnect': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwReserved"]),
        #
        'InternetCheckConnectionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "dwFlags", "dwReserved"]),
        #
        'InternetCheckConnectionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "dwFlags", "dwReserved"]),
        #
        'ResumeSuspendedDownload': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "dwResultCode"]),
        #
        'InternetErrorDlg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWnd", "hRequest", "dwError", "dwFlags", "lppvData"]),
        #
        'InternetConfirmZoneCrossingA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWnd", "szUrlPrev", "szUrlNew", "bPost"]),
        #
        'InternetConfirmZoneCrossingW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWnd", "szUrlPrev", "szUrlNew", "bPost"]),
        #
        'InternetConfirmZoneCrossing': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWnd", "szUrlPrev", "szUrlNew", "bPost"]),
        #
        'CreateUrlCacheEntryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "dwExpectedFileSize", "lpszFileExtension", "lpszFileName", "dwReserved"]),
        #
        'CreateUrlCacheEntryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "dwExpectedFileSize", "lpszFileExtension", "lpszFileName", "dwReserved"]),
        #
        'CommitUrlCacheEntryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeRef("FILETIME", SimStruct), SimTypeRef("FILETIME", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "lpszLocalFileName", "ExpireTime", "LastModifiedTime", "CacheEntryType", "lpHeaderInfo", "cchHeaderInfo", "lpszFileExtension", "lpszOriginalUrl"]),
        #
        'CommitUrlCacheEntryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("FILETIME", SimStruct), SimTypeRef("FILETIME", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "lpszLocalFileName", "ExpireTime", "LastModifiedTime", "CacheEntryType", "lpszHeaderInfo", "cchHeaderInfo", "lpszFileExtension", "lpszOriginalUrl"]),
        #
        'RetrieveUrlCacheEntryFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "lpCacheEntryInfo", "lpcbCacheEntryInfo", "dwReserved"]),
        #
        'RetrieveUrlCacheEntryFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "lpCacheEntryInfo", "lpcbCacheEntryInfo", "dwReserved"]),
        #
        'UnlockUrlCacheEntryFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "dwReserved"]),
        #
        'UnlockUrlCacheEntryFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "dwReserved"]),
        #
        'UnlockUrlCacheEntryFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "dwReserved"]),
        #
        'RetrieveUrlCacheEntryStreamA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszUrlName", "lpCacheEntryInfo", "lpcbCacheEntryInfo", "fRandomRead", "dwReserved"]),
        #
        'RetrieveUrlCacheEntryStreamW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszUrlName", "lpCacheEntryInfo", "lpcbCacheEntryInfo", "fRandomRead", "dwReserved"]),
        #
        'ReadUrlCacheEntryStream': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUrlCacheStream", "dwLocation", "lpBuffer", "lpdwLen", "Reserved"]),
        #
        'ReadUrlCacheEntryStreamEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hUrlCacheStream", "qwLocation", "lpBuffer", "lpdwLen"]),
        #
        'UnlockUrlCacheEntryStream': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hUrlCacheStream", "Reserved"]),
        #
        'GetUrlCacheEntryInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "lpCacheEntryInfo", "lpcbCacheEntryInfo"]),
        #
        'GetUrlCacheEntryInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "lpCacheEntryInfo", "lpcbCacheEntryInfo"]),
        #
        'FindFirstUrlCacheGroup': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwFlags", "dwFilter", "lpSearchCondition", "dwSearchCondition", "lpGroupId", "lpReserved"]),
        #
        'FindNextUrlCacheGroup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFind", "lpGroupId", "lpReserved"]),
        #
        'GetUrlCacheGroupAttributeA': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("INTERNET_CACHE_GROUP_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["gid", "dwFlags", "dwAttributes", "lpGroupInfo", "lpcbGroupInfo", "lpReserved"]),
        #
        'GetUrlCacheGroupAttributeW': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("INTERNET_CACHE_GROUP_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["gid", "dwFlags", "dwAttributes", "lpGroupInfo", "lpcbGroupInfo", "lpReserved"]),
        #
        'SetUrlCacheGroupAttributeA': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("INTERNET_CACHE_GROUP_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["gid", "dwFlags", "dwAttributes", "lpGroupInfo", "lpReserved"]),
        #
        'SetUrlCacheGroupAttributeW': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("INTERNET_CACHE_GROUP_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["gid", "dwFlags", "dwAttributes", "lpGroupInfo", "lpReserved"]),
        #
        'GetUrlCacheEntryInfoExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "lpCacheEntryInfo", "lpcbCacheEntryInfo", "lpszRedirectUrl", "lpcbRedirectUrl", "lpReserved", "dwFlags"]),
        #
        'GetUrlCacheEntryInfoExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "lpCacheEntryInfo", "lpcbCacheEntryInfo", "lpszRedirectUrl", "lpcbRedirectUrl", "lpReserved", "dwFlags"]),
        #
        'SetUrlCacheEntryInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "lpCacheEntryInfo", "dwFieldControl"]),
        #
        'SetUrlCacheEntryInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "lpCacheEntryInfo", "dwFieldControl"]),
        #
        'CreateUrlCacheGroup': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["dwFlags", "lpReserved"]),
        #
        'DeleteUrlCacheGroup': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["GroupId", "dwFlags", "lpReserved"]),
        #
        'SetUrlCacheEntryGroupA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "dwFlags", "GroupId", "pbGroupAttributes", "cbGroupAttributes", "lpReserved"]),
        #
        'SetUrlCacheEntryGroupW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "dwFlags", "GroupId", "pbGroupAttributes", "cbGroupAttributes", "lpReserved"]),
        #
        'SetUrlCacheEntryGroup': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "dwFlags", "GroupId", "pbGroupAttributes", "cbGroupAttributes", "lpReserved"]),
        #
        'FindFirstUrlCacheEntryExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszUrlSearchPattern", "dwFlags", "dwFilter", "GroupId", "lpFirstCacheEntryInfo", "lpcbCacheEntryInfo", "lpGroupAttributes", "lpcbGroupAttributes", "lpReserved"]),
        #
        'FindFirstUrlCacheEntryExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszUrlSearchPattern", "dwFlags", "dwFilter", "GroupId", "lpFirstCacheEntryInfo", "lpcbCacheEntryInfo", "lpGroupAttributes", "lpcbGroupAttributes", "lpReserved"]),
        #
        'FindNextUrlCacheEntryExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEnumHandle", "lpNextCacheEntryInfo", "lpcbCacheEntryInfo", "lpGroupAttributes", "lpcbGroupAttributes", "lpReserved"]),
        #
        'FindNextUrlCacheEntryExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEnumHandle", "lpNextCacheEntryInfo", "lpcbCacheEntryInfo", "lpGroupAttributes", "lpcbGroupAttributes", "lpReserved"]),
        #
        'FindFirstUrlCacheEntryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszUrlSearchPattern", "lpFirstCacheEntryInfo", "lpcbCacheEntryInfo"]),
        #
        'FindFirstUrlCacheEntryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszUrlSearchPattern", "lpFirstCacheEntryInfo", "lpcbCacheEntryInfo"]),
        #
        'FindNextUrlCacheEntryA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEnumHandle", "lpNextCacheEntryInfo", "lpcbCacheEntryInfo"]),
        #
        'FindNextUrlCacheEntryW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEnumHandle", "lpNextCacheEntryInfo", "lpcbCacheEntryInfo"]),
        #
        'FindCloseUrlCache': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEnumHandle"]),
        #
        'DeleteUrlCacheEntryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName"]),
        #
        'DeleteUrlCacheEntryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName"]),
        #
        'DeleteUrlCacheEntry': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName"]),
        #
        'InternetDialA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwndParent", "lpszConnectoid", "dwFlags", "lpdwConnection", "dwReserved"]),
        #
        'InternetDialW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwndParent", "lpszConnectoid", "dwFlags", "lpdwConnection", "dwReserved"]),
        #
        'InternetDial': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwndParent", "lpszConnectoid", "dwFlags", "lpdwConnection", "dwReserved"]),
        #
        'InternetHangUp': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwConnection", "dwReserved"]),
        #
        'InternetGoOnlineA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszURL", "hwndParent", "dwFlags"]),
        #
        'InternetGoOnlineW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszURL", "hwndParent", "dwFlags"]),
        #
        'InternetGoOnline': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszURL", "hwndParent", "dwFlags"]),
        #
        'InternetAutodial': SimTypeFunction([SimTypeInt(signed=False, label="INTERNET_AUTODIAL"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "hwndParent"]),
        #
        'InternetAutodialHangup': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwReserved"]),
        #
        'InternetGetConnectedState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="INTERNET_CONNECTION"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwFlags", "dwReserved"]),
        #
        'InternetGetConnectedStateExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="INTERNET_CONNECTION"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwFlags", "lpszConnectionName", "cchNameLen", "dwReserved"]),
        #
        'InternetGetConnectedStateExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="INTERNET_CONNECTION"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwFlags", "lpszConnectionName", "cchNameLen", "dwReserved"]),
        #
        'DeleteWpadCacheForNetworks': SimTypeFunction([SimTypeInt(signed=False, label="WPAD_CACHE_DELETE")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'InternetInitializeAutoProxyDll': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwReserved"]),
        #
        'DetectAutoProxyUrl': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="PROXY_AUTO_DETECT_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszAutoProxyUrl", "cchAutoProxyUrl", "dwDetectFlags"]),
        #
        'CreateMD5SSOHash': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszChallengeInfo", "pwszRealm", "pwszTarget", "pbHexHash"]),
        #
        'InternetGetConnectedStateEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="INTERNET_CONNECTION"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwFlags", "lpszConnectionName", "dwNameLen", "dwReserved"]),
        #
        'InternetSetDialStateA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszConnectoid", "dwState", "dwReserved"]),
        #
        'InternetSetDialStateW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszConnectoid", "dwState", "dwReserved"]),
        #
        'InternetSetDialState': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszConnectoid", "dwState", "dwReserved"]),
        #
        'InternetSetPerSiteCookieDecisionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pchHostName", "dwDecision"]),
        #
        'InternetSetPerSiteCookieDecisionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pchHostName", "dwDecision"]),
        #
        'InternetGetPerSiteCookieDecisionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pchHostName", "pResult"]),
        #
        'InternetGetPerSiteCookieDecisionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pchHostName", "pResult"]),
        #
        'InternetClearAllPerSiteCookieDecisions': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'InternetEnumPerSiteCookieDecisionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszSiteName", "pcSiteNameSize", "pdwDecision", "dwIndex"]),
        #
        'InternetEnumPerSiteCookieDecisionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszSiteName", "pcSiteNameSize", "pdwDecision", "dwIndex"]),
        #
        'PrivacySetZonePreferenceW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwZone", "dwType", "dwTemplate", "pszPreference"]),
        #
        'PrivacyGetZonePreferenceW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwZone", "dwType", "pdwTemplate", "pszBuffer", "pdwBufferLength"]),
        #
        'HttpIsHostHstsEnabled': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pcwszUrl", "pfIsHsts"]),
        #
        'InternetAlgIdToStringA': SimTypeFunction([SimTypeInt(signed=False, label="ALG_ID"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ai", "lpstr", "lpdwstrLength", "dwReserved"]),
        #
        'InternetAlgIdToStringW': SimTypeFunction([SimTypeInt(signed=False, label="ALG_ID"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ai", "lpstr", "lpdwstrLength", "dwReserved"]),
        #
        'InternetSecurityProtocolToStringA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwProtocol", "lpstr", "lpdwstrLength", "dwReserved"]),
        #
        'InternetSecurityProtocolToStringW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwProtocol", "lpstr", "lpdwstrLength", "dwReserved"]),
        #
        'InternetGetSecurityInfoByURLA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CERT_CHAIN_CONTEXT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszURL", "ppCertChain", "pdwSecureFlags"]),
        #
        'InternetGetSecurityInfoByURLW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CERT_CHAIN_CONTEXT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszURL", "ppCertChain", "pdwSecureFlags"]),
        #
        'InternetGetSecurityInfoByURL': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CERT_CHAIN_CONTEXT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszURL", "ppCertChain", "pdwSecureFlags"]),
        #
        'ShowSecurityInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("INTERNET_SECURITY_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWndParent", "pSecurityInfo"]),
        #
        'ShowX509EncodedCertificate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWndParent", "lpCert", "cbCert"]),
        #
        'ShowClientAuthCerts': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWndParent"]),
        #
        'ParseX509EncodedCertificateForListBoxEntry': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpCert", "cbCert", "lpszListBoxEntry", "lpdwListBoxEntry"]),
        #
        'InternetShowSecurityInfoByURLA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszURL", "hwndParent"]),
        #
        'InternetShowSecurityInfoByURLW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszURL", "hwndParent"]),
        #
        'InternetShowSecurityInfoByURL': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszURL", "hwndParent"]),
        #
        'InternetFortezzaCommand': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwCommand", "hwnd", "dwReserved"]),
        #
        'InternetQueryFortezzaStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdwStatus", "dwReserved"]),
        #
        'InternetWriteFileExA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("INTERNET_BUFFERSA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffersIn", "dwFlags", "dwContext"]),
        #
        'InternetWriteFileExW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("INTERNET_BUFFERSW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "lpBuffersIn", "dwFlags", "dwContext"]),
        #
        'FindP3PPolicySymbol': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszSymbol"]),
        #
        'HttpGetServerCredentials': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszUrl", "ppwszUserName", "ppwszPassword"]),
        #
        'HttpPushEnable': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("HTTP_PUSH_TRANSPORT_SETTING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRequest", "pTransportSetting", "phWait"]),
        #
        'HttpPushWait': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HTTP_PUSH_WAIT_TYPE"), SimTypePointer(SimTypeRef("HTTP_PUSH_NOTIFICATION_STATUS", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWait", "eType", "pNotificationStatus"]),
        #
        'HttpPushClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hWait"]),
        #
        'HttpCheckDavComplianceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "lpszComplianceToken", "lpfFound", "hWnd", "lpvReserved"]),
        #
        'HttpCheckDavComplianceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrl", "lpszComplianceToken", "lpfFound", "hWnd", "lpvReserved"]),
        #
        'IsUrlCacheEntryExpiredA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "dwFlags", "pftLastModified"]),
        #
        'IsUrlCacheEntryExpiredW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "dwFlags", "pftLastModified"]),
        #
        'CreateUrlCacheEntryExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUrlName", "dwExpectedFileSize", "lpszFileExtension", "lpszFileName", "dwReserved", "fPreserveIncomingFileName"]),
        #
        'GetUrlCacheEntryBinaryBlob': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszUrlName", "dwType", "pftExpireTime", "pftAccessTime", "pftModifiedTime", "ppbBlob", "pcbBlob"]),
        #
        'CommitUrlCacheEntryBinaryBlob': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeRef("FILETIME", SimStruct), SimTypeRef("FILETIME", SimStruct), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszUrlName", "dwType", "ftExpireTime", "ftModifiedTime", "pbBlob", "cbBlob"]),
        #
        'CreateUrlCacheContainerA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Name", "lpCachePrefix", "lpszCachePath", "KBCacheLimit", "dwContainerType", "dwOptions", "pvBuffer", "cbBuffer"]),
        #
        'CreateUrlCacheContainerW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Name", "lpCachePrefix", "lpszCachePath", "KBCacheLimit", "dwContainerType", "dwOptions", "pvBuffer", "cbBuffer"]),
        #
        'DeleteUrlCacheContainerA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Name", "dwOptions"]),
        #
        'DeleteUrlCacheContainerW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Name", "dwOptions"]),
        #
        'FindFirstUrlCacheContainerA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_CONTAINER_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pdwModified", "lpContainerInfo", "lpcbContainerInfo", "dwOptions"]),
        #
        'FindFirstUrlCacheContainerW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_CONTAINER_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pdwModified", "lpContainerInfo", "lpcbContainerInfo", "dwOptions"]),
        #
        'FindNextUrlCacheContainerA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_CONTAINER_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEnumHandle", "lpContainerInfo", "lpcbContainerInfo"]),
        #
        'FindNextUrlCacheContainerW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("INTERNET_CACHE_CONTAINER_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEnumHandle", "lpContainerInfo", "lpcbContainerInfo"]),
        #
        'FreeUrlCacheSpaceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszCachePath", "dwSize", "dwFilter"]),
        #
        'FreeUrlCacheSpaceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszCachePath", "dwSize", "dwFilter"]),
        #
        'UrlCacheFreeGlobalSpace': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ullTargetSize", "dwFilter"]),
        #
        'UrlCacheGetGlobalCacheSize': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwFilter", "pullSize", "pullLimit"]),
        #
        'GetUrlCacheConfigInfoA': SimTypeFunction([SimTypePointer(SimTypeRef("INTERNET_CACHE_CONFIG_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="CACHE_CONFIG")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCacheConfigInfo", "lpcbCacheConfigInfo", "dwFieldControl"]),
        #
        'GetUrlCacheConfigInfoW': SimTypeFunction([SimTypePointer(SimTypeRef("INTERNET_CACHE_CONFIG_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="CACHE_CONFIG")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCacheConfigInfo", "lpcbCacheConfigInfo", "dwFieldControl"]),
        #
        'SetUrlCacheConfigInfoA': SimTypeFunction([SimTypePointer(SimTypeRef("INTERNET_CACHE_CONFIG_INFOA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCacheConfigInfo", "dwFieldControl"]),
        #
        'SetUrlCacheConfigInfoW': SimTypeFunction([SimTypePointer(SimTypeRef("INTERNET_CACHE_CONFIG_INFOW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCacheConfigInfo", "dwFieldControl"]),
        #
        'RunOnceUrlCache': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwnd", "hinst", "lpszCmd", "nCmdShow"]),
        #
        'DeleteIE3Cache': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwnd", "hinst", "lpszCmd", "nCmdShow"]),
        #
        'UpdateUrlCacheContentPath': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szNewPath"]),
        #
        'RegisterUrlCacheNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "uMsg", "gid", "dwOpsFilter", "dwReserved"]),
        #
        'GetUrlCacheHeaderData': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nIdx", "lpdwData"]),
        #
        'SetUrlCacheHeaderData': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["nIdx", "dwData"]),
        #
        'IncrementUrlCacheHeaderData': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nIdx", "lpdwData"]),
        #
        'LoadUrlCacheContent': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'AppCacheLookup': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszUrl", "dwFlags", "phAppCache"]),
        #
        'AppCacheCheckManifest': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="APP_CACHE_STATE"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszMasterUrl", "pwszManifestUrl", "pbManifestData", "dwManifestDataSize", "pbManifestResponseHeaders", "dwManifestResponseHeadersSize", "peState", "phNewAppCache"]),
        #
        'AppCacheGetDownloadList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("APP_CACHE_DOWNLOAD_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hAppCache", "pDownloadList"]),
        #
        'AppCacheFreeDownloadList': SimTypeFunction([SimTypePointer(SimTypeRef("APP_CACHE_DOWNLOAD_LIST", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pDownloadList"]),
        #
        'AppCacheFinalize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="APP_CACHE_FINALIZE_STATE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hAppCache", "pbManifestData", "dwManifestDataSize", "peState"]),
        #
        'AppCacheGetFallbackUrl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hAppCache", "pwszUrl", "ppwszFallbackUrl"]),
        #
        'AppCacheGetManifestUrl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hAppCache", "ppwszManifestUrl"]),
        #
        'AppCacheDuplicateHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hAppCache", "phDuplicatedAppCache"]),
        #
        'AppCacheCloseHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["hAppCache"]),
        #
        'AppCacheFreeGroupList': SimTypeFunction([SimTypePointer(SimTypeRef("APP_CACHE_GROUP_LIST", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pAppCacheGroupList"]),
        #
        'AppCacheGetGroupList': SimTypeFunction([SimTypePointer(SimTypeRef("APP_CACHE_GROUP_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pAppCacheGroupList"]),
        #
        'AppCacheGetInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("APP_CACHE_GROUP_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hAppCache", "pAppCacheInfo"]),
        #
        'AppCacheDeleteGroup': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszManifestUrl"]),
        #
        'AppCacheFreeSpace': SimTypeFunction([SimTypeRef("FILETIME", SimStruct)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ftCutOff"]),
        #
        'AppCacheGetIEGroupList': SimTypeFunction([SimTypePointer(SimTypeRef("APP_CACHE_GROUP_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pAppCacheGroupList"]),
        #
        'AppCacheDeleteIEGroup': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszManifestUrl"]),
        #
        'AppCacheFreeIESpace': SimTypeFunction([SimTypeRef("FILETIME", SimStruct)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ftCutOff"]),
        #
        'AppCacheCreateAndCommitFile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hAppCache", "pwszSourceFilePath", "pwszUrl", "pbResponseHeaders", "dwResponseHeadersSize"]),
        #
        'HttpOpenDependencyHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRequestHandle", "fBackground", "phDependencyHandle"]),
        #
        'HttpCloseDependencyHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["hDependencyHandle"]),
        #
        'HttpDuplicateDependencyHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDependencyHandle", "phDuplicatedDependencyHandle"]),
        #
        'HttpIndicatePageLoadComplete': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDependencyHandle"]),
        #
        'UrlCacheFreeEntryInfo': SimTypeFunction([SimTypePointer(SimTypeRef("URLCACHE_ENTRY_INFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pCacheEntryInfo"]),
        #
        'UrlCacheGetEntryInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("URLCACHE_ENTRY_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hAppCache", "pcwszUrl", "pCacheEntryInfo"]),
        #
        'UrlCacheCloseEntryHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["hEntryFile"]),
        #
        'UrlCacheRetrieveEntryFile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("URLCACHE_ENTRY_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hAppCache", "pcwszUrl", "pCacheEntryInfo", "phEntryFile"]),
        #
        'UrlCacheReadEntryStream': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hUrlCacheStream", "ullLocation", "pBuffer", "dwBufferLen", "pdwBufferLen"]),
        #
        'UrlCacheRetrieveEntryStream': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("URLCACHE_ENTRY_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hAppCache", "pcwszUrl", "fRandomRead", "pCacheEntryInfo", "phEntryStream"]),
        #
        'UrlCacheUpdateEntryExtraData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hAppCache", "pcwszUrl", "pbExtraData", "cbExtraData"]),
        #
        'UrlCacheCreateContainer': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszName", "pwszPrefix", "pwszDirectory", "ullLimit", "dwOptions"]),
        #
        'UrlCacheCheckEntriesExist': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["rgpwszUrls", "cEntries", "rgfExist"]),
        #
        'UrlCacheGetContentPaths': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pppwszDirectories", "pcDirectories"]),
        #
        'UrlCacheGetGlobalLimit': SimTypeFunction([SimTypeInt(signed=False, label="URL_CACHE_LIMIT_TYPE"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["limitType", "pullLimit"]),
        #
        'UrlCacheSetGlobalLimit': SimTypeFunction([SimTypeInt(signed=False, label="URL_CACHE_LIMIT_TYPE"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=False, label="UInt32"), arg_names=["limitType", "ullLimit"]),
        #
        'UrlCacheReloadSettings': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'UrlCacheContainerSetEntryMaximumAge': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszPrefix", "dwEntryMaxAge"]),
        #
        'UrlCacheFindFirstEntry': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeRef("URLCACHE_ENTRY_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pwszPrefix", "dwFlags", "dwFilter", "GroupId", "pCacheEntryInfo", "phFind"]),
        #
        'UrlCacheFindNextEntry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("URLCACHE_ENTRY_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hFind", "pCacheEntryInfo"]),
        #
        'UrlCacheServer': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'ReadGuidsForConnectedNetworks': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcNetworks", "pppwszNetworkGuids", "pppbstrNetworkNames", "pppwszGWMacs", "pcGatewayMacs", "pdwFlags"]),
        #
        'IsHostInProxyBypassList': SimTypeFunction([SimTypeInt(signed=False, label="INTERNET_SCHEME"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["tScheme", "lpszHost", "cchHost"]),
        #
        'InternetFreeProxyInfoList': SimTypeFunction([SimTypePointer(SimTypeRef("WININET_PROXY_INFO_LIST", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pProxyInfoList"]),
        #
        'InternetGetProxyForUrl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WININET_PROXY_INFO_LIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInternet", "pcwszUrl", "pProxyInfoList"]),
        #
        'DoConnectoidsExist': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'GetDiskInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pdwClusterSize", "pdlAvail", "pdlTotal"]),
        #
        'PerformOperationOverUrlCacheA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("INTERNET_CACHE_ENTRY_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcei", "pcbcei", "pOpData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrlSearchPattern", "dwFlags", "dwFilter", "GroupId", "pReserved1", "pdwReserved2", "pReserved3", "op", "pOperatorData"]),
        #
        'IsProfilesEnabled': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'InternalInternetGetCookie': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszUrl", "lpszCookieData", "lpdwDataSize"]),
        #
        'ImportCookieFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szFilename"]),
        #
        'ImportCookieFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szFilename"]),
        #
        'ExportCookieFileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["szFilename", "fAppend"]),
        #
        'ExportCookieFileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["szFilename", "fAppend"]),
        #
        'IsDomainLegalCookieDomainA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pchDomain", "pchFullDomain"]),
        #
        'IsDomainLegalCookieDomainW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pchDomain", "pchFullDomain"]),
        #
        'HttpWebSocketCompleteUpgrade': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hRequest", "dwContext"]),
        #
        'HttpWebSocketSend': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="HTTP_WEB_SOCKET_BUFFER_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWebSocket", "BufferType", "pvBuffer", "dwBufferLength"]),
        #
        'HttpWebSocketReceive': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="HTTP_WEB_SOCKET_BUFFER_TYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWebSocket", "pvBuffer", "dwBufferLength", "pdwBytesRead", "pBufferType"]),
        #
        'HttpWebSocketClose': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWebSocket", "usStatus", "pvReason", "dwReasonLength"]),
        #
        'HttpWebSocketShutdown': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWebSocket", "usStatus", "pvReason", "dwReasonLength"]),
        #
        'HttpWebSocketQueryCloseStatus': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWebSocket", "pusStatus", "pvReason", "dwReasonLength", "pdwReasonLengthConsumed"]),
        #
        'InternetConvertUrlFromWireToWideChar': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pcszUrl", "cchUrl", "pcwszBaseUrl", "dwCodePageHost", "dwCodePagePath", "fEncodePathExtra", "dwCodePageExtra", "ppwszConvertedUrl"]),
    }

lib.set_prototypes(prototypes)
