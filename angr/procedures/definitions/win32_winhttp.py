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
lib.set_library_names("winhttp.dll")
prototypes = \
    {
        #
        'WinHttpSetStatusCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["hInternet", "dwContext", "dwInternetStatus", "lpvStatusInformation", "dwStatusInformationLength"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["hInternet", "dwContext", "dwInternetStatus", "lpvStatusInformation", "dwStatusInformationLength"]), offset=0), arg_names=["hInternet", "lpfnInternetCallback", "dwNotificationFlags", "dwReserved"]),
        #
        'WinHttpTimeFromSystemTime': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pst", "pwszTime"]),
        #
        'WinHttpTimeToSystemTime': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszTime", "pst"]),
        #
        'WinHttpCrackUrl': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("URL_COMPONENTS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszUrl", "dwUrlLength", "dwFlags", "lpUrlComponents"]),
        #
        'WinHttpCreateUrl': SimTypeFunction([SimTypePointer(SimTypeRef("URL_COMPONENTS", SimStruct), offset=0), SimTypeInt(signed=False, label="WIN_HTTP_CREATE_URL_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpUrlComponents", "dwFlags", "pwszUrl", "pdwUrlLength"]),
        #
        'WinHttpCheckPlatform': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'WinHttpGetDefaultProxyConfiguration': SimTypeFunction([SimTypePointer(SimTypeRef("WINHTTP_PROXY_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProxyInfo"]),
        #
        'WinHttpSetDefaultProxyConfiguration': SimTypeFunction([SimTypePointer(SimTypeRef("WINHTTP_PROXY_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProxyInfo"]),
        #
        'WinHttpOpen': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="WINHTTP_ACCESS_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pszAgentW", "dwAccessType", "pszProxyW", "pszProxyBypassW", "dwFlags"]),
        #
        'WinHttpCloseHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hInternet"]),
        #
        'WinHttpConnect': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hSession", "pswzServerName", "nServerPort", "dwReserved"]),
        #
        'WinHttpReadData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpBuffer", "dwNumberOfBytesToRead", "lpdwNumberOfBytesRead"]),
        #
        'WinHttpReadDataEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRequest", "lpBuffer", "dwNumberOfBytesToRead", "lpdwNumberOfBytesRead", "ullFlags", "cbProperty", "pvProperty"]),
        #
        'WinHttpWriteData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpBuffer", "dwNumberOfBytesToWrite", "lpdwNumberOfBytesWritten"]),
        #
        'WinHttpQueryDataAvailable': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpdwNumberOfBytesAvailable"]),
        #
        'WinHttpQueryOption': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hInternet", "dwOption", "lpBuffer", "lpdwBufferLength"]),
        #
        'WinHttpSetOption': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hInternet", "dwOption", "lpBuffer", "dwBufferLength"]),
        #
        'WinHttpSetTimeouts': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hInternet", "nResolveTimeout", "nConnectTimeout", "nSendTimeout", "nReceiveTimeout"]),
        #
        'WinHttpOpenRequest': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypeInt(signed=False, label="WINHTTP_OPEN_REQUEST_FLAGS")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hConnect", "pwszVerb", "pwszObjectName", "pwszVersion", "pwszReferrer", "ppwszAcceptTypes", "dwFlags"]),
        #
        'WinHttpAddRequestHeaders': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpszHeaders", "dwHeadersLength", "dwModifiers"]),
        #
        'WinHttpAddRequestHeadersEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WINHTTP_EXTENDED_HEADER", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRequest", "dwModifiers", "ullFlags", "ullExtra", "cHeaders", "pHeaders"]),
        #
        'WinHttpSendRequest': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpszHeaders", "dwHeadersLength", "lpOptional", "dwOptionalLength", "dwTotalLength", "dwContext"]),
        #
        'WinHttpSetCredentials': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "AuthTargets", "AuthScheme", "pwszUserName", "pwszPassword", "pAuthParams"]),
        #
        'WinHttpQueryAuthSchemes': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpdwSupportedSchemes", "lpdwFirstScheme", "pdwAuthTarget"]),
        #
        'WinHttpReceiveResponse': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "lpReserved"]),
        #
        'WinHttpQueryHeaders': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRequest", "dwInfoLevel", "pwszName", "lpBuffer", "lpdwBufferLength", "lpdwIndex"]),
        #
        'WinHttpQueryHeadersEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimUnion({"pwszName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pszName": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("WINHTTP_EXTENDED_HEADER", SimStruct), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRequest", "dwInfoLevel", "ullFlags", "uiCodePage", "pdwIndex", "pHeaderName", "pBuffer", "pdwBufferLength", "ppHeaders", "pdwHeadersCount"]),
        #
        'WinHttpQueryConnectionGroup': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypePointer(SimTypeRef("WINHTTP_QUERY_CONNECTION_GROUP_RESULT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hInternet", "pGuidConnection", "ullFlags", "ppResult"]),
        #
        'WinHttpFreeQueryConnectionGroupResult': SimTypeFunction([SimTypePointer(SimTypeRef("WINHTTP_QUERY_CONNECTION_GROUP_RESULT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pResult"]),
        #
        'WinHttpDetectAutoProxyConfigUrl': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwAutoDetectFlags", "ppwstrAutoConfigUrl"]),
        #
        'WinHttpGetProxyForUrl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WINHTTP_AUTOPROXY_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeRef("WINHTTP_PROXY_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSession", "lpcwszUrl", "pAutoProxyOptions", "pProxyInfo"]),
        #
        'WinHttpCreateProxyResolver': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSession", "phResolver"]),
        #
        'WinHttpGetProxyForUrlEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WINHTTP_AUTOPROXY_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hResolver", "pcwszUrl", "pAutoProxyOptions", "pContext"]),
        #
        'WinHttpGetProxyForUrlEx2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WINHTTP_AUTOPROXY_OPTIONS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hResolver", "pcwszUrl", "pAutoProxyOptions", "cbInterfaceSelectionContext", "pInterfaceSelectionContext", "pContext"]),
        #
        'WinHttpGetProxyResult': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("WINHTTP_PROXY_RESULT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hResolver", "pProxyResult"]),
        #
        'WinHttpGetProxyResultEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("WINHTTP_PROXY_RESULT_EX", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hResolver", "pProxyResultEx"]),
        #
        'WinHttpFreeProxyResult': SimTypeFunction([SimTypePointer(SimTypeRef("WINHTTP_PROXY_RESULT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pProxyResult"]),
        #
        'WinHttpFreeProxyResultEx': SimTypeFunction([SimTypePointer(SimTypeRef("WINHTTP_PROXY_RESULT_EX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pProxyResultEx"]),
        #
        'WinHttpResetAutoProxy': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSession", "dwFlags"]),
        #
        'WinHttpGetIEProxyConfigForCurrentUser': SimTypeFunction([SimTypePointer(SimTypeRef("WINHTTP_CURRENT_USER_IE_PROXY_CONFIG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProxyConfig"]),
        #
        'WinHttpWriteProxySettings': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("WINHTTP_PROXY_SETTINGS", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSession", "fForceUpdate", "pWinHttpProxySettings"]),
        #
        'WinHttpReadProxySettings': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("WINHTTP_PROXY_SETTINGS", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSession", "pcwszConnectionName", "fFallBackToDefaultSettings", "fSetAutoDiscoverForDefaultSettings", "pdwSettingsVersion", "pfDefaultSettingsAreReturned", "pWinHttpProxySettings"]),
        #
        'WinHttpFreeProxySettings': SimTypeFunction([SimTypePointer(SimTypeRef("WINHTTP_PROXY_SETTINGS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pWinHttpProxySettings"]),
        #
        'WinHttpGetProxySettingsVersion': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSession", "pdwProxySettingsVersion"]),
        #
        'WinHttpSetProxySettingsPerUser': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["fProxySettingsPerUser"]),
        #
        'WinHttpWebSocketCompleteUpgrade': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hRequest", "pContext"]),
        #
        'WinHttpWebSocketSend': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="WINHTTP_WEB_SOCKET_BUFFER_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWebSocket", "eBufferType", "pvBuffer", "dwBufferLength"]),
        #
        'WinHttpWebSocketReceive': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="WINHTTP_WEB_SOCKET_BUFFER_TYPE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWebSocket", "pvBuffer", "dwBufferLength", "pdwBytesRead", "peBufferType"]),
        #
        'WinHttpWebSocketShutdown': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWebSocket", "usStatus", "pvReason", "dwReasonLength"]),
        #
        'WinHttpWebSocketClose': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWebSocket", "usStatus", "pvReason", "dwReasonLength"]),
        #
        'WinHttpWebSocketQueryCloseStatus': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWebSocket", "pusStatus", "pvReason", "dwReasonLength", "pdwReasonLengthConsumed"]),
        #
        'WinHttpRegisterProxyChangeNotification': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ullFlags", "pvContext"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ullFlags", "pfnCallback", "pvContext", "hRegistration"]),
        #
        'WinHttpUnregisterProxyChangeNotification': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRegistration"]),
        #
        'WinHttpGetProxySettingsEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="WINHTTP_PROXY_SETTINGS_TYPE"), SimTypePointer(SimTypeRef("WINHTTP_PROXY_SETTINGS_PARAM", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hResolver", "ProxySettingsType", "pProxySettingsParam", "pContext"]),
        #
        'WinHttpGetProxySettingsResultEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hResolver", "pProxySettingsEx"]),
        #
        'WinHttpFreeProxySettingsEx': SimTypeFunction([SimTypeInt(signed=False, label="WINHTTP_PROXY_SETTINGS_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProxySettingsType", "pProxySettingsEx"]),
    }

lib.set_prototypes(prototypes)
