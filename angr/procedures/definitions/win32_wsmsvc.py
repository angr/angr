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
lib.set_library_names("wsmsvc.dll")
prototypes = \
    {
        #
        'WSManInitialize': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["flags", "apiHandle"]),
        #
        'WSManDeinitialize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["apiHandle", "flags"]),
        #
        'WSManGetErrorMessage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["apiHandle", "flags", "languageCode", "errorCode", "messageLength", "message", "messageLengthUsed"]),
        #
        'WSManCreateSession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSMAN_AUTHENTICATION_CREDENTIALS", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_PROXY_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["apiHandle", "connection", "flags", "serverAuthenticationCredentials", "proxyInfo", "session"]),
        #
        'WSManCloseSession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["session", "flags"]),
        #
        'WSManSetSessionOption': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WSManSessionOption"), SimTypePointer(SimTypeRef("WSMAN_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["session", "option", "data"]),
        #
        'WSManGetSessionOptionAsDword': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WSManSessionOption"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["session", "option", "value"]),
        #
        'WSManGetSessionOptionAsString': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WSManSessionOption"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["session", "option", "stringLength", "string", "stringLengthUsed"]),
        #
        'WSManCloseOperation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["operationHandle", "flags"]),
        #
        'WSManCreateShell': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSMAN_SHELL_STARTUP_INFO_V11", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_OPTION_SET", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["session", "flags", "resourceUri", "startupInfo", "options", "createXml", "async", "shell"]),
        #
        'WSManRunShellCommand': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSMAN_COMMAND_ARG_SET", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_OPTION_SET", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["shell", "flags", "commandLine", "args", "options", "async", "command"]),
        #
        'WSManSignalShell': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["shell", "command", "flags", "code", "async", "signalOperation"]),
        #
        'WSManReceiveShellOutput': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSMAN_STREAM_ID_SET", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["shell", "command", "flags", "desiredStreamSet", "async", "receiveOperation"]),
        #
        'WSManSendShellInput': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSMAN_DATA", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["shell", "command", "flags", "streamId", "streamData", "endOfStream", "async", "sendOperation"]),
        #
        'WSManCloseCommand': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["commandHandle", "flags", "async"]),
        #
        'WSManCloseShell': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["shellHandle", "flags", "async"]),
        #
        'WSManCreateShellEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSMAN_SHELL_STARTUP_INFO_V11", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_OPTION_SET", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["session", "flags", "resourceUri", "shellId", "startupInfo", "options", "createXml", "async", "shell"]),
        #
        'WSManRunShellCommandEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSMAN_COMMAND_ARG_SET", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_OPTION_SET", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["shell", "flags", "commandId", "commandLine", "args", "options", "async", "command"]),
        #
        'WSManDisconnectShell': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSMAN_SHELL_DISCONNECT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["shell", "flags", "disconnectInfo", "async"]),
        #
        'WSManReconnectShell': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["shell", "flags", "async"]),
        #
        'WSManReconnectShellCommand': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["commandHandle", "flags", "async"]),
        #
        'WSManConnectShell': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSMAN_OPTION_SET", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["session", "flags", "resourceUri", "shellID", "options", "connectXml", "async", "shell"]),
        #
        'WSManConnectShellCommand': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSMAN_OPTION_SET", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSMAN_SHELL_ASYNC", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["shell", "flags", "commandID", "options", "connectXml", "async", "command"]),
        #
        'WSManPluginReportContext': SimTypeFunction([SimTypePointer(SimTypeRef("WSMAN_PLUGIN_REQUEST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["requestDetails", "flags", "context"]),
        #
        'WSManPluginReceiveResult': SimTypeFunction([SimTypePointer(SimTypeRef("WSMAN_PLUGIN_REQUEST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSMAN_DATA", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["requestDetails", "flags", "stream", "streamResult", "commandState", "exitCode"]),
        #
        'WSManPluginOperationComplete': SimTypeFunction([SimTypePointer(SimTypeRef("WSMAN_PLUGIN_REQUEST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["requestDetails", "flags", "errorCode", "extendedInformation"]),
        #
        'WSManPluginGetOperationParameters': SimTypeFunction([SimTypePointer(SimTypeRef("WSMAN_PLUGIN_REQUEST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSMAN_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["requestDetails", "flags", "data"]),
        #
        'WSManPluginGetConfiguration': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSMAN_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pluginContext", "flags", "data"]),
        #
        'WSManPluginReportCompletion': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pluginContext", "flags"]),
        #
        'WSManPluginFreeRequestDetails': SimTypeFunction([SimTypePointer(SimTypeRef("WSMAN_PLUGIN_REQUEST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["requestDetails"]),
        #
        'WSManPluginAuthzUserComplete': SimTypeFunction([SimTypePointer(SimTypeRef("WSMAN_SENDER_DETAILS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["senderDetails", "flags", "userAuthorizationContext", "impersonationToken", "userIsAdministrator", "errorCode", "extendedErrorInformation"]),
        #
        'WSManPluginAuthzOperationComplete': SimTypeFunction([SimTypePointer(SimTypeRef("WSMAN_SENDER_DETAILS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["senderDetails", "flags", "userAuthorizationContext", "errorCode", "extendedErrorInformation"]),
        #
        'WSManPluginAuthzQueryQuotaComplete': SimTypeFunction([SimTypePointer(SimTypeRef("WSMAN_SENDER_DETAILS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSMAN_AUTHZ_QUOTA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["senderDetails", "flags", "quota", "errorCode", "extendedErrorInformation"]),
    }

lib.set_prototypes(prototypes)
