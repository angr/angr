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
lib.set_library_names("mscoree.dll")
prototypes = \
    {
        #
        'GetCORSystemDirectory': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbuffer", "cchBuffer", "dwLength"]),
        #
        'GetCORVersion': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbBuffer", "cchBuffer", "dwLength"]),
        #
        'GetFileVersion': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szFilename", "szBuffer", "cchBuffer", "dwLength"]),
        #
        'GetCORRequiredVersion': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbuffer", "cchBuffer", "dwLength"]),
        #
        'GetRequestedRuntimeInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pExe", "pwszVersion", "pConfigurationFile", "startupFlags", "runtimeInfoFlags", "pDirectory", "dwDirectory", "dwDirectoryLength", "pVersion", "cchBuffer", "dwlength"]),
        #
        'GetRequestedRuntimeVersion': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pExe", "pVersion", "cchBuffer", "dwLength"]),
        #
        'CorBindToRuntimeHost': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszVersion", "pwszBuildFlavor", "pwszHostConfigFile", "pReserved", "startupFlags", "rclsid", "riid", "ppv"]),
        #
        'CorBindToRuntimeEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszVersion", "pwszBuildFlavor", "startupFlags", "rclsid", "riid", "ppv"]),
        #
        'CorBindToRuntimeByCfg': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCfgStream", "reserved", "startupFlags", "rclsid", "riid", "ppv"]),
        #
        'CorBindToRuntime': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszVersion", "pwszBuildFlavor", "rclsid", "riid", "ppv"]),
        #
        'CorBindToCurrentRuntime': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszFileName", "rclsid", "riid", "ppv"]),
        #
        'ClrCreateManagedInstance': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pTypeName", "riid", "ppObject"]),
        #
        'CorMarkThreadInThreadPool': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'RunDll32ShimW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "hinst", "lpszCmdLine", "nCmdShow"]),
        #
        'LoadLibraryShim': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szDllName", "szVersion", "pvReserved", "phModDll"]),
        #
        'CallFunctionShim': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szDllName", "szFunctionName", "lpvArgument1", "lpvArgument2", "szVersion", "pvReserved"]),
        #
        'GetRealProcAddress': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszProcName", "ppv"]),
        #
        'CorExitProcess': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["exitCode"]),
        #
        'LoadStringRC': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["iResouceID", "szBuffer", "iMax", "bQuiet"]),
        #
        'LoadStringRCEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lcid", "iResouceID", "szBuffer", "iMax", "bQuiet", "pcwchUsed"]),
        #
        'LockClrVersion': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hostCallback", "pBeginHostSetup", "pEndHostSetup"]),
        #
        'CreateDebuggingInterfaceFromVersion': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iDebuggerVersion", "szDebuggeeVersion", "ppCordb"]),
        #
        'GetVersionFromProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProcess", "pVersion", "cchBuffer", "dwLength"]),
        #
        'CorLaunchApplication': SimTypeFunction([SimTypeInt(signed=False, label="HOST_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeRef("PROCESS_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwClickOnceHost", "pwzAppFullName", "dwManifestPaths", "ppwzManifestPaths", "dwActivationData", "ppwzActivationData", "lpProcessInformation"]),
        #
        'GetRequestedRuntimeVersionForCLSID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="CLSID_RESOLUTION_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid", "pVersion", "cchBuffer", "dwLength", "dwResolutionFlags"]),
        #
        'GetCLRIdentityManager': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppManager"]),
        #
        'CLRCreateInstance': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsid", "riid", "ppInterface"]),
    }

lib.set_prototypes(prototypes)
