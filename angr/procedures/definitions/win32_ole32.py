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
lib.set_library_names("ole32.dll")
prototypes = \
    {
        #
        'CoRegisterMessageFilter': SimTypeFunction([SimTypeBottom(label="IMessageFilter"), SimTypePointer(SimTypeBottom(label="IMessageFilter"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMessageFilter", "lplpMessageFilter"]),
        #
        'CoGetInterceptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iidIntercepted", "punkOuter", "iid", "ppv"]),
        #
        'CoGetInterceptorFromTypeInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeBottom(label="ITypeInfo"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iidIntercepted", "punkOuter", "typeInfo", "iid", "ppv"]),
        #
        'CoBuildVersion': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'CoInitialize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvReserved"]),
        #
        'CoRegisterMallocSpy': SimTypeFunction([SimTypeBottom(label="IMallocSpy")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMallocSpy"]),
        #
        'CoRevokeMallocSpy': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'CoRegisterInitializeSpy': SimTypeFunction([SimTypeBottom(label="IInitializeSpy"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSpy", "puliCookie"]),
        #
        'CoRevokeInitializeSpy': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["uliCookie"]),
        #
        'CoGetSystemSecurityPermissions': SimTypeFunction([SimTypeInt(signed=False, label="COMSD"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["comSDType", "ppSD"]),
        #
        'CoLoadLibrary': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszLibName", "bAutoFree"]),
        #
        'CoFreeLibrary': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hInst"]),
        #
        'CoFreeAllLibraries': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'CoAllowSetForegroundWindow': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk", "lpvReserved"]),
        #
        'DcomChannelSetHResult': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pvReserved", "pulReserved", "appsHR"]),
        #
        'CoIsOle1Class': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid"]),
        #
        'CLSIDFromProgIDEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszProgID", "lpclsid"]),
        #
        'CoFileTimeToDosDateTime': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileTime", "lpDosDate", "lpDosTime"]),
        #
        'CoDosDateTimeToFileTime': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nDosDate", "nDosTime", "lpFileTime"]),
        #
        'CoFileTimeNow': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileTime"]),
        #
        'CoRegisterChannelHook': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IChannelHook")], SimTypeInt(signed=True, label="Int32"), arg_names=["ExtensionUuid", "pChannelHook"]),
        #
        'CoTreatAsClass': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsidOld", "clsidNew"]),
        #
        'CreateDataAdviseHolder': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IDataAdviseHolder"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppDAHolder"]),
        #
        'CreateDataCache': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnkOuter", "rclsid", "iid", "ppv"]),
        #
        'CoInstall': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("uCLSSPEC", SimStruct), offset=0), SimTypePointer(SimTypeRef("QUERYCONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbc", "dwFlags", "pClassSpec", "pQuery", "pszCodeBase"]),
        #
        'BindMoniker': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pmk", "grfOpt", "iidResult", "ppvResult"]),
        #
        'CoGetObject': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("BIND_OPTS", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszName", "pBindOptions", "riid", "ppv"]),
        #
        'MkParseDisplayName': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbc", "szUserName", "pchEaten", "ppmk"]),
        #
        'MonikerRelativePathTo': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pmkSrc", "pmkDest", "ppmkRelPath", "dwReserved"]),
        #
        'MonikerCommonPrefixWith': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pmkThis", "pmkOther", "ppmkCommon"]),
        #
        'CreateBindCtx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IBindCtx"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["reserved", "ppbc"]),
        #
        'CreateGenericComposite': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pmkFirst", "pmkRest", "ppmkComposite"]),
        #
        'GetClassFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szFilename", "pclsid"]),
        #
        'CreateClassMoniker': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid", "ppmk"]),
        #
        'CreateFileMoniker': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszPathName", "ppmk"]),
        #
        'CreateItemMoniker': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszDelim", "lpszItem", "ppmk"]),
        #
        'CreateAntiMoniker': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppmk"]),
        #
        'CreatePointerMoniker': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punk", "ppmk"]),
        #
        'CreateObjrefMoniker': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punk", "ppmk"]),
        #
        'GetRunningObjectTable': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IRunningObjectTable"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["reserved", "pprot"]),
        #
        'CreateStdProgressIndicator': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IBindStatusCallback"), SimTypePointer(SimTypeBottom(label="IBindStatusCallback"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "pszTitle", "pIbscCaller", "ppIbsc"]),
        #
        'CoGetMalloc': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMalloc"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwMemContext", "ppMalloc"]),
        #
        'CoUninitialize': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'CoGetCurrentProcess': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'CoInitializeEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pvReserved", "dwCoInit"]),
        #
        'CoGetCallerTID': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwTID"]),
        #
        'CoGetCurrentLogicalThreadId': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pguid"]),
        #
        'CoGetContextToken': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pToken"]),
        #
        'CoGetApartmentType': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="APTTYPE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="APTTYPEQUALIFIER"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAptType", "pAptQualifier"]),
        #
        'CoIncrementMTAUsage': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCookie"]),
        #
        'CoDecrementMTAUsage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Cookie"]),
        #
        'CoAllowUnmarshalerCLSID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsid"]),
        #
        'CoGetObjectContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppv"]),
        #
        'CoGetClassObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid", "dwClsContext", "pvReserved", "riid", "ppv"]),
        #
        'CoRegisterClassObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="CLSCTX"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid", "pUnk", "dwClsContext", "flags", "lpdwRegister"]),
        #
        'CoRevokeClassObject': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwRegister"]),
        #
        'CoResumeClassObjects': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'CoSuspendClassObjects': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'CoAddRefServerProcess': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'CoReleaseServerProcess': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'CoGetPSClsid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "pClsid"]),
        #
        'CoRegisterPSClsid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "rclsid"]),
        #
        'CoRegisterSurrogate': SimTypeFunction([SimTypeBottom(label="ISurrogate")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSurrogate"]),
        #
        'CoDisconnectObject': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk", "dwReserved"]),
        #
        'CoLockObjectExternal': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk", "fLock", "fLastUnlockReleases"]),
        #
        'CoIsHandlerConnected': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk"]),
        #
        'CoCreateFreeThreadedMarshaler': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punkOuter", "ppunkMarshal"]),
        #
        'CoFreeUnusedLibraries': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'CoFreeUnusedLibrariesEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwUnloadDelay", "dwReserved"]),
        #
        'CoDisconnectContext': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTimeout"]),
        #
        'CoInitializeSecurity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SOLE_AUTHENTICATION_SERVICE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="RPC_C_AUTHN_LEVEL"), SimTypeInt(signed=False, label="RPC_C_IMP_LEVEL"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecDesc", "cAuthSvc", "asAuthSvc", "pReserved1", "dwAuthnLevel", "dwImpLevel", "pAuthList", "dwCapabilities", "pReserved3"]),
        #
        'CoGetCallContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppInterface"]),
        #
        'CoQueryProxyBlanket': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProxy", "pwAuthnSvc", "pAuthzSvc", "pServerPrincName", "pAuthnLevel", "pImpLevel", "pAuthInfo", "pCapabilites"]),
        #
        'CoSetProxyBlanket': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="RPC_C_AUTHN_LEVEL"), SimTypeInt(signed=False, label="RPC_C_IMP_LEVEL"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pProxy", "dwAuthnSvc", "dwAuthzSvc", "pServerPrincName", "dwAuthnLevel", "dwImpLevel", "pAuthInfo", "dwCapabilities"]),
        #
        'CoCopyProxy': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProxy", "ppCopy"]),
        #
        'CoQueryClientBlanket': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAuthnSvc", "pAuthzSvc", "pServerPrincName", "pAuthnLevel", "pImpLevel", "pPrivs", "pCapabilities"]),
        #
        'CoImpersonateClient': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'CoRevertToSelf': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'CoQueryAuthenticationServices': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SOLE_AUTHENTICATION_SERVICE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcAuthSvc", "asAuthSvc"]),
        #
        'CoSwitchCallContext': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pNewObject", "ppOldObject"]),
        #
        'CoCreateInstance': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="CLSCTX"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid", "pUnkOuter", "dwClsContext", "riid", "ppv"]),
        #
        'CoCreateInstanceEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="CLSCTX"), SimTypePointer(SimTypeRef("COSERVERINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MULTI_QI", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Clsid", "punkOuter", "dwClsCtx", "pServerInfo", "dwCount", "pResults"]),
        #
        'CoCreateInstanceFromApp': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="CLSCTX"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MULTI_QI", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Clsid", "punkOuter", "dwClsCtx", "reserved", "dwCount", "pResults"]),
        #
        'CoRegisterActivationFilter': SimTypeFunction([SimTypeBottom(label="IActivationFilter")], SimTypeInt(signed=True, label="Int32"), arg_names=["pActivationFilter"]),
        #
        'CoGetCancelObject': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwThreadId", "iid", "ppUnk"]),
        #
        'CoSetCancelObject': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk"]),
        #
        'CoCancelCall': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwThreadId", "ulTimeout"]),
        #
        'CoTestCancel': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'CoEnableCallCancellation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pReserved"]),
        #
        'CoDisableCallCancellation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pReserved"]),
        #
        'StringFromCLSID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid", "lplpsz"]),
        #
        'CLSIDFromString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpsz", "pclsid"]),
        #
        'StringFromIID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid", "lplpsz"]),
        #
        'IIDFromString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpsz", "lpiid"]),
        #
        'ProgIDFromCLSID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsid", "lplpszProgID"]),
        #
        'CLSIDFromProgID': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszProgID", "lpclsid"]),
        #
        'StringFromGUID2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["rguid", "lpsz", "cchMax"]),
        #
        'CoCreateGuid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pguid"]),
        #
        'CoWaitForMultipleHandles': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "dwTimeout", "cHandles", "pHandles", "lpdwindex"]),
        #
        'CoWaitForMultipleObjects': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "dwTimeout", "cHandles", "pHandles", "lpdwindex"]),
        #
        'CoGetTreatAsClass': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsidOld", "pClsidNew"]),
        #
        'CoInvalidateRemoteMachineBindings': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszMachineName"]),
        #
        'CoTaskMemAlloc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["cb"]),
        #
        'CoTaskMemRealloc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pv", "cb"]),
        #
        'CoTaskMemFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pv"]),
        #
        'CoRegisterDeviceCatalog': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["deviceInstanceId", "cookie"]),
        #
        'CoRevokeDeviceCatalog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cookie"]),
        #
        'HWND_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HWND_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HWND_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HWND_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HWND_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HWND_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HWND_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HWND_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'CLIPFORMAT_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'CLIPFORMAT_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'CLIPFORMAT_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'CLIPFORMAT_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HBITMAP_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HBITMAP_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HBITMAP_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HBITMAP_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HDC_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HDC_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HDC_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HDC_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HICON_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HICON_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HICON_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HICON_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'SNB_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'SNB_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'SNB_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'SNB_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'STGMEDIUM_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'STGMEDIUM_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'STGMEDIUM_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'STGMEDIUM_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'CLIPFORMAT_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'CLIPFORMAT_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'CLIPFORMAT_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'CLIPFORMAT_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HBITMAP_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HBITMAP_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HBITMAP_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HBITMAP_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HDC_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HDC_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HDC_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HDC_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HICON_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HICON_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HICON_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HICON_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'SNB_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'SNB_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'SNB_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'SNB_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'STGMEDIUM_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'STGMEDIUM_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'STGMEDIUM_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'STGMEDIUM_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'CoGetMarshalSizeMax': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pulSize", "riid", "pUnk", "dwDestContext", "pvDestContext", "mshlflags"]),
        #
        'CoMarshalInterface': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pStm", "riid", "pUnk", "dwDestContext", "pvDestContext", "mshlflags"]),
        #
        'CoUnmarshalInterface': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStm", "riid", "ppv"]),
        #
        'CoMarshalHresult': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pstm", "hresult"]),
        #
        'CoUnmarshalHresult': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstm", "phresult"]),
        #
        'CoReleaseMarshalData': SimTypeFunction([SimTypeBottom(label="IStream")], SimTypeInt(signed=True, label="Int32"), arg_names=["pStm"]),
        #
        'CoGetStandardMarshal': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMarshal"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "pUnk", "dwDestContext", "pvDestContext", "mshlflags", "ppMarshal"]),
        #
        'CoGetStdMarshalEx': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnkOuter", "smexflags", "ppUnkInner"]),
        #
        'CoMarshalInterThreadInterfaceInStream': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "pUnk", "ppStm"]),
        #
        'HACCEL_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HACCEL_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HACCEL_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HACCEL_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HGLOBAL_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HGLOBAL_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HGLOBAL_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HGLOBAL_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HMENU_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HMENU_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HMENU_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HMENU_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HACCEL_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HACCEL_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HACCEL_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HACCEL_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HGLOBAL_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HGLOBAL_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HGLOBAL_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HGLOBAL_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HMENU_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HMENU_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HMENU_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HMENU_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HPALETTE_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HPALETTE_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HPALETTE_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HPALETTE_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HPALETTE_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HPALETTE_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HPALETTE_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HPALETTE_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'CoGetInstanceFromFile': SimTypeFunction([SimTypePointer(SimTypeRef("COSERVERINFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="CLSCTX"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MULTI_QI", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pServerInfo", "pClsid", "punkOuter", "dwClsCtx", "grfMode", "pwszName", "dwCount", "pResults"]),
        #
        'CoGetInstanceFromIStorage': SimTypeFunction([SimTypePointer(SimTypeRef("COSERVERINFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="CLSCTX"), SimTypeBottom(label="IStorage"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MULTI_QI", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pServerInfo", "pClsid", "punkOuter", "dwClsCtx", "pstg", "dwCount", "pResults"]),
        #
        'StgOpenAsyncDocfileOnIFillLockBytes': SimTypeFunction([SimTypeBottom(label="IFillLockBytes"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IStorage"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pflb", "grfMode", "asyncFlags", "ppstgOpen"]),
        #
        'StgGetIFillLockBytesOnILockBytes': SimTypeFunction([SimTypeBottom(label="ILockBytes"), SimTypePointer(SimTypeBottom(label="IFillLockBytes"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pilb", "ppflb"]),
        #
        'StgGetIFillLockBytesOnFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IFillLockBytes"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwcsName", "ppflb"]),
        #
        'CreateStreamOnHGlobal': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="IStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGlobal", "fDeleteOnRelease", "ppstm"]),
        #
        'GetHGlobalFromStream': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstm", "phglobal"]),
        #
        'CoGetInterfaceAndReleaseStream': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStm", "iid", "ppv"]),
        #
        'PropVariantCopy': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarDest", "pvarSrc"]),
        #
        'PropVariantClear': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvar"]),
        #
        'FreePropVariantArray': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cVariants", "rgvars"]),
        #
        'StgCreateDocfile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="STGM"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IStorage"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwcsName", "grfMode", "reserved", "ppstgOpen"]),
        #
        'StgCreateDocfileOnILockBytes': SimTypeFunction([SimTypeBottom(label="ILockBytes"), SimTypeInt(signed=False, label="STGM"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IStorage"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plkbyt", "grfMode", "reserved", "ppstgOpen"]),
        #
        'StgOpenStorage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IStorage"), SimTypeInt(signed=False, label="STGM"), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IStorage"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwcsName", "pstgPriority", "grfMode", "snbExclude", "reserved", "ppstgOpen"]),
        #
        'StgOpenStorageOnILockBytes': SimTypeFunction([SimTypeBottom(label="ILockBytes"), SimTypeBottom(label="IStorage"), SimTypeInt(signed=False, label="STGM"), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IStorage"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plkbyt", "pstgPriority", "grfMode", "snbExclude", "reserved", "ppstgOpen"]),
        #
        'StgIsStorageFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwcsName"]),
        #
        'StgIsStorageILockBytes': SimTypeFunction([SimTypeBottom(label="ILockBytes")], SimTypeInt(signed=True, label="Int32"), arg_names=["plkbyt"]),
        #
        'StgSetTimes': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszName", "pctime", "patime", "pmtime"]),
        #
        'StgCreateStorageEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="STGM"), SimTypeInt(signed=False, label="STGFMT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("STGOPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwcsName", "grfMode", "stgfmt", "grfAttrs", "pStgOptions", "pSecurityDescriptor", "riid", "ppObjectOpen"]),
        #
        'StgOpenStorageEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="STGM"), SimTypeInt(signed=False, label="STGFMT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("STGOPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwcsName", "grfMode", "stgfmt", "grfAttrs", "pStgOptions", "pSecurityDescriptor", "riid", "ppObjectOpen"]),
        #
        'StgCreatePropStg': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IPropertyStorage"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk", "fmtid", "pclsid", "grfFlags", "dwReserved", "ppPropStg"]),
        #
        'StgOpenPropStg': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IPropertyStorage"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk", "fmtid", "grfFlags", "dwReserved", "ppPropStg"]),
        #
        'StgCreatePropSetStg': SimTypeFunction([SimTypeBottom(label="IStorage"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IPropertySetStorage"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStorage", "dwReserved", "ppPropSetStg"]),
        #
        'FmtIdToPropStgName': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfmtid", "oszName"]),
        #
        'PropStgNameToFmtId': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["oszName", "pfmtid"]),
        #
        'ReadClassStg': SimTypeFunction([SimTypeBottom(label="IStorage"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStg", "pclsid"]),
        #
        'WriteClassStg': SimTypeFunction([SimTypeBottom(label="IStorage"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStg", "rclsid"]),
        #
        'ReadClassStm': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStm", "pclsid"]),
        #
        'WriteClassStm': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStm", "rclsid"]),
        #
        'GetHGlobalFromILockBytes': SimTypeFunction([SimTypeBottom(label="ILockBytes"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["plkbyt", "phglobal"]),
        #
        'CreateILockBytesOnHGlobal': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="ILockBytes"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGlobal", "fDeleteOnRelease", "pplkbyt"]),
        #
        'GetConvertStg': SimTypeFunction([SimTypeBottom(label="IStorage")], SimTypeInt(signed=True, label="Int32"), arg_names=["pStg"]),
        #
        'StgConvertVariantToProperty': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("SERIALIZEDPROPERTYVALUE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeRef("SERIALIZEDPROPERTYVALUE", SimStruct), offset=0), arg_names=["pvar", "CodePage", "pprop", "pcb", "pid", "fReserved", "pcIndirect"]),
        #
        'StgConvertPropertyToVariant': SimTypeFunction([SimTypePointer(SimTypeRef("SERIALIZEDPROPERTYVALUE", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeBottom(label="IMemoryAllocator")], SimTypeChar(label="Byte"), arg_names=["pprop", "CodePage", "pvar", "pma"]),
        #
        'StgPropertyLengthAsVariant': SimTypeFunction([SimTypePointer(SimTypeRef("SERIALIZEDPROPERTYVALUE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16"), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pProp", "cbProp", "CodePage", "bReserved"]),
        #
        'WriteFmtUserTypeStg': SimTypeFunction([SimTypeBottom(label="IStorage"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstg", "cf", "lpszUserType"]),
        #
        'ReadFmtUserTypeStg': SimTypeFunction([SimTypeBottom(label="IStorage"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstg", "pcf", "lplpszUserType"]),
        #
        'OleConvertOLESTREAMToIStorage': SimTypeFunction([SimTypePointer(SimTypeRef("OLESTREAM", SimStruct), offset=0), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypeRef("DVTARGETDEVICE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpolestream", "pstg", "ptd"]),
        #
        'OleConvertIStorageToOLESTREAM': SimTypeFunction([SimTypeBottom(label="IStorage"), SimTypePointer(SimTypeRef("OLESTREAM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstg", "lpolestream"]),
        #
        'SetConvertStg': SimTypeFunction([SimTypeBottom(label="IStorage"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pStg", "fConvert"]),
        #
        'OleConvertIStorageToOLESTREAMEx': SimTypeFunction([SimTypeBottom(label="IStorage"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0), SimTypePointer(SimTypeRef("OLESTREAM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstg", "cfFormat", "lWidth", "lHeight", "dwSize", "pmedium", "polestm"]),
        #
        'OleConvertOLESTREAMToIStorageEx': SimTypeFunction([SimTypePointer(SimTypeRef("OLESTREAM", SimStruct), offset=0), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["polestm", "pstg", "pcfFormat", "plwWidth", "plHeight", "pdwSize", "pmedium"]),
        #
        'CoGetDefaultContext': SimTypeFunction([SimTypeInt(signed=False, label="APTTYPE"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["aptType", "riid", "ppv"]),
        #
        'OleBuildVersion': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'OleInitialize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvReserved"]),
        #
        'OleUninitialize': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'OleQueryLinkFromData': SimTypeFunction([SimTypeBottom(label="IDataObject")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcDataObject"]),
        #
        'OleQueryCreateFromData': SimTypeFunction([SimTypeBottom(label="IDataObject")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcDataObject"]),
        #
        'OleCreate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid", "riid", "renderopt", "pFormatEtc", "pClientSite", "pStg", "ppvObj"]),
        #
        'OleCreateEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="OLECREATE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IAdviseSink"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid", "riid", "dwFlags", "renderopt", "cFormats", "rgAdvf", "rgFormatEtc", "lpAdviseSink", "rgdwConnection", "pClientSite", "pStg", "ppvObj"]),
        #
        'OleCreateFromData': SimTypeFunction([SimTypeBottom(label="IDataObject"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcDataObj", "riid", "renderopt", "pFormatEtc", "pClientSite", "pStg", "ppvObj"]),
        #
        'OleCreateFromDataEx': SimTypeFunction([SimTypeBottom(label="IDataObject"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="OLECREATE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IAdviseSink"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcDataObj", "riid", "dwFlags", "renderopt", "cFormats", "rgAdvf", "rgFormatEtc", "lpAdviseSink", "rgdwConnection", "pClientSite", "pStg", "ppvObj"]),
        #
        'OleCreateLinkFromData': SimTypeFunction([SimTypeBottom(label="IDataObject"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcDataObj", "riid", "renderopt", "pFormatEtc", "pClientSite", "pStg", "ppvObj"]),
        #
        'OleCreateLinkFromDataEx': SimTypeFunction([SimTypeBottom(label="IDataObject"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="OLECREATE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IAdviseSink"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcDataObj", "riid", "dwFlags", "renderopt", "cFormats", "rgAdvf", "rgFormatEtc", "lpAdviseSink", "rgdwConnection", "pClientSite", "pStg", "ppvObj"]),
        #
        'OleCreateStaticFromData': SimTypeFunction([SimTypeBottom(label="IDataObject"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcDataObj", "iid", "renderopt", "pFormatEtc", "pClientSite", "pStg", "ppvObj"]),
        #
        'OleCreateLink': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pmkLinkSrc", "riid", "renderopt", "lpFormatEtc", "pClientSite", "pStg", "ppvObj"]),
        #
        'OleCreateLinkEx': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="OLECREATE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IAdviseSink"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pmkLinkSrc", "riid", "dwFlags", "renderopt", "cFormats", "rgAdvf", "rgFormatEtc", "lpAdviseSink", "rgdwConnection", "pClientSite", "pStg", "ppvObj"]),
        #
        'OleCreateLinkToFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszFileName", "riid", "renderopt", "lpFormatEtc", "pClientSite", "pStg", "ppvObj"]),
        #
        'OleCreateLinkToFileEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="OLECREATE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IAdviseSink"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszFileName", "riid", "dwFlags", "renderopt", "cFormats", "rgAdvf", "rgFormatEtc", "lpAdviseSink", "rgdwConnection", "pClientSite", "pStg", "ppvObj"]),
        #
        'OleCreateFromFile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid", "lpszFileName", "riid", "renderopt", "lpFormatEtc", "pClientSite", "pStg", "ppvObj"]),
        #
        'OleCreateFromFileEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="OLECREATE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IAdviseSink"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid", "lpszFileName", "riid", "dwFlags", "renderopt", "cFormats", "rgAdvf", "rgFormatEtc", "lpAdviseSink", "rgdwConnection", "pClientSite", "pStg", "ppvObj"]),
        #
        'OleLoad': SimTypeFunction([SimTypeBottom(label="IStorage"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IOleClientSite"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStg", "riid", "pClientSite", "ppvObj"]),
        #
        'OleSave': SimTypeFunction([SimTypeBottom(label="IPersistStorage"), SimTypeBottom(label="IStorage"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pPS", "pStg", "fSameAsLoad"]),
        #
        'OleLoadFromStream': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStm", "iidInterface", "ppvObj"]),
        #
        'OleSaveToStream': SimTypeFunction([SimTypeBottom(label="IPersistStream"), SimTypeBottom(label="IStream")], SimTypeInt(signed=True, label="Int32"), arg_names=["pPStm", "pStm"]),
        #
        'OleSetContainedObject': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnknown", "fContained"]),
        #
        'OleNoteObjectVisible': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnknown", "fVisible"]),
        #
        'RegisterDragDrop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IDropTarget")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pDropTarget"]),
        #
        'RevokeDragDrop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
        #
        'DoDragDrop': SimTypeFunction([SimTypeBottom(label="IDataObject"), SimTypeBottom(label="IDropSource"), SimTypeInt(signed=False, label="DROPEFFECT"), SimTypePointer(SimTypeInt(signed=False, label="DROPEFFECT"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDataObj", "pDropSource", "dwOKEffects", "pdwEffect"]),
        #
        'OleSetClipboard': SimTypeFunction([SimTypeBottom(label="IDataObject")], SimTypeInt(signed=True, label="Int32"), arg_names=["pDataObj"]),
        #
        'OleGetClipboard': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IDataObject"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppDataObj"]),
        #
        'OleGetClipboardWithEnterpriseInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IDataObject"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dataObject", "dataEnterpriseId", "sourceDescription", "targetDescription", "dataDescription"]),
        #
        'OleFlushClipboard': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'OleIsCurrentClipboard': SimTypeFunction([SimTypeBottom(label="IDataObject")], SimTypeInt(signed=True, label="Int32"), arg_names=["pDataObj"]),
        #
        'OleCreateMenuDescriptor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OLEMENUGROUPWIDTHS", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hmenuCombined", "lpMenuWidths"]),
        #
        'OleSetMenuDescriptor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IOleInPlaceFrame"), SimTypeBottom(label="IOleInPlaceActiveObject")], SimTypeInt(signed=True, label="Int32"), arg_names=["holemenu", "hwndFrame", "hwndActiveObject", "lpFrame", "lpActiveObj"]),
        #
        'OleDestroyMenuDescriptor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["holemenu"]),
        #
        'OleTranslateAccelerator': SimTypeFunction([SimTypeBottom(label="IOleInPlaceFrame"), SimTypePointer(SimTypeRef("OLEINPLACEFRAMEINFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFrame", "lpFrameInfo", "lpmsg"]),
        #
        'OleDuplicateData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CLIPBOARD_FORMAT"), SimTypeInt(signed=False, label="GLOBAL_ALLOC_FLAGS")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hSrc", "cfFormat", "uiFlags"]),
        #
        'OleDraw': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnknown", "dwAspect", "hdcDraw", "lprcBounds"]),
        #
        'OleRun': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnknown"]),
        #
        'OleIsRunning': SimTypeFunction([SimTypeBottom(label="IOleObject")], SimTypeInt(signed=True, label="Int32"), arg_names=["pObject"]),
        #
        'OleLockRunning': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnknown", "fLock", "fLastUnlockCloses"]),
        #
        'ReleaseStgMedium': SimTypeFunction([SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0"]),
        #
        'CreateOleAdviseHolder': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IOleAdviseHolder"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppOAHolder"]),
        #
        'OleCreateDefaultHandler': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsid", "pUnkOuter", "riid", "lplpObj"]),
        #
        'OleCreateEmbeddingHelper': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="EMBDHLP_FLAGS"), SimTypeBottom(label="IClassFactory"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsid", "pUnkOuter", "flags", "pCF", "riid", "lplpObj"]),
        #
        'IsAccelerator': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("MSG", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAccel", "cAccelEntries", "lpMsg", "lpwCmd"]),
        #
        'OleGetIconOfFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["lpszPath", "fUseFileAsLabel"]),
        #
        'OleGetIconOfClass': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["rclsid", "lpszLabel", "fUseTypeAsLabel"]),
        #
        'OleMetafilePictFromIconAndLabel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hIcon", "lpszLabel", "lpszSourceFile", "iIconIndex"]),
        #
        'OleRegGetUserType': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsid", "dwFormOfType", "pszUserType"]),
        #
        'OleRegGetMiscStatus': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsid", "dwAspect", "pdwStatus"]),
        #
        'OleRegEnumFormatEtc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IEnumFORMATETC"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsid", "dwDirection", "ppenum"]),
        #
        'OleRegEnumVerbs': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="IEnumOLEVERB"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsid", "ppenum"]),
        #
        'OleConvertOLESTREAMToIStorage2': SimTypeFunction([SimTypePointer(SimTypeRef("OLESTREAM", SimStruct), offset=0), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypeRef("DVTARGETDEVICE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pClsid", "szClass", "szTopicName", "szItemName", "szUNCName", "linkUpdatingOption", "pvContext"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpolestream", "pstg", "ptd", "opt", "pvCallbackContext", "pQueryConvertOLELinkCallback"]),
        #
        'OleDoAutoConvert': SimTypeFunction([SimTypeBottom(label="IStorage"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStg", "pClsidNew"]),
        #
        'OleGetAutoConvert': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsidOld", "pClsidNew"]),
        #
        'OleSetAutoConvert': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsidOld", "clsidNew"]),
        #
        'OleConvertOLESTREAMToIStorageEx2': SimTypeFunction([SimTypePointer(SimTypeRef("OLESTREAM", SimStruct), offset=0), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pClsid", "szClass", "szTopicName", "szItemName", "szUNCName", "linkUpdatingOption", "pvContext"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["polestm", "pstg", "pcfFormat", "plwWidth", "plHeight", "pdwSize", "pmedium", "opt", "pvCallbackContext", "pQueryConvertOLELinkCallback"]),
        #
        'HRGN_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HRGN_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HRGN_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HRGN_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HMONITOR_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HMONITOR_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HMONITOR_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HMONITOR_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'HMONITOR_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'HMONITOR_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HMONITOR_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'HMONITOR_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
    }

lib.set_prototypes(prototypes)
