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
lib.set_library_names("urlmon.dll")
prototypes = \
    {
        #
        'CreateUri': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="URI_CREATE_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IUri"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzURI", "dwFlags", "dwReserved", "ppURI"]),
        #
        'CreateUriWithFragment': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IUri"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzURI", "pwzFragment", "dwFlags", "dwReserved", "ppURI"]),
        #
        'CreateUriFromMultiByteString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IUri"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszANSIInputUri", "dwEncodingFlags", "dwCodePage", "dwCreateFlags", "dwReserved", "ppUri"]),
        #
        'CreateIUriBuilder': SimTypeFunction([SimTypeBottom(label="IUri"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IUriBuilder"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIUri", "dwFlags", "dwReserved", "ppIUriBuilder"]),
        #
        'CreateURLMoniker': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMkCtx", "szURL", "ppmk"]),
        #
        'CreateURLMonikerEx': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMkCtx", "szURL", "ppmk", "dwFlags"]),
        #
        'GetClassURL': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szURL", "pClsID"]),
        #
        'CreateAsyncBindCtx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback"), SimTypeBottom(label="IEnumFORMATETC"), SimTypePointer(SimTypeBottom(label="IBindCtx"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["reserved", "pBSCb", "pEFetc", "ppBC"]),
        #
        'CreateURLMonikerEx2': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypeBottom(label="IUri"), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMkCtx", "pUri", "ppmk", "dwFlags"]),
        #
        'CreateAsyncBindCtxEx': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback"), SimTypeBottom(label="IEnumFORMATETC"), SimTypePointer(SimTypeBottom(label="IBindCtx"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pbc", "dwOptions", "pBSCb", "pEnum", "ppBC", "reserved"]),
        #
        'MkParseDisplayNameEx': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbc", "szDisplayName", "pchEaten", "ppmk"]),
        #
        'RegisterBindStatusCallback': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IBindStatusCallback"), SimTypePointer(SimTypeBottom(label="IBindStatusCallback"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "pBSCb", "ppBSCBPrev", "dwReserved"]),
        #
        'RevokeBindStatusCallback': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "pBSCb"]),
        #
        'GetClassFileOrMime': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "szFilename", "pBuffer", "cbSize", "szMime", "dwReserved", "pclsid"]),
        #
        'IsValidURL': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "szURL", "dwReserved"]),
        #
        'CoGetClassObjectFromURL': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IBindCtx"), SimTypeInt(signed=False, label="CLSCTX"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rCLASSID", "szCODE", "dwFileVersionMS", "dwFileVersionLS", "szTYPE", "pBindCtx", "dwClsContext", "pvReserved", "riid", "ppv"]),
        #
        'IEInstallScope': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdwScope"]),
        #
        'FaultInIEFeature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("uCLSSPEC", SimStruct), offset=0), SimTypePointer(SimTypeRef("QUERYCONTEXT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "pClassSpec", "pQuery", "dwFlags"]),
        #
        'GetComponentIDFromCLSSPEC': SimTypeFunction([SimTypePointer(SimTypeRef("uCLSSPEC", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pClassspec", "ppszComponentID"]),
        #
        'IsAsyncMoniker': SimTypeFunction([SimTypeBottom(label="IMoniker")], SimTypeInt(signed=True, label="Int32"), arg_names=["pmk"]),
        #
        'RegisterMediaTypes': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ctypes", "rgszTypes", "rgcfTypes"]),
        #
        'FindMediaType': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rgszTypes", "rgcfTypes"]),
        #
        'CreateFormatEnumerator': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="IEnumFORMATETC"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cfmtetc", "rgfmtetc", "ppenumfmtetc"]),
        #
        'RegisterFormatEnumerator': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IEnumFORMATETC"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "pEFetc", "reserved"]),
        #
        'RevokeFormatEnumerator': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IEnumFORMATETC")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "pEFetc"]),
        #
        'RegisterMediaTypeClass': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "ctypes", "rgszTypes", "rgclsID", "reserved"]),
        #
        'FindMediaTypeClass': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "szType", "pclsID", "reserved"]),
        #
        'UrlMkSetSessionOption': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwOption", "pBuffer", "dwBufferLength", "dwReserved"]),
        #
        'UrlMkGetSessionOption': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwOption", "pBuffer", "dwBufferLength", "pdwBufferLengthOut", "dwReserved"]),
        #
        'FindMimeFromData': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBC", "pwzUrl", "pBuffer", "cbSize", "pwzMimeProposed", "dwMimeFlags", "ppwzMimeOut", "dwReserved"]),
        #
        'ObtainUserAgentString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwOption", "pszUAOut", "cbSize"]),
        #
        'CompareSecurityIds': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pbSecurityId1", "dwLen1", "pbSecurityId2", "dwLen2", "dwReserved"]),
        #
        'CompatFlagsFromClsid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pclsid", "pdwCompatFlags", "pdwMiscStatusFlags"]),
        #
        'SetAccessForIEAppContainer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="IEObjectType"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hObject", "ieObjectType", "dwAccessMask"]),
        #
        'HlinkSimpleNavigateToString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IBindStatusCallback"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["szTarget", "szLocation", "szTargetFrameName", "pUnk", "pbc", "param5", "grfHLNF", "dwReserved"]),
        #
        'HlinkSimpleNavigateToMoniker': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IBindStatusCallback"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pmkTarget", "szLocation", "szTargetFrameName", "pUnk", "pbc", "param5", "grfHLNF", "dwReserved"]),
        #
        'URLOpenStreamA': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'URLOpenStreamW': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'URLOpenPullStreamA': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'URLOpenPullStreamW': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3"]),
        #
        'URLDownloadToFileA': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'URLDownloadToFileW': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'URLDownloadToCacheFileA': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "cchFileName", "param4", "param5"]),
        #
        'URLDownloadToCacheFileW': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "cchFileName", "param4", "param5"]),
        #
        'URLOpenBlockingStreamA': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="IStream"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'URLOpenBlockingStreamW': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IStream"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindStatusCallback")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'HlinkGoBack': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk"]),
        #
        'HlinkGoForward': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk"]),
        #
        'HlinkNavigateString': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk", "szTarget"]),
        #
        'HlinkNavigateMoniker': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IMoniker")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk", "pmkTarget"]),
        #
        'CoInternetParseUrl': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="PARSEACTION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzUrl", "ParseAction", "dwFlags", "pszResult", "cchResult", "pcchResult", "dwReserved"]),
        #
        'CoInternetParseIUri': SimTypeFunction([SimTypeBottom(label="IUri"), SimTypeInt(signed=False, label="PARSEACTION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIUri", "ParseAction", "dwFlags", "pwzResult", "cchResult", "pcchResult", "dwReserved"]),
        #
        'CoInternetCombineUrl': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzBaseUrl", "pwzRelativeUrl", "dwCombineFlags", "pszResult", "cchResult", "pcchResult", "dwReserved"]),
        #
        'CoInternetCombineUrlEx': SimTypeFunction([SimTypeBottom(label="IUri"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IUri"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBaseUri", "pwzRelativeUrl", "dwCombineFlags", "ppCombinedUri", "dwReserved"]),
        #
        'CoInternetCombineIUri': SimTypeFunction([SimTypeBottom(label="IUri"), SimTypeBottom(label="IUri"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IUri"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBaseUri", "pRelativeUri", "dwCombineFlags", "ppCombinedUri", "dwReserved"]),
        #
        'CoInternetCompareUrl': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzUrl1", "pwzUrl2", "dwFlags"]),
        #
        'CoInternetGetProtocolFlags': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzUrl", "pdwFlags", "dwReserved"]),
        #
        'CoInternetQueryInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="QUERYOPTION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzUrl", "QueryOptions", "dwQueryFlags", "pvBuffer", "cbBuffer", "pcbBuffer", "dwReserved"]),
        #
        'CoInternetGetSession': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IInternetSession"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwSessionMode", "ppIInternetSession", "dwReserved"]),
        #
        'CoInternetGetSecurityUrl': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypeInt(signed=False, label="PSUACTION"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszUrl", "ppwszSecUrl", "psuAction", "dwReserved"]),
        #
        'CoInternetGetSecurityUrlEx': SimTypeFunction([SimTypeBottom(label="IUri"), SimTypePointer(SimTypeBottom(label="IUri"), offset=0), SimTypeInt(signed=False, label="PSUACTION"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUri", "ppSecUri", "psuAction", "dwReserved"]),
        #
        'CoInternetSetFeatureEnabled': SimTypeFunction([SimTypeInt(signed=False, label="INTERNETFEATURELIST"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FeatureEntry", "dwFlags", "fEnable"]),
        #
        'CoInternetIsFeatureEnabled': SimTypeFunction([SimTypeInt(signed=False, label="INTERNETFEATURELIST"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FeatureEntry", "dwFlags"]),
        #
        'CoInternetIsFeatureEnabledForUrl': SimTypeFunction([SimTypeInt(signed=False, label="INTERNETFEATURELIST"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IInternetSecurityManager")], SimTypeInt(signed=True, label="Int32"), arg_names=["FeatureEntry", "dwFlags", "szURL", "pSecMgr"]),
        #
        'CoInternetIsFeatureEnabledForIUri': SimTypeFunction([SimTypeInt(signed=False, label="INTERNETFEATURELIST"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IUri"), SimTypeBottom(label="IInternetSecurityManagerEx2")], SimTypeInt(signed=True, label="Int32"), arg_names=["FeatureEntry", "dwFlags", "pIUri", "pSecMgr"]),
        #
        'CoInternetIsFeatureZoneElevationEnabled': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IInternetSecurityManager"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["szFromURL", "szToURL", "pSecMgr", "dwFlags"]),
        #
        'CopyStgMedium': SimTypeFunction([SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0), SimTypePointer(SimTypeRef("STGMEDIUM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcstgmedSrc", "pstgmedDest"]),
        #
        'CopyBindInfo': SimTypeFunction([SimTypePointer(SimTypeRef("BINDINFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("BINDINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcbiSrc", "pbiDest"]),
        #
        'ReleaseBindInfo': SimTypeFunction([SimTypePointer(SimTypeRef("BINDINFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pbindinfo"]),
        #
        'IEGetUserPrivateNamespaceName': SimTypeFunction([], SimTypePointer(SimTypeChar(label="Char"), offset=0)),
        #
        'CoInternetCreateSecurityManager': SimTypeFunction([SimTypeBottom(label="IServiceProvider"), SimTypePointer(SimTypeBottom(label="IInternetSecurityManager"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSP", "ppSM", "dwReserved"]),
        #
        'CoInternetCreateZoneManager': SimTypeFunction([SimTypeBottom(label="IServiceProvider"), SimTypePointer(SimTypeBottom(label="IInternetZoneManager"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSP", "ppZM", "dwReserved"]),
        #
        'GetSoftwareUpdateInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SOFTDISTINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szDistUnit", "psdi"]),
        #
        'SetSoftwareUpdateAdvertisementState': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["szDistUnit", "dwAdState", "dwAdvertisedVersionMS", "dwAdvertisedVersionLS"]),
        #
        'IsLoggingEnabledA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl"]),
        #
        'IsLoggingEnabledW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszUrl"]),
        #
        'WriteHitLogging': SimTypeFunction([SimTypePointer(SimTypeRef("HIT_LOGGING_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpLogginginfo"]),
    }

lib.set_prototypes(prototypes)
