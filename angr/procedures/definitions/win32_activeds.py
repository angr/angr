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
lib.set_library_names("activeds.dll")
prototypes = \
    {
        #
        'ADsGetObject': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszPathName", "riid", "ppObject"]),
        #
        'ADsBuildEnumerator': SimTypeFunction([SimTypeBottom(label="IADsContainer"), SimTypePointer(SimTypeBottom(label="IEnumVARIANT"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pADsContainer", "ppEnumVariant"]),
        #
        'ADsFreeEnumerator': SimTypeFunction([SimTypeBottom(label="IEnumVARIANT")], SimTypeInt(signed=True, label="Int32"), arg_names=["pEnumVariant"]),
        #
        'ADsEnumerateNext': SimTypeFunction([SimTypeBottom(label="IEnumVARIANT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pEnumVariant", "cElements", "pvar", "pcElementsFetched"]),
        #
        'ADsBuildVarArrayStr': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lppPathNames", "dwPathNames", "pVar"]),
        #
        'ADsBuildVarArrayInt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwObjectTypes", "dwObjectTypes", "pVar"]),
        #
        'ADsOpenObject': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="ADS_AUTHENTICATION_ENUM"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszPathName", "lpszUserName", "lpszPassword", "dwReserved", "riid", "ppObject"]),
        #
        'ADsGetLastError': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpError", "lpErrorBuf", "dwErrorBufLen", "lpNameBuf", "dwNameBufLen"]),
        #
        'ADsSetLastError': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwErr", "pszError", "pszProvider"]),
        #
        'AllocADsMem': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["cb"]),
        #
        'FreeADsMem': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMem"]),
        #
        'ReallocADsMem': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pOldMem", "cbOld", "cbNew"]),
        #
        'AllocADsStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pStr"]),
        #
        'FreeADsStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStr"]),
        #
        'ReallocADsStr': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppStr", "pStr"]),
        #
        'ADsEncodeBinaryData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbSrcData", "dwSrcLen", "ppszDestData"]),
        #
        'ADsDecodeBinaryData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szSrcData", "ppbDestData", "pdwDestLen"]),
        #
        'PropVariantToAdsType': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("ADSVALUE", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pVariant", "dwNumVariant", "ppAdsValues", "pdwNumValues"]),
        #
        'AdsTypeToPropVariant': SimTypeFunction([SimTypePointer(SimTypeRef("ADSVALUE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdsValues", "dwNumValues", "pVariant"]),
        #
        'AdsFreeAdsValues': SimTypeFunction([SimTypePointer(SimTypeRef("ADSVALUE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pAdsValues", "dwNumValues"]),
        #
        'BinarySDToSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSecurityDescriptor", "pVarsec", "pszServerName", "userName", "passWord", "dwFlags"]),
        #
        'SecurityDescriptorToBinarySD': SimTypeFunction([SimTypeRef("VARIANT", SimStruct), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["vVarSecDes", "ppSecurityDescriptor", "pdwSDLength", "pszServerName", "userName", "passWord", "dwFlags"]),
    }

lib.set_prototypes(prototypes)
