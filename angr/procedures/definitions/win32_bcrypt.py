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
lib.set_library_names("bcrypt.dll")
prototypes = \
    {
        #
        'BCryptOpenAlgorithmProvider': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["phAlgorithm", "pszAlgId", "pszImplementation", "dwFlags"]),
        #
        'BCryptEnumAlgorithms': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_OPERATION"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("BCRYPT_ALGORITHM_IDENTIFIER", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwAlgOperations", "pAlgCount", "ppAlgList", "dwFlags"]),
        #
        'BCryptEnumProviders': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("BCRYPT_PROVIDER_NAME", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszAlgId", "pImplCount", "ppImplList", "dwFlags"]),
        #
        'BCryptGetProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hObject", "pszProperty", "pbOutput", "cbOutput", "pcbResult", "dwFlags"]),
        #
        'BCryptSetProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hObject", "pszProperty", "pbInput", "cbInput", "dwFlags"]),
        #
        'BCryptCloseAlgorithmProvider': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAlgorithm", "dwFlags"]),
        #
        'BCryptFreeBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pvBuffer"]),
        #
        'BCryptGenerateSymmetricKey': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAlgorithm", "phKey", "pbKeyObject", "cbKeyObject", "pbSecret", "cbSecret", "dwFlags"]),
        #
        'BCryptGenerateKeyPair': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAlgorithm", "phKey", "dwLength", "dwFlags"]),
        #
        'BCryptEncrypt': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="BCRYPT_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "pbInput", "cbInput", "pPaddingInfo", "pbIV", "cbIV", "pbOutput", "cbOutput", "pcbResult", "dwFlags"]),
        #
        'BCryptDecrypt': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="BCRYPT_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "pbInput", "cbInput", "pPaddingInfo", "pbIV", "cbIV", "pbOutput", "cbOutput", "pcbResult", "dwFlags"]),
        #
        'BCryptExportKey': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "hExportKey", "pszBlobType", "pbOutput", "cbOutput", "pcbResult", "dwFlags"]),
        #
        'BCryptImportKey': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAlgorithm", "hImportKey", "pszBlobType", "phKey", "pbKeyObject", "cbKeyObject", "pbInput", "cbInput", "dwFlags"]),
        #
        'BCryptImportKeyPair': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAlgorithm", "hImportKey", "pszBlobType", "phKey", "pbInput", "cbInput", "dwFlags"]),
        #
        'BCryptDuplicateKey': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "phNewKey", "pbKeyObject", "cbKeyObject", "dwFlags"]),
        #
        'BCryptFinalizeKeyPair': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "dwFlags"]),
        #
        'BCryptDestroyKey': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey"]),
        #
        'BCryptDestroySecret': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSecret"]),
        #
        'BCryptSignHash': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="BCRYPT_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "pPaddingInfo", "pbInput", "cbInput", "pbOutput", "cbOutput", "pcbResult", "dwFlags"]),
        #
        'BCryptVerifySignature': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="BCRYPT_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "pPaddingInfo", "pbHash", "cbHash", "pbSignature", "cbSignature", "dwFlags"]),
        #
        'BCryptSecretAgreement': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPrivKey", "hPubKey", "phAgreedSecret", "dwFlags"]),
        #
        'BCryptDeriveKey': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("BCryptBufferDesc", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hSharedSecret", "pwszKDF", "pParameterList", "pbDerivedKey", "cbDerivedKey", "pcbResult", "dwFlags"]),
        #
        'BCryptKeyDerivation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("BCryptBufferDesc", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKey", "pParameterList", "pbDerivedKey", "cbDerivedKey", "pcbResult", "dwFlags"]),
        #
        'BCryptCreateHash': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAlgorithm", "phHash", "pbHashObject", "cbHashObject", "pbSecret", "cbSecret", "dwFlags"]),
        #
        'BCryptHashData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash", "pbInput", "cbInput", "dwFlags"]),
        #
        'BCryptFinishHash': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash", "pbOutput", "cbOutput", "dwFlags"]),
        #
        'BCryptCreateMultiHash': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAlgorithm", "phHash", "nHashes", "pbHashObject", "cbHashObject", "pbSecret", "cbSecret", "dwFlags"]),
        #
        'BCryptProcessMultiOperations': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="BCRYPT_MULTI_OPERATION_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hObject", "operationType", "pOperations", "cbOperations", "dwFlags"]),
        #
        'BCryptDuplicateHash': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash", "phNewHash", "pbHashObject", "cbHashObject", "dwFlags"]),
        #
        'BCryptDestroyHash': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash"]),
        #
        'BCryptHash': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAlgorithm", "pbSecret", "cbSecret", "pbInput", "cbInput", "pbOutput", "cbOutput"]),
        #
        'BCryptGenRandom': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="BCRYPTGENRANDOM_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAlgorithm", "pbBuffer", "cbBuffer", "dwFlags"]),
        #
        'BCryptDeriveKeyCapi': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hHash", "hTargetAlg", "pbDerivedKey", "cbDerivedKey", "dwFlags"]),
        #
        'BCryptDeriveKeyPBKDF2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPrf", "pbPassword", "cbPassword", "pbSalt", "cbSalt", "cIterations", "pbDerivedKey", "cbDerivedKey", "dwFlags"]),
        #
        'BCryptQueryProviderRegistration': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="BCRYPT_QUERY_PROVIDER_MODE"), SimTypeInt(signed=False, label="BCRYPT_INTERFACE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_PROVIDER_REG", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszProvider", "dwMode", "dwInterface", "pcbBuffer", "ppBuffer"]),
        #
        'BCryptEnumRegisteredProviders': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_PROVIDERS", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcbBuffer", "ppBuffer"]),
        #
        'BCryptCreateContext': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_TABLE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPT_CONTEXT_CONFIG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTable", "pszContext", "pConfig"]),
        #
        'BCryptDeleteContext': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_TABLE"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTable", "pszContext"]),
        #
        'BCryptEnumContexts': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_TABLE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_CONTEXTS", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTable", "pcbBuffer", "ppBuffer"]),
        #
        'BCryptConfigureContext': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_TABLE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPT_CONTEXT_CONFIG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTable", "pszContext", "pConfig"]),
        #
        'BCryptQueryContextConfiguration': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_TABLE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_CONTEXT_CONFIG", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTable", "pszContext", "pcbBuffer", "ppBuffer"]),
        #
        'BCryptAddContextFunction': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_TABLE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="BCRYPT_INTERFACE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTable", "pszContext", "dwInterface", "pszFunction", "dwPosition"]),
        #
        'BCryptRemoveContextFunction': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_TABLE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="BCRYPT_INTERFACE"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTable", "pszContext", "dwInterface", "pszFunction"]),
        #
        'BCryptEnumContextFunctions': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_TABLE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="BCRYPT_INTERFACE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_CONTEXT_FUNCTIONS", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTable", "pszContext", "dwInterface", "pcbBuffer", "ppBuffer"]),
        #
        'BCryptConfigureContextFunction': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_TABLE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="BCRYPT_INTERFACE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPT_CONTEXT_FUNCTION_CONFIG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTable", "pszContext", "dwInterface", "pszFunction", "pConfig"]),
        #
        'BCryptQueryContextFunctionConfiguration': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_TABLE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="BCRYPT_INTERFACE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_CONTEXT_FUNCTION_CONFIG", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTable", "pszContext", "dwInterface", "pszFunction", "pcbBuffer", "ppBuffer"]),
        #
        'BCryptEnumContextFunctionProviders': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_TABLE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="BCRYPT_INTERFACE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_CONTEXT_FUNCTION_PROVIDERS", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTable", "pszContext", "dwInterface", "pszFunction", "pcbBuffer", "ppBuffer"]),
        #
        'BCryptSetContextFunctionProperty': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_TABLE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="BCRYPT_INTERFACE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTable", "pszContext", "dwInterface", "pszFunction", "pszProperty", "cbValue", "pbValue"]),
        #
        'BCryptQueryContextFunctionProperty': SimTypeFunction([SimTypeInt(signed=False, label="BCRYPT_TABLE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="BCRYPT_INTERFACE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwTable", "pszContext", "dwInterface", "pszFunction", "pszProperty", "pcbValue", "ppbValue"]),
        #
        'BCryptRegisterConfigChangeNotify': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phEvent"]),
        #
        'BCryptUnregisterConfigChangeNotify': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent"]),
        #
        'BCryptResolveProviders': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="BCRYPT_QUERY_PROVIDER_MODE"), SimTypeInt(signed=False, label="BCRYPT_RESOLVE_PROVIDERS_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_PROVIDER_REFS", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszContext", "dwInterface", "pszFunction", "pszProvider", "dwMode", "dwFlags", "pcbBuffer", "ppBuffer"]),
        #
        'BCryptGetFipsAlgorithmMode': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfEnabled"]),
    }

lib.set_prototypes(prototypes)
