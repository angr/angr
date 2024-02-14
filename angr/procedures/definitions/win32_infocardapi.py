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
lib.set_library_names("infocardapi.dll")
prototypes = \
    {
        #
        'GetToken': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POLICY_ELEMENT", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("GENERIC_XML_TOKEN", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cPolicyChain", "pPolicyChain", "securityToken", "phProofTokenCrypto"]),
        #
        'ManageCardSpace': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'ImportInformationCard': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fileName"]),
        #
        'Encrypt': SimTypeFunction([SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCrypto", "fOAEP", "cbInData", "pInData", "pcbOutData", "ppOutData"]),
        #
        'Decrypt': SimTypeFunction([SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCrypto", "fOAEP", "cbInData", "pInData", "pcbOutData", "ppOutData"]),
        #
        'SignHash': SimTypeFunction([SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCrypto", "cbHash", "pHash", "hashAlgOid", "pcbSig", "ppSig"]),
        #
        'VerifyHash': SimTypeFunction([SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCrypto", "cbHash", "pHash", "hashAlgOid", "cbSig", "pSig", "pfVerified"]),
        #
        'GetCryptoTransform': SimTypeFunction([SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="PaddingMode"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="Direction"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSymmetricCrypto", "mode", "padding", "feedbackSize", "direction", "cbIV", "pIV", "pphTransform"]),
        #
        'GetKeyedHash': SimTypeFunction([SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSymmetricCrypto", "pphHash"]),
        #
        'TransformBlock': SimTypeFunction([SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCrypto", "cbInData", "pInData", "pcbOutData", "ppOutData"]),
        #
        'TransformFinalBlock': SimTypeFunction([SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCrypto", "cbInData", "pInData", "pcbOutData", "ppOutData"]),
        #
        'HashCore': SimTypeFunction([SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCrypto", "cbInData", "pInData"]),
        #
        'HashFinal': SimTypeFunction([SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCrypto", "cbInData", "pInData", "pcbOutData", "ppOutData"]),
        #
        'FreeToken': SimTypeFunction([SimTypePointer(SimTypeRef("GENERIC_XML_TOKEN", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAllocMemory"]),
        #
        'CloseCryptoHandle': SimTypeFunction([SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCrypto"]),
        #
        'GenerateDerivedKey': SimTypeFunction([SimTypePointer(SimTypeRef("INFORMATIONCARD_CRYPTO_HANDLE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCrypto", "cbLabel", "pLabel", "cbNonce", "pNonce", "derivedKeyLength", "offset", "algId", "pcbKey", "ppKey"]),
        #
        'GetBrowserToken': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwParamType", "pParam", "pcbToken", "ppToken"]),
    }

lib.set_prototypes(prototypes)
