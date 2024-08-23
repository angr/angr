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
lib.set_library_names("cryptxml.dll")
prototypes = \
    {
        #
        'CryptXmlClose': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCryptXml"]),
        #
        'CryptXmlGetTransforms': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_XML_TRANSFORM_CHAIN_CONFIG", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppConfig"]),
        #
        'CryptXmlOpenToEncode': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPT_XML_TRANSFORM_CHAIN_CONFIG", SimStruct), offset=0), SimTypeInt(signed=False, label="CRYPT_XML_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPT_XML_PROPERTY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CRYPT_XML_BLOB", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pConfig", "dwFlags", "wszId", "rgProperty", "cProperty", "pEncoded", "phSignature"]),
        #
        'CryptXmlOpenToDecode': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPT_XML_TRANSFORM_CHAIN_CONFIG", SimStruct), offset=0), SimTypeInt(signed=False, label="CRYPT_XML_FLAGS"), SimTypePointer(SimTypeRef("CRYPT_XML_PROPERTY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CRYPT_XML_BLOB", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pConfig", "dwFlags", "rgProperty", "cProperty", "pEncoded", "phCryptXml"]),
        #
        'CryptXmlAddObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CRYPT_XML_PROPERTY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CRYPT_XML_BLOB", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_XML_OBJECT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSignatureOrObject", "dwFlags", "rgProperty", "cProperty", "pEncoded", "ppObject"]),
        #
        'CryptXmlCreateReference': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPT_XML_ALGORITHM", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CRYPT_XML_ALGORITHM", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCryptXml", "dwFlags", "wszId", "wszURI", "wszType", "pDigestMethod", "cTransform", "rgTransform", "phReference"]),
        #
        'CryptXmlDigestReference': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CRYPT_XML_DATA_PROVIDER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hReference", "dwFlags", "pDataProviderIn"]),
        #
        'CryptXmlSetHMACSecret': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hSignature", "pbSecret", "cbSecret"]),
        #
        'CryptXmlSign': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="CERT_KEY_SPEC"), SimTypeInt(signed=False, label="CRYPT_XML_FLAGS"), SimTypeInt(signed=False, label="CRYPT_XML_KEYINFO_SPEC"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CRYPT_XML_ALGORITHM", SimStruct), offset=0), SimTypePointer(SimTypeRef("CRYPT_XML_ALGORITHM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSignature", "hKey", "dwKeySpec", "dwFlags", "dwKeyInfoSpec", "pvKeyInfoSpec", "pSignatureMethod", "pCanonicalization"]),
        #
        'CryptXmlImportPublicKey': SimTypeFunction([SimTypeInt(signed=False, label="CRYPT_XML_FLAGS"), SimTypePointer(SimTypeRef("CRYPT_XML_KEY_VALUE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pKeyValue", "phKey"]),
        #
        'CryptXmlVerifySignature': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="CRYPT_XML_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["hSignature", "hKey", "dwFlags"]),
        #
        'CryptXmlGetDocContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_XML_DOC_CTXT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCryptXml", "ppStruct"]),
        #
        'CryptXmlGetSignature': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_XML_SIGNATURE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCryptXml", "ppStruct"]),
        #
        'CryptXmlGetReference': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_XML_REFERENCE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCryptXml", "ppStruct"]),
        #
        'CryptXmlGetStatus': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CRYPT_XML_STATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCryptXml", "pStatus"]),
        #
        'CryptXmlEncode': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="CRYPT_XML_CHARSET"), SimTypePointer(SimTypeRef("CRYPT_XML_PROPERTY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pvCallbackState", "pbData", "cbData"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCryptXml", "dwCharset", "rgProperty", "cProperty", "pvCallbackState", "pfnWrite"]),
        #
        'CryptXmlGetAlgorithmInfo': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPT_XML_ALGORITHM", SimStruct), offset=0), SimTypeInt(signed=False, label="CRYPT_XML_FLAGS"), SimTypePointer(SimTypePointer(SimTypeRef("CRYPT_XML_ALGORITHM_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pXmlAlgorithm", "dwFlags", "ppAlgInfo"]),
        #
        'CryptXmlFindAlgorithmInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("CRYPT_XML_ALGORITHM_INFO", SimStruct), offset=0), arg_names=["dwFindByType", "pvFindBy", "dwGroupId", "dwFlags"]),
        #
        'CryptXmlEnumAlgorithmInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("CRYPT_XML_ALGORITHM_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pInfo", "pvArg"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwGroupId", "dwFlags", "pvArg", "pfnEnumAlgInfo"]),
    }

lib.set_prototypes(prototypes)
