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
lib.set_library_names("wintrust.dll")
prototypes = \
    {
        #
        'CryptCATOpen': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="CRYPTCAT_OPEN_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="CRYPTCAT_VERSION"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pwszFileName", "fdwOpenFlags", "hProv", "dwPublicVersion", "dwEncodingType"]),
        #
        'CryptCATClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCatalog"]),
        #
        'CryptCATStoreFromHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeRef("CRYPTCATSTORE", SimStruct), offset=0), arg_names=["hCatalog"]),
        #
        'CryptCATHandleFromStore': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPTCATSTORE", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pCatStore"]),
        #
        'CryptCATPersistStore': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCatalog"]),
        #
        'CryptCATGetCatAttrInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATATTRIBUTE", SimStruct), offset=0), arg_names=["hCatalog", "pwszReferenceTag"]),
        #
        'CryptCATPutCatAttrInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATATTRIBUTE", SimStruct), offset=0), arg_names=["hCatalog", "pwszReferenceTag", "dwAttrTypeAndAction", "cbData", "pbData"]),
        #
        'CryptCATEnumerateCatAttr': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CRYPTCATATTRIBUTE", SimStruct), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATATTRIBUTE", SimStruct), offset=0), arg_names=["hCatalog", "pPrevAttr"]),
        #
        'CryptCATGetMemberInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATMEMBER", SimStruct), offset=0), arg_names=["hCatalog", "pwszReferenceTag"]),
        #
        'CryptCATAllocSortedMemberInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATMEMBER", SimStruct), offset=0), arg_names=["hCatalog", "pwszReferenceTag"]),
        #
        'CryptCATFreeSortedMemberInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CRYPTCATMEMBER", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["hCatalog", "pCatMember"]),
        #
        'CryptCATGetAttrInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CRYPTCATMEMBER", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATATTRIBUTE", SimStruct), offset=0), arg_names=["hCatalog", "pCatMember", "pwszReferenceTag"]),
        #
        'CryptCATPutMemberInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATMEMBER", SimStruct), offset=0), arg_names=["hCatalog", "pwszFileName", "pwszReferenceTag", "pgSubjectType", "dwCertVersion", "cbSIPIndirectData", "pbSIPIndirectData"]),
        #
        'CryptCATPutAttrInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CRYPTCATMEMBER", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATATTRIBUTE", SimStruct), offset=0), arg_names=["hCatalog", "pCatMember", "pwszReferenceTag", "dwAttrTypeAndAction", "cbData", "pbData"]),
        #
        'CryptCATEnumerateMember': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CRYPTCATMEMBER", SimStruct), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATMEMBER", SimStruct), offset=0), arg_names=["hCatalog", "pPrevMember"]),
        #
        'CryptCATEnumerateAttr': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CRYPTCATMEMBER", SimStruct), offset=0), SimTypePointer(SimTypeRef("CRYPTCATATTRIBUTE", SimStruct), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATATTRIBUTE", SimStruct), offset=0), arg_names=["hCatalog", "pCatMember", "pPrevAttr"]),
        #
        'CryptCATCDFOpen': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwErrorArea", "dwLocalError", "pwszLine"]), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATCDF", SimStruct), offset=0), arg_names=["pwszFilePath", "pfnParseError"]),
        #
        'CryptCATCDFClose': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPTCATCDF", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCDF"]),
        #
        'CryptCATCDFEnumCatAttributes': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPTCATCDF", SimStruct), offset=0), SimTypePointer(SimTypeRef("CRYPTCATATTRIBUTE", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwErrorArea", "dwLocalError", "pwszLine"]), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATATTRIBUTE", SimStruct), offset=0), arg_names=["pCDF", "pPrevAttr", "pfnParseError"]),
        #
        'CryptCATCDFEnumMembers': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPTCATCDF", SimStruct), offset=0), SimTypePointer(SimTypeRef("CRYPTCATMEMBER", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwErrorArea", "dwLocalError", "pwszLine"]), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATMEMBER", SimStruct), offset=0), arg_names=["pCDF", "pPrevMember", "pfnParseError"]),
        #
        'CryptCATCDFEnumAttributes': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPTCATCDF", SimStruct), offset=0), SimTypePointer(SimTypeRef("CRYPTCATMEMBER", SimStruct), offset=0), SimTypePointer(SimTypeRef("CRYPTCATATTRIBUTE", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwErrorArea", "dwLocalError", "pwszLine"]), offset=0)], SimTypePointer(SimTypeRef("CRYPTCATATTRIBUTE", SimStruct), offset=0), arg_names=["pCDF", "pMember", "pPrevAttr", "pfnParseError"]),
        #
        'IsCatalogFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "pwszFileName"]),
        #
        'CryptCATAdminAcquireContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phCatAdmin", "pgSubsystem", "dwFlags"]),
        #
        'CryptCATAdminAcquireContext2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CERT_STRONG_SIGN_PARA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phCatAdmin", "pgSubsystem", "pwszHashAlgorithm", "pStrongHashPolicy", "dwFlags"]),
        #
        'CryptCATAdminReleaseContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCatAdmin", "dwFlags"]),
        #
        'CryptCATAdminReleaseCatalogContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCatAdmin", "hCatInfo", "dwFlags"]),
        #
        'CryptCATAdminEnumCatalogFromHash': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hCatAdmin", "pbHash", "cbHash", "dwFlags", "phPrevCatInfo"]),
        #
        'CryptCATAdminCalcHashFromFileHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hFile", "pcbHash", "pbHash", "dwFlags"]),
        #
        'CryptCATAdminCalcHashFromFileHandle2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCatAdmin", "hFile", "pcbHash", "pbHash", "dwFlags"]),
        #
        'CryptCATAdminAddCatalog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hCatAdmin", "pwszCatalogFile", "pwszSelectBaseName", "dwFlags"]),
        #
        'CryptCATAdminRemoveCatalog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCatAdmin", "pwszCatalogFile", "dwFlags"]),
        #
        'CryptCATCatalogInfoFromContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CATALOG_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCatInfo", "psCatInfo", "dwFlags"]),
        #
        'CryptCATAdminResolveCatalogPath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CATALOG_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCatAdmin", "pwszCatalogFile", "psCatInfo", "dwFlags"]),
        #
        'CryptCATAdminPauseServiceForBackup': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "fResume"]),
        #
        'FindCertsByIssuer': SimTypeFunction([SimTypePointer(SimTypeRef("CERT_CHAIN", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pCertChains", "pcbCertChains", "pcCertChains", "pbEncodedIssuerName", "cbEncodedIssuerName", "pwszPurpose", "dwKeySpec"]),
        #
        'CryptSIPGetSignedDataMsg': SimTypeFunction([SimTypePointer(SimTypeRef("SIP_SUBJECTINFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="CERT_QUERY_ENCODING_TYPE"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSubjectInfo", "pdwEncodingType", "dwIndex", "pcbSignedDataMsg", "pbSignedDataMsg"]),
        #
        'CryptSIPPutSignedDataMsg': SimTypeFunction([SimTypePointer(SimTypeRef("SIP_SUBJECTINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="CERT_QUERY_ENCODING_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSubjectInfo", "dwEncodingType", "pdwIndex", "cbSignedDataMsg", "pbSignedDataMsg"]),
        #
        'CryptSIPCreateIndirectData': SimTypeFunction([SimTypePointer(SimTypeRef("SIP_SUBJECTINFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("SIP_INDIRECT_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSubjectInfo", "pcbIndirectData", "pIndirectData"]),
        #
        'CryptSIPVerifyIndirectData': SimTypeFunction([SimTypePointer(SimTypeRef("SIP_SUBJECTINFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIP_INDIRECT_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSubjectInfo", "pIndirectData"]),
        #
        'CryptSIPRemoveSignedDataMsg': SimTypeFunction([SimTypePointer(SimTypeRef("SIP_SUBJECTINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSubjectInfo", "dwIndex"]),
        #
        'CryptSIPGetCaps': SimTypeFunction([SimTypePointer(SimTypeRef("SIP_SUBJECTINFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIP_CAP_SET_V3", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSubjInfo", "pCaps"]),
        #
        'CryptSIPGetSealedDigest': SimTypeFunction([SimTypePointer(SimTypeRef("SIP_SUBJECTINFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSubjectInfo", "pSig", "dwSig", "pbDigest", "pcbDigest"]),
        #
        'WinVerifyTrust': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pgActionID", "pWVTData"]),
        #
        'WinVerifyTrustEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("WINTRUST_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pgActionID", "pWinTrustData"]),
        #
        'WintrustGetRegPolicyFlags': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="WINTRUST_POLICY_FLAGS"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pdwPolicyFlags"]),
        #
        'WintrustSetRegPolicyFlags': SimTypeFunction([SimTypeInt(signed=False, label="WINTRUST_POLICY_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwPolicyFlags"]),
        #
        'WintrustAddActionID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CRYPT_REGISTER_ACTIONID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pgActionID", "fdwFlags", "psProvInfo"]),
        #
        'WintrustRemoveActionID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pgActionID"]),
        #
        'WintrustLoadFunctionPointers': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("CRYPT_PROVIDER_FUNCTIONS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pgActionID", "pPfns"]),
        #
        'WintrustAddDefaultForUsage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("CRYPT_PROVIDER_REGDEFUSAGE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUsageOID", "psDefUsage"]),
        #
        'WintrustGetDefaultForUsage': SimTypeFunction([SimTypeInt(signed=False, label="WINTRUST_GET_DEFAULT_FOR_USAGE_ACTION"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("CRYPT_PROVIDER_DEFUSAGE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwAction", "pszUsageOID", "psUsage"]),
        #
        'WTHelperGetProvSignerFromChain': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPT_PROVIDER_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("CRYPT_PROVIDER_SGNR", SimStruct), offset=0), arg_names=["pProvData", "idxSigner", "fCounterSigner", "idxCounterSigner"]),
        #
        'WTHelperGetProvCertFromChain': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPT_PROVIDER_SGNR", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("CRYPT_PROVIDER_CERT", SimStruct), offset=0), arg_names=["pSgnr", "idxCert"]),
        #
        'WTHelperProvDataFromStateData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeRef("CRYPT_PROVIDER_DATA", SimStruct), offset=0), arg_names=["hStateData"]),
        #
        'WTHelperGetProvPrivateDataFromChain': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPT_PROVIDER_DATA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypePointer(SimTypeRef("CRYPT_PROVIDER_PRIVDATA", SimStruct), offset=0), arg_names=["pProvData", "pgProviderID"]),
        #
        'WTHelperCertIsSelfSigned': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CERT_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwEncoding", "pCert"]),
        #
        'WTHelperCertCheckValidSignature': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPT_PROVIDER_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProvData"]),
        #
        'OpenPersonalTrustDBDialogEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "dwFlags", "pvReserved"]),
        #
        'OpenPersonalTrustDBDialog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent"]),
        #
        'WintrustSetDefaultIncludePEPageHashes': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["fIncludePEPageHashes"]),
    }

lib.set_prototypes(prototypes)
