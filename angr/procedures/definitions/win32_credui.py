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
lib.set_library_names("credui.dll")
prototypes = \
    {
        #
        'SspiPromptForCredentialsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszTargetName", "pUiInfo", "dwAuthError", "pszPackage", "pInputAuthIdentity", "ppAuthIdentity", "pfSave", "dwFlags"]),
        #
        'SspiPromptForCredentialsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszTargetName", "pUiInfo", "dwAuthError", "pszPackage", "pInputAuthIdentity", "ppAuthIdentity", "pfSave", "dwFlags"]),
        #
        'SspiIsPromptingNeeded': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["ErrorOrNtStatus"]),
        #
        'CredUnPackAuthenticationBufferW': SimTypeFunction([SimTypeInt(signed=False, label="CRED_PACK_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pAuthBuffer", "cbAuthBuffer", "pszUserName", "pcchMaxUserName", "pszDomainName", "pcchMaxDomainName", "pszPassword", "pcchMaxPassword"]),
        #
        'CredUnPackAuthenticationBufferA': SimTypeFunction([SimTypeInt(signed=False, label="CRED_PACK_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pAuthBuffer", "cbAuthBuffer", "pszUserName", "pcchlMaxUserName", "pszDomainName", "pcchMaxDomainName", "pszPassword", "pcchMaxPassword"]),
        #
        'CredPackAuthenticationBufferW': SimTypeFunction([SimTypeInt(signed=False, label="CRED_PACK_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pszUserName", "pszPassword", "pPackedCredentials", "pcbPackedCredentials"]),
        #
        'CredPackAuthenticationBufferA': SimTypeFunction([SimTypeInt(signed=False, label="CRED_PACK_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pszUserName", "pszPassword", "pPackedCredentials", "pcbPackedCredentials"]),
        #
        'CredUIPromptForCredentialsW': SimTypeFunction([SimTypePointer(SimTypeRef("CREDUI_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="CREDUI_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pUiInfo", "pszTargetName", "pContext", "dwAuthError", "pszUserName", "ulUserNameBufferSize", "pszPassword", "ulPasswordBufferSize", "save", "dwFlags"]),
        #
        'CredUIPromptForCredentialsA': SimTypeFunction([SimTypePointer(SimTypeRef("CREDUI_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="CREDUI_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pUiInfo", "pszTargetName", "pContext", "dwAuthError", "pszUserName", "ulUserNameBufferSize", "pszPassword", "ulPasswordBufferSize", "save", "dwFlags"]),
        #
        'CredUIPromptForWindowsCredentialsW': SimTypeFunction([SimTypePointer(SimTypeRef("CREDUI_INFOW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="CREDUIWIN_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pUiInfo", "dwAuthError", "pulAuthPackage", "pvInAuthBuffer", "ulInAuthBufferSize", "ppvOutAuthBuffer", "pulOutAuthBufferSize", "pfSave", "dwFlags"]),
        #
        'CredUIPromptForWindowsCredentialsA': SimTypeFunction([SimTypePointer(SimTypeRef("CREDUI_INFOA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="CREDUIWIN_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pUiInfo", "dwAuthError", "pulAuthPackage", "pvInAuthBuffer", "ulInAuthBufferSize", "ppvOutAuthBuffer", "pulOutAuthBufferSize", "pfSave", "dwFlags"]),
        #
        'CredUIParseUserNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["UserName", "user", "userBufferSize", "domain", "domainBufferSize"]),
        #
        'CredUIParseUserNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["userName", "user", "userBufferSize", "domain", "domainBufferSize"]),
        #
        'CredUICmdLinePromptForCredentialsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="CREDUI_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszTargetName", "pContext", "dwAuthError", "UserName", "ulUserBufferSize", "pszPassword", "ulPasswordBufferSize", "pfSave", "dwFlags"]),
        #
        'CredUICmdLinePromptForCredentialsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="CREDUI_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszTargetName", "pContext", "dwAuthError", "UserName", "ulUserBufferSize", "pszPassword", "ulPasswordBufferSize", "pfSave", "dwFlags"]),
        #
        'CredUIConfirmCredentialsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszTargetName", "bConfirm"]),
        #
        'CredUIConfirmCredentialsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszTargetName", "bConfirm"]),
        #
        'CredUIStoreSSOCredW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszRealm", "pszUsername", "pszPassword", "bPersist"]),
        #
        'CredUIReadSSOCredW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszRealm", "ppszUsername"]),
    }

lib.set_prototypes(prototypes)
