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
lib.set_library_names("cryptui.dll")
prototypes = \
    {
        #
        'CryptUIDlgViewContext': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwContextType", "pvContext", "hwnd", "pwszTitle", "dwFlags", "pvReserved"]),
        #
        'CryptUIDlgSelectCertificateFromStore': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), arg_names=["hCertStore", "hwnd", "pwszTitle", "pwszDisplayString", "dwDontUseColumn", "dwFlags", "pvReserved"]),
        #
        'CertSelectionGetSerializedBlob': SimTypeFunction([SimTypePointer(SimTypeRef("CERT_SELECTUI_INPUT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcsi", "ppOutBuffer", "pulOutBufferSize"]),
        #
        'CryptUIDlgCertMgr': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPTUI_CERT_MGR_STRUCT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCryptUICertMgr"]),
        #
        'CryptUIWizDigitalSign': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPTUI_WIZ_DIGITAL_SIGN_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "hwndParent", "pwszWizardTitle", "pDigitalSignInfo", "ppSignContext"]),
        #
        'CryptUIWizFreeDigitalSignContext': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSignContext"]),
        #
        'CryptUIDlgViewCertificateW': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPTUI_VIEWCERTIFICATE_STRUCTW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCertViewInfo", "pfPropertiesChanged"]),
        #
        'CryptUIDlgViewCertificateA': SimTypeFunction([SimTypePointer(SimTypeRef("CRYPTUI_VIEWCERTIFICATE_STRUCTA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCertViewInfo", "pfPropertiesChanged"]),
        #
        'CryptUIWizExport': SimTypeFunction([SimTypeInt(signed=False, label="CRYPTUI_WIZ_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPTUI_WIZ_EXPORT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "hwndParent", "pwszWizardTitle", "pExportInfo", "pvoid"]),
        #
        'CryptUIWizImport': SimTypeFunction([SimTypeInt(signed=False, label="CRYPTUI_WIZ_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPTUI_WIZ_IMPORT_SRC_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "hwndParent", "pwszWizardTitle", "pImportSrc", "hDestCertStore"]),
    }

lib.set_prototypes(prototypes)
