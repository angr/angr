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
lib.set_library_names("drtprov.dll")
prototypes = \
    {
        #
        'DrtCreatePnrpBootstrapResolver': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DRT_BOOTSTRAP_PROVIDER", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fPublish", "pwzPeerName", "pwzCloudName", "pwzPublishingIdentity", "ppResolver"]),
        #
        'DrtDeletePnrpBootstrapResolver': SimTypeFunction([SimTypePointer(SimTypeRef("DRT_BOOTSTRAP_PROVIDER", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pResolver"]),
        #
        'DrtCreateDnsBootstrapResolver': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DRT_BOOTSTRAP_PROVIDER", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["port", "pwszAddress", "ppModule"]),
        #
        'DrtDeleteDnsBootstrapResolver': SimTypeFunction([SimTypePointer(SimTypeRef("DRT_BOOTSTRAP_PROVIDER", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pResolver"]),
        #
        'DrtCreateDerivedKeySecurityProvider': SimTypeFunction([SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DRT_SECURITY_PROVIDER", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRootCert", "pLocalCert", "ppSecurityProvider"]),
        #
        'DrtCreateDerivedKey': SimTypeFunction([SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DRT_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pLocalCert", "pKey"]),
        #
        'DrtDeleteDerivedKeySecurityProvider': SimTypeFunction([SimTypePointer(SimTypeRef("DRT_SECURITY_PROVIDER", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pSecurityProvider"]),
        #
        'DrtCreateNullSecurityProvider': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("DRT_SECURITY_PROVIDER", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppSecurityProvider"]),
        #
        'DrtDeleteNullSecurityProvider': SimTypeFunction([SimTypePointer(SimTypeRef("DRT_SECURITY_PROVIDER", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pSecurityProvider"]),
    }

lib.set_prototypes(prototypes)
