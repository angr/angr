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
lib.set_library_names("dsparse.dll")
prototypes = \
    {
        #
        'DsMakeSpnW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServiceClass", "ServiceName", "InstanceName", "InstancePort", "Referrer", "pcSpnLength", "pszSpn"]),
        #
        'DsMakeSpnA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServiceClass", "ServiceName", "InstanceName", "InstancePort", "Referrer", "pcSpnLength", "pszSpn"]),
        #
        'DsCrackSpnA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszSpn", "pcServiceClass", "ServiceClass", "pcServiceName", "ServiceName", "pcInstanceName", "InstanceName", "pInstancePort"]),
        #
        'DsCrackSpnW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszSpn", "pcServiceClass", "ServiceClass", "pcServiceName", "ServiceName", "pcInstanceName", "InstanceName", "pInstancePort"]),
        #
        'DsQuoteRdnValueW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["cUnquotedRdnValueLength", "psUnquotedRdnValue", "pcQuotedRdnValueLength", "psQuotedRdnValue"]),
        #
        'DsQuoteRdnValueA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["cUnquotedRdnValueLength", "psUnquotedRdnValue", "pcQuotedRdnValueLength", "psQuotedRdnValue"]),
        #
        'DsUnquoteRdnValueW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["cQuotedRdnValueLength", "psQuotedRdnValue", "pcUnquotedRdnValueLength", "psUnquotedRdnValue"]),
        #
        'DsUnquoteRdnValueA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["cQuotedRdnValueLength", "psQuotedRdnValue", "pcUnquotedRdnValueLength", "psUnquotedRdnValue"]),
        #
        'DsGetRdnW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ppDN", "pcDN", "ppKey", "pcKey", "ppVal", "pcVal"]),
        #
        'DsCrackUnquotedMangledRdnW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="DS_MANGLE_FOR"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszRDN", "cchRDN", "pGuid", "peDsMangleFor"]),
        #
        'DsCrackUnquotedMangledRdnA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="DS_MANGLE_FOR"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszRDN", "cchRDN", "pGuid", "peDsMangleFor"]),
        #
        'DsIsMangledRdnValueW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DS_MANGLE_FOR")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszRdn", "cRdn", "eDsMangleForDesired"]),
        #
        'DsIsMangledRdnValueA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DS_MANGLE_FOR")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszRdn", "cRdn", "eDsMangleForDesired"]),
        #
        'DsIsMangledDnA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="DS_MANGLE_FOR")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszDn", "eDsMangleFor"]),
        #
        'DsIsMangledDnW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="DS_MANGLE_FOR")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszDn", "eDsMangleFor"]),
        #
        'DsCrackSpn2A': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszSpn", "cSpn", "pcServiceClass", "ServiceClass", "pcServiceName", "ServiceName", "pcInstanceName", "InstanceName", "pInstancePort"]),
        #
        'DsCrackSpn2W': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszSpn", "cSpn", "pcServiceClass", "ServiceClass", "pcServiceName", "ServiceName", "pcInstanceName", "InstanceName", "pInstancePort"]),
        #
        'DsCrackSpn3W': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszSpn", "cSpn", "pcHostName", "HostName", "pcInstanceName", "InstanceName", "pPortNumber", "pcDomainName", "DomainName", "pcRealmName", "RealmName"]),
        #
        'DsCrackSpn4W': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszSpn", "cSpn", "pcHostName", "HostName", "pcInstanceName", "InstanceName", "pcPortName", "PortName", "pcDomainName", "DomainName", "pcRealmName", "RealmName"]),
    }

lib.set_prototypes(prototypes)
