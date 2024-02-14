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
lib.set_library_names("snmpapi.dll")
prototypes = \
    {
        #
        'SnmpUtilOidCpy': SimTypeFunction([SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0), SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pOidDst", "pOidSrc"]),
        #
        'SnmpUtilOidAppend': SimTypeFunction([SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0), SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pOidDst", "pOidSrc"]),
        #
        'SnmpUtilOidNCmp': SimTypeFunction([SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0), SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pOid1", "pOid2", "nSubIds"]),
        #
        'SnmpUtilOidCmp': SimTypeFunction([SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0), SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pOid1", "pOid2"]),
        #
        'SnmpUtilOidFree': SimTypeFunction([SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pOid"]),
        #
        'SnmpUtilOctetsCmp': SimTypeFunction([SimTypePointer(SimTypeRef("AsnOctetString", SimStruct), offset=0), SimTypePointer(SimTypeRef("AsnOctetString", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pOctets1", "pOctets2"]),
        #
        'SnmpUtilOctetsNCmp': SimTypeFunction([SimTypePointer(SimTypeRef("AsnOctetString", SimStruct), offset=0), SimTypePointer(SimTypeRef("AsnOctetString", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pOctets1", "pOctets2", "nChars"]),
        #
        'SnmpUtilOctetsCpy': SimTypeFunction([SimTypePointer(SimTypeRef("AsnOctetString", SimStruct), offset=0), SimTypePointer(SimTypeRef("AsnOctetString", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pOctetsDst", "pOctetsSrc"]),
        #
        'SnmpUtilOctetsFree': SimTypeFunction([SimTypePointer(SimTypeRef("AsnOctetString", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pOctets"]),
        #
        'SnmpUtilAsnAnyCpy': SimTypeFunction([SimTypePointer(SimTypeRef("AsnAny", SimStruct), offset=0), SimTypePointer(SimTypeRef("AsnAny", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAnyDst", "pAnySrc"]),
        #
        'SnmpUtilAsnAnyFree': SimTypeFunction([SimTypePointer(SimTypeRef("AsnAny", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pAny"]),
        #
        'SnmpUtilVarBindCpy': SimTypeFunction([SimTypePointer(SimTypeRef("SnmpVarBind", SimStruct), offset=0), SimTypePointer(SimTypeRef("SnmpVarBind", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pVbDst", "pVbSrc"]),
        #
        'SnmpUtilVarBindFree': SimTypeFunction([SimTypePointer(SimTypeRef("SnmpVarBind", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pVb"]),
        #
        'SnmpUtilVarBindListCpy': SimTypeFunction([SimTypePointer(SimTypeRef("SnmpVarBindList", SimStruct), offset=0), SimTypePointer(SimTypeRef("SnmpVarBindList", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pVblDst", "pVblSrc"]),
        #
        'SnmpUtilVarBindListFree': SimTypeFunction([SimTypePointer(SimTypeRef("SnmpVarBindList", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pVbl"]),
        #
        'SnmpUtilMemFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pMem"]),
        #
        'SnmpUtilMemAlloc': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["nBytes"]),
        #
        'SnmpUtilMemReAlloc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pMem", "nBytes"]),
        #
        'SnmpUtilOidToA': SimTypeFunction([SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["Oid"]),
        #
        'SnmpUtilIdsToA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["Ids", "IdLength"]),
        #
        'SnmpUtilPrintOid': SimTypeFunction([SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Oid"]),
        #
        'SnmpUtilPrintAsnAny': SimTypeFunction([SimTypePointer(SimTypeRef("AsnAny", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pAny"]),
        #
        'SnmpSvcGetUptime': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'SnmpSvcSetLogLevel': SimTypeFunction([SimTypeInt(signed=False, label="SNMP_LOG")], SimTypeBottom(label="Void"), arg_names=["nLogLevel"]),
        #
        'SnmpSvcSetLogType': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["nLogType"]),
        #
        'SnmpUtilDbgPrint': SimTypeFunction([SimTypeInt(signed=False, label="SNMP_LOG"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["nLogLevel", "szFormat"]),
    }

lib.set_prototypes(prototypes)
