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
lib.set_library_names("mgmtapi.dll")
prototypes = \
    {
        #
        'SnmpMgrOpen': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["lpAgentAddress", "lpAgentCommunity", "nTimeOut", "nRetries"]),
        #
        'SnmpMgrCtl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["session", "dwCtlCode", "lpvInBuffer", "cbInBuffer", "lpvOUTBuffer", "cbOUTBuffer", "lpcbBytesReturned"]),
        #
        'SnmpMgrClose': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["session"]),
        #
        'SnmpMgrRequest': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("SnmpVarBindList", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SNMP_ERROR_STATUS"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["session", "requestType", "variableBindings", "errorStatus", "errorIndex"]),
        #
        'SnmpMgrStrToOid': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["string", "oid"]),
        #
        'SnmpMgrOidToStr': SimTypeFunction([SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["oid", "string"]),
        #
        'SnmpMgrTrapListen': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phTrapAvailable"]),
        #
        'SnmpMgrGetTrap': SimTypeFunction([SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0), SimTypePointer(SimTypeRef("AsnOctetString", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SNMP_GENERICTRAP"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("SnmpVarBindList", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["enterprise", "IPAddress", "genericTrap", "specificTrap", "timeStamp", "variableBindings"]),
        #
        'SnmpMgrGetTrapEx': SimTypeFunction([SimTypePointer(SimTypeRef("AsnObjectIdentifier", SimStruct), offset=0), SimTypePointer(SimTypeRef("AsnOctetString", SimStruct), offset=0), SimTypePointer(SimTypeRef("AsnOctetString", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SNMP_GENERICTRAP"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("AsnOctetString", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("SnmpVarBindList", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["enterprise", "agentAddress", "sourceAddress", "genericTrap", "specificTrap", "community", "timeStamp", "variableBindings"]),
    }

lib.set_prototypes(prototypes)
