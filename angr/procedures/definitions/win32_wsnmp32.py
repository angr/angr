# pylint:disable=line-too-long
import logging

from ...sim_type import SimTypeFunction,     SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat,     SimTypePointer,     SimTypeChar,     SimStruct,     SimTypeFixedSizeArray,     SimTypeBottom,     SimUnion,     SimTypeBool
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
lib.set_library_names("wsnmp32.dll")
prototypes = \
    {
        # 
        'SnmpGetTranslateMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="SNMP_API_TRANSLATE_MODE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["nTranslateMode"]),
        # 
        'SnmpSetTranslateMode': SimTypeFunction([SimTypeInt(signed=False, label="SNMP_API_TRANSLATE_MODE")], SimTypeInt(signed=False, label="UInt32"), arg_names=["nTranslateMode"]),
        # 
        'SnmpGetRetransmitMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="SNMP_STATUS"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["nRetransmitMode"]),
        # 
        'SnmpSetRetransmitMode': SimTypeFunction([SimTypeInt(signed=False, label="SNMP_STATUS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["nRetransmitMode"]),
        # 
        'SnmpGetTimeout': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEntity", "nPolicyTimeout", "nActualTimeout"]),
        # 
        'SnmpSetTimeout': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEntity", "nPolicyTimeout"]),
        # 
        'SnmpGetRetry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEntity", "nPolicyRetry", "nActualRetry"]),
        # 
        'SnmpSetRetry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEntity", "nPolicyRetry"]),
        # 
        'SnmpGetVendorInfo': SimTypeFunction([SimTypePointer(SimStruct({"vendorName": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 64), "vendorContact": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 64), "vendorVersionId": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 32), "vendorVersionDate": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 32), "vendorEnterprise": SimTypeInt(signed=False, label="UInt32")}, name="smiVENDORINFO", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["vendorInfo"]),
        # 
        'SnmpStartup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SNMP_API_TRANSLATE_MODE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SNMP_STATUS"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["nMajorVersion", "nMinorVersion", "nLevel", "nTranslateMode", "nRetransmitMode"]),
        # 
        'SnmpCleanup': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        # 
        'SnmpOpen': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "wMsg"]),
        # 
        'SnmpClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["session"]),
        # 
        'SnmpSendMsg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["session", "srcEntity", "dstEntity", "context", "PDU"]),
        # 
        'SnmpRecvMsg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["session", "srcEntity", "dstEntity", "context", "PDU"]),
        # 
        'SnmpRegister': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="smiOID", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="SNMP_STATUS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["session", "srcEntity", "dstEntity", "context", "notification", "state"]),
        # 
        'SnmpCreateSession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSession", "hWnd", "wMsg", "wParam", "lParam", "lpClientData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "wMsg", "fCallBack", "lpClientData"]),
        # 
        'SnmpListen': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SNMP_STATUS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEntity", "lStatus"]),
        # 
        'SnmpListenEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEntity", "lStatus", "nUseEntityAddr"]),
        # 
        'SnmpCancelMsg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["session", "reqId"]),
        # 
        'SnmpStartupEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SNMP_API_TRANSLATE_MODE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SNMP_STATUS"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["nMajorVersion", "nMinorVersion", "nLevel", "nTranslateMode", "nRetransmitMode"]),
        # 
        'SnmpCleanupEx': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        # 
        'SnmpStrToEntity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["session", "string"]),
        # 
        'SnmpEntityToStr': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["entity", "size", "string"]),
        # 
        'SnmpFreeEntity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["entity"]),
        # 
        'SnmpStrToContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="smiOCTETS", pack=False, align=None), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["session", "string"]),
        # 
        'SnmpContextToStr': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="smiOCTETS", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["context", "string"]),
        # 
        'SnmpFreeContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["context"]),
        # 
        'SnmpSetPort': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEntity", "nPort"]),
        # 
        'SnmpCreatePdu': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SNMP_PDU_TYPE"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["session", "PDU_type", "request_id", "error_status", "error_index", "varbindlist"]),
        # 
        'SnmpGetPduData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="SNMP_PDU_TYPE"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SNMP_ERROR"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PDU", "PDU_type", "request_id", "error_status", "error_index", "varbindlist"]),
        # 
        'SnmpSetPduData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PDU", "PDU_type", "request_id", "non_repeaters", "max_repetitions", "varbindlist"]),
        # 
        'SnmpDuplicatePdu': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["session", "PDU"]),
        # 
        'SnmpFreePdu': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PDU"]),
        # 
        'SnmpCreateVbl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="smiOID", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"syntax": SimTypeInt(signed=False, label="UInt32"), "value": SimUnion({"sNumber": SimTypeInt(signed=True, label="Int32"), "uNumber": SimTypeInt(signed=False, label="UInt32"), "hNumber": SimStruct({"hipart": SimTypeInt(signed=False, label="UInt32"), "lopart": SimTypeInt(signed=False, label="UInt32")}, name="smiCNTR64", pack=False, align=None), "string": SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="smiOCTETS", pack=False, align=None), "oid": SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="smiOID", pack=False, align=None), "empty": SimTypeChar(label="Byte")}, name="<anon>", label="None")}, name="smiVALUE", pack=False, align=None), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["session", "name", "value"]),
        # 
        'SnmpDuplicateVbl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["session", "vbl"]),
        # 
        'SnmpFreeVbl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["vbl"]),
        # 
        'SnmpCountVbl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["vbl"]),
        # 
        'SnmpGetVb': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="smiOID", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"syntax": SimTypeInt(signed=False, label="UInt32"), "value": SimUnion({"sNumber": SimTypeInt(signed=True, label="Int32"), "uNumber": SimTypeInt(signed=False, label="UInt32"), "hNumber": SimStruct({"hipart": SimTypeInt(signed=False, label="UInt32"), "lopart": SimTypeInt(signed=False, label="UInt32")}, name="smiCNTR64", pack=False, align=None), "string": SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="smiOCTETS", pack=False, align=None), "oid": SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="smiOID", pack=False, align=None), "empty": SimTypeChar(label="Byte")}, name="<anon>", label="None")}, name="smiVALUE", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["vbl", "index", "name", "value"]),
        # 
        'SnmpSetVb': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="smiOID", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"syntax": SimTypeInt(signed=False, label="UInt32"), "value": SimUnion({"sNumber": SimTypeInt(signed=True, label="Int32"), "uNumber": SimTypeInt(signed=False, label="UInt32"), "hNumber": SimStruct({"hipart": SimTypeInt(signed=False, label="UInt32"), "lopart": SimTypeInt(signed=False, label="UInt32")}, name="smiCNTR64", pack=False, align=None), "string": SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="smiOCTETS", pack=False, align=None), "oid": SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="smiOID", pack=False, align=None), "empty": SimTypeChar(label="Byte")}, name="<anon>", label="None")}, name="smiVALUE", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["vbl", "index", "name", "value"]),
        # 
        'SnmpDeleteVb': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["vbl", "index"]),
        # 
        'SnmpGetLastError': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["session"]),
        # 
        'SnmpStrToOid': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="smiOID", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["string", "dstOID"]),
        # 
        'SnmpOidToStr': SimTypeFunction([SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="smiOID", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["srcOID", "size", "string"]),
        # 
        'SnmpOidCopy': SimTypeFunction([SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="smiOID", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="smiOID", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["srcOID", "dstOID"]),
        # 
        'SnmpOidCompare': SimTypeFunction([SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="smiOID", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="smiOID", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["xOID", "yOID", "maxlen", "result"]),
        # 
        'SnmpEncodeMsg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="smiOCTETS", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["session", "srcEntity", "dstEntity", "context", "pdu", "msgBufDesc"]),
        # 
        'SnmpDecodeMsg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="smiOCTETS", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["session", "srcEntity", "dstEntity", "context", "pdu", "msgBufDesc"]),
        # 
        'SnmpFreeDescriptor': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"len": SimTypeInt(signed=False, label="UInt32"), "ptr": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="smiOCTETS", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["syntax", "descriptor"]),
    }

lib.set_prototypes(prototypes)
