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
lib.set_library_names("sfc.dll")
prototypes = \
    {
        # 
        'SfcGetNextProtectedFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"FileName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 260), "FileNumber": SimTypeInt(signed=False, label="UInt32")}, name="PROTECTED_FILE_DATA", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RpcHandle", "ProtFileData"]),
        # 
        'SfcIsFileProtected': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RpcHandle", "ProtFileName"]),
        # 
        'SfcIsKeyProtected': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "SubKeyName", "KeySam"]),
        # 
        'SfpVerifyFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFileName", "pszError", "dwErrSize"]),
        # 
        'SRSetRestorePointA': SimTypeFunction([SimTypePointer(SimStruct({"dwEventType": SimTypeInt(signed=False, label="RESTOREPOINTINFO_EVENT_TYPE"), "dwRestorePtType": SimTypeInt(signed=False, label="RESTOREPOINTINFO_TYPE"), "llSequenceNumber": SimTypeLongLong(signed=True, label="Int64"), "szDescription": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 64)}, name="RESTOREPOINTINFOA", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"nStatus": SimTypeInt(signed=False, label="UInt32"), "llSequenceNumber": SimTypeLongLong(signed=True, label="Int64")}, name="STATEMGRSTATUS", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRestorePtSpec", "pSMgrStatus"]),
        # 
        'SRSetRestorePointW': SimTypeFunction([SimTypePointer(SimStruct({"dwEventType": SimTypeInt(signed=False, label="RESTOREPOINTINFO_EVENT_TYPE"), "dwRestorePtType": SimTypeInt(signed=False, label="RESTOREPOINTINFO_TYPE"), "llSequenceNumber": SimTypeLongLong(signed=True, label="Int64"), "szDescription": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 256)}, name="RESTOREPOINTINFOW", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"nStatus": SimTypeInt(signed=False, label="UInt32"), "llSequenceNumber": SimTypeLongLong(signed=True, label="Int64")}, name="STATEMGRSTATUS", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRestorePtSpec", "pSMgrStatus"]),
    }

lib.set_prototypes(prototypes)
