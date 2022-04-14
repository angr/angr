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
lib.set_library_names("ualapi.dll")
prototypes = \
    {
        # 
        'UalStart': SimTypeFunction([SimTypePointer(SimStruct({"Size": SimTypeInt(signed=False, label="UInt32"), "RoleGuid": SimTypeBottom(label="Guid"), "TenantId": SimTypeBottom(label="Guid"), "Address": SimStruct({"ss_family": SimTypeShort(signed=False, label="UInt16"), "__ss_pad1": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 6), "__ss_align": SimTypeLongLong(signed=True, label="Int64"), "__ss_pad2": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 112)}, name="SOCKADDR_STORAGE", pack=False, align=None), "UserName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 260)}, name="UAL_DATA_BLOB", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Data"]),
        # 
        'UalStop': SimTypeFunction([SimTypePointer(SimStruct({"Size": SimTypeInt(signed=False, label="UInt32"), "RoleGuid": SimTypeBottom(label="Guid"), "TenantId": SimTypeBottom(label="Guid"), "Address": SimStruct({"ss_family": SimTypeShort(signed=False, label="UInt16"), "__ss_pad1": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 6), "__ss_align": SimTypeLongLong(signed=True, label="Int64"), "__ss_pad2": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 112)}, name="SOCKADDR_STORAGE", pack=False, align=None), "UserName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 260)}, name="UAL_DATA_BLOB", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Data"]),
        # 
        'UalInstrument': SimTypeFunction([SimTypePointer(SimStruct({"Size": SimTypeInt(signed=False, label="UInt32"), "RoleGuid": SimTypeBottom(label="Guid"), "TenantId": SimTypeBottom(label="Guid"), "Address": SimStruct({"ss_family": SimTypeShort(signed=False, label="UInt16"), "__ss_pad1": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 6), "__ss_align": SimTypeLongLong(signed=True, label="Int64"), "__ss_pad2": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 112)}, name="SOCKADDR_STORAGE", pack=False, align=None), "UserName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 260)}, name="UAL_DATA_BLOB", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Data"]),
        # 
        'UalRegisterProduct': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["wszProductName", "wszRoleName", "wszGuid"]),
    }

lib.set_prototypes(prototypes)
