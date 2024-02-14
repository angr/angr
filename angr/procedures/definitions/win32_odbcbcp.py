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
lib.set_library_names("odbcbcp.dll")
prototypes = \
    {
        #
        'bcp_batch': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'bcp_bind': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1", "param2", "param3", "param4", "param5", "param6", "param7"]),
        #
        'bcp_colfmt': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="Byte"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1", "param2", "param3", "param4", "param5", "param6", "param7"]),
        #
        'bcp_collen': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1", "param2"]),
        #
        'bcp_colptr': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1", "param2"]),
        #
        'bcp_columns': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1"]),
        #
        'bcp_control': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1", "param2"]),
        #
        'bcp_done': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'bcp_exec': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1"]),
        #
        'bcp_getcolfmt': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1", "param2", "param3", "param4", "param5"]),
        #
        'bcp_initA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'bcp_initW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'bcp_moretext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1", "param2"]),
        #
        'bcp_readfmtA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1"]),
        #
        'bcp_readfmtW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1"]),
        #
        'bcp_sendrow': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["param0"]),
        #
        'bcp_setcolfmt': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1", "param2", "param3", "param4"]),
        #
        'bcp_writefmtA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1"]),
        #
        'bcp_writefmtW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1"]),
        #
        'dbprtypeA': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0"]),
        #
        'dbprtypeW': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["param0"]),
        #
        'SQLLinkedServers': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["param0"]),
        #
        'SQLLinkedCatalogsA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=True, label="Int16")], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1", "param2"]),
        #
        'SQLLinkedCatalogsW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=True, label="Int16")], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "param1", "param2"]),
        #
        'SQLInitEnumServers': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pwchServerName", "pwchInstanceName"]),
        #
        'SQLGetNextEnumeration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["hEnumHandle", "prgEnumData", "piEnumLength"]),
        #
        'SQLCloseEnumServers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeShort(signed=True, label="Int16"), arg_names=["hEnumHandle"]),
    }

lib.set_prototypes(prototypes)
