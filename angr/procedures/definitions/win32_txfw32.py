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
lib.set_library_names("txfw32.dll")
prototypes = \
    {
        # 
        'TxfLogCreateFileReadContext': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimStruct({"Internal": SimTypeLongLong(signed=False, label="UInt64")}, name="CLS_LSN", pack=False, align=None), SimStruct({"Internal": SimTypeLongLong(signed=False, label="UInt64")}, name="CLS_LSN", pack=False, align=None), SimTypePointer(SimStruct({"Anonymous": SimStruct({"LowPart": SimTypeLongLong(signed=True, label="Int64"), "HighPart": SimTypeLongLong(signed=True, label="Int64")}, name="_Anonymous_e__Struct", pack=False, align=None)}, name="TXF_ID", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogPath", "BeginningLsn", "EndingLsn", "TxfFileId", "TxfLogContext"]),
        # 
        'TxfLogCreateRangeReadContext': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimStruct({"Internal": SimTypeLongLong(signed=False, label="UInt64")}, name="CLS_LSN", pack=False, align=None), SimStruct({"Internal": SimTypeLongLong(signed=False, label="UInt64")}, name="CLS_LSN", pack=False, align=None), SimTypePointer(SimUnion({"Anonymous": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_Anonymous_e__Struct", pack=False, align=None), "u": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_u_e__Struct", pack=False, align=None), "QuadPart": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0), SimTypePointer(SimUnion({"Anonymous": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_Anonymous_e__Struct", pack=False, align=None), "u": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_u_e__Struct", pack=False, align=None), "QuadPart": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogPath", "BeginningLsn", "EndingLsn", "BeginningVirtualClock", "EndingVirtualClock", "RecordTypeMask", "TxfLogContext"]),
        # 
        'TxfLogDestroyReadContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TxfLogContext"]),
        # 
        'TxfLogReadRecords': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TxfLogContext", "BufferLength", "Buffer", "BytesUsed", "RecordCount"]),
        # 
        'TxfReadMetadataInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"Anonymous": SimStruct({"LowPart": SimTypeLongLong(signed=True, label="Int64"), "HighPart": SimTypeLongLong(signed=True, label="Int64")}, name="_Anonymous_e__Struct", pack=False, align=None)}, name="TXF_ID", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"Internal": SimTypeLongLong(signed=False, label="UInt64")}, name="CLS_LSN", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "TxfFileId", "LastLsn", "TransactionState", "LockingTransaction"]),
        # 
        'TxfLogRecordGetFileName': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimStruct({"Anonymous": SimStruct({"LowPart": SimTypeLongLong(signed=True, label="Int64"), "HighPart": SimTypeLongLong(signed=True, label="Int64")}, name="_Anonymous_e__Struct", pack=False, align=None)}, name="TXF_ID", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RecordBuffer", "RecordBufferLengthInBytes", "NameBuffer", "NameBufferLengthInBytes", "TxfId"]),
        # 
        'TxfLogRecordGetGenericType': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimUnion({"Anonymous": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_Anonymous_e__Struct", pack=False, align=None), "u": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_u_e__Struct", pack=False, align=None), "QuadPart": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RecordBuffer", "RecordBufferLengthInBytes", "GenericType", "VirtualClock"]),
        # 
        'TxfSetThreadMiniVersionForCreate': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeBottom(label="Void"), arg_names=["MiniVersion"]),
        # 
        'TxfGetThreadMiniVersionForCreate': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["MiniVersion"]),
    }

lib.set_prototypes(prototypes)
