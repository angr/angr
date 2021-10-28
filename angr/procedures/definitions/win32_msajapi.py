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
lib.set_library_names("msajapi.dll")
prototypes = \
    {
        # 
        'AllJoynConnectToBus': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["connectionSpec"]),
        # 
        'AllJoynCloseBusHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["busHandle"]),
        # 
        'AllJoynSendToBus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["connectedBusHandle", "buffer", "bytesToWrite", "bytesTransferred", "reserved"]),
        # 
        'AllJoynReceiveFromBus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["connectedBusHandle", "buffer", "bytesToRead", "bytesTransferred", "reserved"]),
        # 
        'AllJoynEventSelect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["connectedBusHandle", "eventHandle", "eventTypes"]),
        # 
        'AllJoynEnumEvents': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["connectedBusHandle", "eventToReset", "eventTypes"]),
        # 
        'AllJoynCreateBus': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"nLength": SimTypeInt(signed=False, label="UInt32"), "lpSecurityDescriptor": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "bInheritHandle": SimTypeInt(signed=True, label="Int32")}, name="SECURITY_ATTRIBUTES", pack=False, align=None), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["outBufferSize", "inBufferSize", "lpSecurityAttributes"]),
        # 
        'AllJoynAcceptBusConnection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["serverBusHandle", "abortEvent"]),
        # 
        'alljoyn_unity_deferred_callbacks_process': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        # 
        'alljoyn_unity_set_deferred_callback_mainthread_only': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["mainthread_only"]),
        # 
        'QCC_StatusText': SimTypeFunction([SimTypeInt(signed=False, label="QStatus")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["status"]),
        # 
        'alljoyn_msgarg_create': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        # 
        'alljoyn_msgarg_create_and_set': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["signature"]),
        # 
        'alljoyn_msgarg_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["arg"]),
        # 
        'alljoyn_msgarg_array_create': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["size"]),
        # 
        'alljoyn_msgarg_array_element': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["arg", "index"]),
        # 
        'alljoyn_msgarg_set': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "signature"]),
        # 
        'alljoyn_msgarg_get': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "signature"]),
        # 
        'alljoyn_msgarg_copy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["source"]),
        # 
        'alljoyn_msgarg_clone': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["destination", "source"]),
        # 
        'alljoyn_msgarg_equal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lhv", "rhv"]),
        # 
        'alljoyn_msgarg_array_set': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["args", "numArgs", "signature"]),
        # 
        'alljoyn_msgarg_array_get': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["args", "numArgs", "signature"]),
        # 
        'alljoyn_msgarg_tostring': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["arg", "str", "buf", "indent"]),
        # 
        'alljoyn_msgarg_array_tostring': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["args", "numArgs", "str", "buf", "indent"]),
        # 
        'alljoyn_msgarg_signature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["arg", "str", "buf"]),
        # 
        'alljoyn_msgarg_array_signature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["values", "numValues", "str", "buf"]),
        # 
        'alljoyn_msgarg_hassignature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["arg", "signature"]),
        # 
        'alljoyn_msgarg_getdictelement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "elemSig"]),
        # 
        'alljoyn_msgarg_gettype': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="alljoyn_typeid"), arg_names=["arg"]),
        # 
        'alljoyn_msgarg_clear': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["arg"]),
        # 
        'alljoyn_msgarg_stabilize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["arg"]),
        # 
        'alljoyn_msgarg_array_set_offset': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["args", "argOffset", "numArgs", "signature"]),
        # 
        'alljoyn_msgarg_set_and_stabilize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "signature"]),
        # 
        'alljoyn_msgarg_set_uint8': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "y"]),
        # 
        'alljoyn_msgarg_set_bool': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "b"]),
        # 
        'alljoyn_msgarg_set_int16': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=True, label="Int16")], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "n"]),
        # 
        'alljoyn_msgarg_set_uint16': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "q"]),
        # 
        'alljoyn_msgarg_set_int32': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "i"]),
        # 
        'alljoyn_msgarg_set_uint32': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "u"]),
        # 
        'alljoyn_msgarg_set_int64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "x"]),
        # 
        'alljoyn_msgarg_set_uint64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "t"]),
        # 
        'alljoyn_msgarg_set_double': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeFloat(size=64)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "d"]),
        # 
        'alljoyn_msgarg_set_string': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "s"]),
        # 
        'alljoyn_msgarg_set_objectpath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "o"]),
        # 
        'alljoyn_msgarg_set_signature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "g"]),
        # 
        'alljoyn_msgarg_get_uint8': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "y"]),
        # 
        'alljoyn_msgarg_get_bool': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "b"]),
        # 
        'alljoyn_msgarg_get_int16': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "n"]),
        # 
        'alljoyn_msgarg_get_uint16': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "q"]),
        # 
        'alljoyn_msgarg_get_int32': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "i"]),
        # 
        'alljoyn_msgarg_get_uint32': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "u"]),
        # 
        'alljoyn_msgarg_get_int64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "x"]),
        # 
        'alljoyn_msgarg_get_uint64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "t"]),
        # 
        'alljoyn_msgarg_get_double': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "d"]),
        # 
        'alljoyn_msgarg_get_string': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "s"]),
        # 
        'alljoyn_msgarg_get_objectpath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "o"]),
        # 
        'alljoyn_msgarg_get_signature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "g"]),
        # 
        'alljoyn_msgarg_get_variant': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "v"]),
        # 
        'alljoyn_msgarg_set_uint8_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "ay"]),
        # 
        'alljoyn_msgarg_set_bool_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "ab"]),
        # 
        'alljoyn_msgarg_set_int16_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "an"]),
        # 
        'alljoyn_msgarg_set_uint16_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "aq"]),
        # 
        'alljoyn_msgarg_set_int32_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "ai"]),
        # 
        'alljoyn_msgarg_set_uint32_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "au"]),
        # 
        'alljoyn_msgarg_set_int64_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "ax"]),
        # 
        'alljoyn_msgarg_set_uint64_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "at"]),
        # 
        'alljoyn_msgarg_set_double_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "ad"]),
        # 
        'alljoyn_msgarg_set_string_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "as"]),
        # 
        'alljoyn_msgarg_set_objectpath_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "ao"]),
        # 
        'alljoyn_msgarg_set_signature_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "ag"]),
        # 
        'alljoyn_msgarg_get_uint8_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "ay"]),
        # 
        'alljoyn_msgarg_get_bool_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "ab"]),
        # 
        'alljoyn_msgarg_get_int16_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "an"]),
        # 
        'alljoyn_msgarg_get_uint16_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "aq"]),
        # 
        'alljoyn_msgarg_get_int32_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "ai"]),
        # 
        'alljoyn_msgarg_get_uint32_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "au"]),
        # 
        'alljoyn_msgarg_get_int64_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "ax"]),
        # 
        'alljoyn_msgarg_get_uint64_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "at"]),
        # 
        'alljoyn_msgarg_get_double_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "length", "ad"]),
        # 
        'alljoyn_msgarg_get_variant_array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "signature", "length", "av"]),
        # 
        'alljoyn_msgarg_get_array_numberofelements': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["arg"]),
        # 
        'alljoyn_msgarg_get_array_element': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["arg", "index", "element"]),
        # 
        'alljoyn_msgarg_get_array_elementsignature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["arg", "index"]),
        # 
        'alljoyn_msgarg_getkey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["arg"]),
        # 
        'alljoyn_msgarg_getvalue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["arg"]),
        # 
        'alljoyn_msgarg_setdictentry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "key", "value"]),
        # 
        'alljoyn_msgarg_setstruct': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["arg", "struct_members", "num_members"]),
        # 
        'alljoyn_msgarg_getnummembers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["arg"]),
        # 
        'alljoyn_msgarg_getmember': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["arg", "index"]),
        # 
        'alljoyn_aboutdata_create_empty': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        # 
        'alljoyn_aboutdata_create': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["defaultLanguage"]),
        # 
        'alljoyn_aboutdata_create_full': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["arg", "language"]),
        # 
        'alljoyn_aboutdata_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["data"]),
        # 
        'alljoyn_aboutdata_createfromxml': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "aboutDataXml"]),
        # 
        'alljoyn_aboutdata_isvalid': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["data", "language"]),
        # 
        'alljoyn_aboutdata_createfrommsgarg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "arg", "language"]),
        # 
        'alljoyn_aboutdata_setappid': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "appId", "num"]),
        # 
        'alljoyn_aboutdata_setappid_fromstring': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "appId"]),
        # 
        'alljoyn_aboutdata_getappid': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "appId", "num"]),
        # 
        'alljoyn_aboutdata_setdefaultlanguage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "defaultLanguage"]),
        # 
        'alljoyn_aboutdata_getdefaultlanguage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "defaultLanguage"]),
        # 
        'alljoyn_aboutdata_setdevicename': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "deviceName", "language"]),
        # 
        'alljoyn_aboutdata_getdevicename': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "deviceName", "language"]),
        # 
        'alljoyn_aboutdata_setdeviceid': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "deviceId"]),
        # 
        'alljoyn_aboutdata_getdeviceid': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "deviceId"]),
        # 
        'alljoyn_aboutdata_setappname': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "appName", "language"]),
        # 
        'alljoyn_aboutdata_getappname': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "appName", "language"]),
        # 
        'alljoyn_aboutdata_setmanufacturer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "manufacturer", "language"]),
        # 
        'alljoyn_aboutdata_getmanufacturer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "manufacturer", "language"]),
        # 
        'alljoyn_aboutdata_setmodelnumber': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "modelNumber"]),
        # 
        'alljoyn_aboutdata_getmodelnumber': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "modelNumber"]),
        # 
        'alljoyn_aboutdata_setsupportedlanguage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "language"]),
        # 
        'alljoyn_aboutdata_getsupportedlanguages': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["data", "languageTags", "num"]),
        # 
        'alljoyn_aboutdata_setdescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "description", "language"]),
        # 
        'alljoyn_aboutdata_getdescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "description", "language"]),
        # 
        'alljoyn_aboutdata_setdateofmanufacture': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "dateOfManufacture"]),
        # 
        'alljoyn_aboutdata_getdateofmanufacture': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "dateOfManufacture"]),
        # 
        'alljoyn_aboutdata_setsoftwareversion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "softwareVersion"]),
        # 
        'alljoyn_aboutdata_getsoftwareversion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "softwareVersion"]),
        # 
        'alljoyn_aboutdata_getajsoftwareversion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "ajSoftwareVersion"]),
        # 
        'alljoyn_aboutdata_sethardwareversion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "hardwareVersion"]),
        # 
        'alljoyn_aboutdata_gethardwareversion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "hardwareVersion"]),
        # 
        'alljoyn_aboutdata_setsupporturl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "supportUrl"]),
        # 
        'alljoyn_aboutdata_getsupporturl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "supportUrl"]),
        # 
        'alljoyn_aboutdata_setfield': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "name", "value", "language"]),
        # 
        'alljoyn_aboutdata_getfield': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "name", "value", "language"]),
        # 
        'alljoyn_aboutdata_getfields': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["data", "fields", "num_fields"]),
        # 
        'alljoyn_aboutdata_getaboutdata': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "msgArg", "language"]),
        # 
        'alljoyn_aboutdata_getannouncedaboutdata': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["data", "msgArg"]),
        # 
        'alljoyn_aboutdata_isfieldrequired': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["data", "fieldName"]),
        # 
        'alljoyn_aboutdata_isfieldannounced': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["data", "fieldName"]),
        # 
        'alljoyn_aboutdata_isfieldlocalized': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["data", "fieldName"]),
        # 
        'alljoyn_aboutdata_getfieldsignature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["data", "fieldName"]),
        # 
        'alljoyn_abouticon_create': SimTypeFunction([], SimTypePointer(SimStruct({}, name="_alljoyn_abouticon_handle", pack=False, align=None), offset=0)),
        # 
        'alljoyn_abouticon_destroy': SimTypeFunction([SimTypePointer(SimStruct({}, name="_alljoyn_abouticon_handle", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["icon"]),
        # 
        'alljoyn_abouticon_getcontent': SimTypeFunction([SimTypePointer(SimStruct({}, name="_alljoyn_abouticon_handle", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["icon", "data", "size"]),
        # 
        'alljoyn_abouticon_setcontent': SimTypeFunction([SimTypePointer(SimStruct({}, name="_alljoyn_abouticon_handle", pack=False, align=None), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="QStatus"), arg_names=["icon", "type", "data", "csize", "ownsData"]),
        # 
        'alljoyn_abouticon_geturl': SimTypeFunction([SimTypePointer(SimStruct({}, name="_alljoyn_abouticon_handle", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["icon", "type", "url"]),
        # 
        'alljoyn_abouticon_seturl': SimTypeFunction([SimTypePointer(SimStruct({}, name="_alljoyn_abouticon_handle", pack=False, align=None), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["icon", "type", "url"]),
        # 
        'alljoyn_abouticon_clear': SimTypeFunction([SimTypePointer(SimStruct({}, name="_alljoyn_abouticon_handle", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["icon"]),
        # 
        'alljoyn_abouticon_setcontent_frommsgarg': SimTypeFunction([SimTypePointer(SimStruct({}, name="_alljoyn_abouticon_handle", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["icon", "arg"]),
        # 
        'alljoyn_permissionconfigurator_getdefaultclaimcapabilities': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        # 
        'alljoyn_permissionconfigurator_getapplicationstate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="alljoyn_applicationstate"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "state"]),
        # 
        'alljoyn_permissionconfigurator_setapplicationstate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="alljoyn_applicationstate")], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "state"]),
        # 
        'alljoyn_permissionconfigurator_getpublickey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "publicKey"]),
        # 
        'alljoyn_permissionconfigurator_publickey_destroy': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["publicKey"]),
        # 
        'alljoyn_permissionconfigurator_getmanifesttemplate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "manifestTemplateXml"]),
        # 
        'alljoyn_permissionconfigurator_manifesttemplate_destroy': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["manifestTemplateXml"]),
        # 
        'alljoyn_permissionconfigurator_setmanifesttemplatefromxml': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "manifestTemplateXml"]),
        # 
        'alljoyn_permissionconfigurator_getclaimcapabilities': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "claimCapabilities"]),
        # 
        'alljoyn_permissionconfigurator_setclaimcapabilities': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "claimCapabilities"]),
        # 
        'alljoyn_permissionconfigurator_getclaimcapabilitiesadditionalinfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "additionalInfo"]),
        # 
        'alljoyn_permissionconfigurator_setclaimcapabilitiesadditionalinfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "additionalInfo"]),
        # 
        'alljoyn_permissionconfigurator_reset': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator"]),
        # 
        'alljoyn_permissionconfigurator_claim': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "caKey", "identityCertificateChain", "groupId", "groupSize", "groupAuthority", "manifestsXmls", "manifestsCount"]),
        # 
        'alljoyn_permissionconfigurator_updateidentity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "identityCertificateChain", "manifestsXmls", "manifestsCount"]),
        # 
        'alljoyn_permissionconfigurator_getidentity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "identityCertificateChain"]),
        # 
        'alljoyn_permissionconfigurator_certificatechain_destroy': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["certificateChain"]),
        # 
        'alljoyn_permissionconfigurator_getmanifests': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"count": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "xmls": SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)}, name="alljoyn_manifestarray", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "manifestArray"]),
        # 
        'alljoyn_permissionconfigurator_manifestarray_cleanup': SimTypeFunction([SimTypePointer(SimStruct({"count": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "xmls": SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)}, name="alljoyn_manifestarray", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["manifestArray"]),
        # 
        'alljoyn_permissionconfigurator_installmanifests': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "manifestsXmls", "manifestsCount", "append"]),
        # 
        'alljoyn_permissionconfigurator_getidentitycertificateid': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"serial": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "serialLen": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "issuerPublicKey": SimTypePointer(SimTypeChar(label="SByte"), offset=0), "issuerAki": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "issuerAkiLen": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="alljoyn_certificateid", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "certificateId"]),
        # 
        'alljoyn_permissionconfigurator_certificateid_cleanup': SimTypeFunction([SimTypePointer(SimStruct({"serial": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "serialLen": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "issuerPublicKey": SimTypePointer(SimTypeChar(label="SByte"), offset=0), "issuerAki": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "issuerAkiLen": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="alljoyn_certificateid", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["certificateId"]),
        # 
        'alljoyn_permissionconfigurator_updatepolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "policyXml"]),
        # 
        'alljoyn_permissionconfigurator_getpolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "policyXml"]),
        # 
        'alljoyn_permissionconfigurator_getdefaultpolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "policyXml"]),
        # 
        'alljoyn_permissionconfigurator_policy_destroy': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["policyXml"]),
        # 
        'alljoyn_permissionconfigurator_resetpolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator"]),
        # 
        'alljoyn_permissionconfigurator_getmembershipsummaries': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"count": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "ids": SimTypePointer(SimStruct({"serial": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "serialLen": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "issuerPublicKey": SimTypePointer(SimTypeChar(label="SByte"), offset=0), "issuerAki": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "issuerAkiLen": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="alljoyn_certificateid", pack=False, align=None), offset=0)}, name="alljoyn_certificateidarray", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "certificateIds"]),
        # 
        'alljoyn_permissionconfigurator_certificateidarray_cleanup': SimTypeFunction([SimTypePointer(SimStruct({"count": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "ids": SimTypePointer(SimStruct({"serial": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "serialLen": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "issuerPublicKey": SimTypePointer(SimTypeChar(label="SByte"), offset=0), "issuerAki": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "issuerAkiLen": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="alljoyn_certificateid", pack=False, align=None), offset=0)}, name="alljoyn_certificateidarray", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["certificateIdArray"]),
        # 
        'alljoyn_permissionconfigurator_installmembership': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "membershipCertificateChain"]),
        # 
        'alljoyn_permissionconfigurator_removemembership': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator", "serial", "serialLen", "issuerPublicKey", "issuerAki", "issuerAkiLen"]),
        # 
        'alljoyn_permissionconfigurator_startmanagement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator"]),
        # 
        'alljoyn_permissionconfigurator_endmanagement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configurator"]),
        # 
        'alljoyn_applicationstatelistener_create': SimTypeFunction([SimTypePointer(SimStruct({"state": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypeInt(signed=False, label="alljoyn_applicationstate"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["busName", "publicKey", "applicationState", "context"]), offset=0)}, name="alljoyn_applicationstatelistener_callbacks", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["callbacks", "context"]),
        # 
        'alljoyn_applicationstatelistener_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["listener"]),
        # 
        'alljoyn_keystorelistener_create': SimTypeFunction([SimTypePointer(SimStruct({"load_request": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="alljoyn_keystorelistener"), SimTypeBottom(label="alljoyn_keystore")], SimTypeInt(signed=False, label="QStatus"), arg_names=["context", "listener", "keyStore"]), offset=0), "store_request": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="alljoyn_keystorelistener"), SimTypeBottom(label="alljoyn_keystore")], SimTypeInt(signed=False, label="QStatus"), arg_names=["context", "listener", "keyStore"]), offset=0)}, name="alljoyn_keystorelistener_callbacks", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["callbacks", "context"]),
        # 
        'alljoyn_keystorelistener_with_synchronization_create': SimTypeFunction([SimTypePointer(SimStruct({"load_request": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="alljoyn_keystorelistener"), SimTypeBottom(label="alljoyn_keystore")], SimTypeInt(signed=False, label="QStatus"), arg_names=["context", "listener", "keyStore"]), offset=0), "store_request": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="alljoyn_keystorelistener"), SimTypeBottom(label="alljoyn_keystore")], SimTypeInt(signed=False, label="QStatus"), arg_names=["context", "listener", "keyStore"]), offset=0), "acquire_exclusive_lock": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="alljoyn_keystorelistener")], SimTypeInt(signed=False, label="QStatus"), arg_names=["context", "listener"]), offset=0), "release_exclusive_lock": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="alljoyn_keystorelistener")], SimTypeBottom(label="Void"), arg_names=["context", "listener"]), offset=0)}, name="alljoyn_keystorelistener_with_synchronization_callbacks", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["callbacks", "context"]),
        # 
        'alljoyn_keystorelistener_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["listener"]),
        # 
        'alljoyn_keystorelistener_putkeys': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["listener", "keyStore", "source", "password"]),
        # 
        'alljoyn_keystorelistener_getkeys': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["listener", "keyStore", "sink", "sink_sz"]),
        # 
        'alljoyn_sessionopts_create': SimTypeFunction([SimTypeChar(label="Byte"), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="Byte"), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["traffic", "isMultipoint", "proximity", "transports"]),
        # 
        'alljoyn_sessionopts_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["opts"]),
        # 
        'alljoyn_sessionopts_get_traffic': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["opts"]),
        # 
        'alljoyn_sessionopts_set_traffic': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["opts", "traffic"]),
        # 
        'alljoyn_sessionopts_get_multipoint': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["opts"]),
        # 
        'alljoyn_sessionopts_set_multipoint': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["opts", "isMultipoint"]),
        # 
        'alljoyn_sessionopts_get_proximity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["opts"]),
        # 
        'alljoyn_sessionopts_set_proximity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["opts", "proximity"]),
        # 
        'alljoyn_sessionopts_get_transports': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["opts"]),
        # 
        'alljoyn_sessionopts_set_transports': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeBottom(label="Void"), arg_names=["opts", "transports"]),
        # 
        'alljoyn_sessionopts_iscompatible': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["one", "other"]),
        # 
        'alljoyn_sessionopts_cmp': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["one", "other"]),
        # 
        'alljoyn_message_create': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus"]),
        # 
        'alljoyn_message_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["msg"]),
        # 
        'alljoyn_message_isbroadcastsignal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["msg"]),
        # 
        'alljoyn_message_isglobalbroadcast': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["msg"]),
        # 
        'alljoyn_message_issessionless': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["msg"]),
        # 
        'alljoyn_message_getflags': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["msg"]),
        # 
        'alljoyn_message_isexpired': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["msg", "tillExpireMS"]),
        # 
        'alljoyn_message_isunreliable': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["msg"]),
        # 
        'alljoyn_message_isencrypted': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["msg"]),
        # 
        'alljoyn_message_getauthmechanism': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["msg"]),
        # 
        'alljoyn_message_gettype': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="alljoyn_messagetype"), arg_names=["msg"]),
        # 
        'alljoyn_message_getargs': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["msg", "numArgs", "args"]),
        # 
        'alljoyn_message_getarg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["msg", "argN"]),
        # 
        'alljoyn_message_parseargs': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["msg", "signature"]),
        # 
        'alljoyn_message_getcallserial': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["msg"]),
        # 
        'alljoyn_message_getsignature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["msg"]),
        # 
        'alljoyn_message_getobjectpath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["msg"]),
        # 
        'alljoyn_message_getinterface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["msg"]),
        # 
        'alljoyn_message_getmembername': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["msg"]),
        # 
        'alljoyn_message_getreplyserial': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["msg"]),
        # 
        'alljoyn_message_getsender': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["msg"]),
        # 
        'alljoyn_message_getreceiveendpointname': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["msg"]),
        # 
        'alljoyn_message_getdestination': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["msg"]),
        # 
        'alljoyn_message_getcompressiontoken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["msg"]),
        # 
        'alljoyn_message_getsessionid': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["msg"]),
        # 
        'alljoyn_message_geterrorname': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["msg", "errorMessage", "errorMessage_size"]),
        # 
        'alljoyn_message_tostring': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["msg", "str", "buf"]),
        # 
        'alljoyn_message_description': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["msg", "str", "buf"]),
        # 
        'alljoyn_message_gettimestamp': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["msg"]),
        # 
        'alljoyn_message_eql': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["one", "other"]),
        # 
        'alljoyn_message_setendianess': SimTypeFunction([SimTypeChar(label="SByte")], SimTypeBottom(label="Void"), arg_names=["endian"]),
        # 
        'alljoyn_authlistener_requestcredentialsresponse': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["listener", "authContext", "accept", "credentials"]),
        # 
        'alljoyn_authlistener_verifycredentialsresponse': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["listener", "authContext", "accept"]),
        # 
        'alljoyn_authlistener_create': SimTypeFunction([SimTypePointer(SimStruct({"request_credentials": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR"), SimTypeShort(signed=False, label="UInt16"), SimTypeBottom(label="PSTR"), SimTypeShort(signed=False, label="UInt16"), SimTypeBottom(label="alljoyn_credentials")], SimTypeInt(signed=True, label="Int32"), arg_names=["context", "authMechanism", "peerName", "authCount", "userName", "credMask", "credentials"]), offset=0), "verify_credentials": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR"), SimTypeBottom(label="alljoyn_credentials")], SimTypeInt(signed=True, label="Int32"), arg_names=["context", "authMechanism", "peerName", "credentials"]), offset=0), "security_violation": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="QStatus"), SimTypeBottom(label="alljoyn_message")], SimTypeBottom(label="Void"), arg_names=["context", "status", "msg"]), offset=0), "authentication_complete": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["context", "authMechanism", "peerName", "success"]), offset=0)}, name="alljoyn_authlistener_callbacks", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["callbacks", "context"]),
        # 
        'alljoyn_authlistenerasync_create': SimTypeFunction([SimTypePointer(SimStruct({"request_credentials": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="alljoyn_authlistener"), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR"), SimTypeShort(signed=False, label="UInt16"), SimTypeBottom(label="PSTR"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["context", "listener", "authMechanism", "peerName", "authCount", "userName", "credMask", "authContext"]), offset=0), "verify_credentials": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="alljoyn_authlistener"), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR"), SimTypeBottom(label="alljoyn_credentials"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["context", "listener", "authMechanism", "peerName", "credentials", "authContext"]), offset=0), "security_violation": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="QStatus"), SimTypeBottom(label="alljoyn_message")], SimTypeBottom(label="Void"), arg_names=["context", "status", "msg"]), offset=0), "authentication_complete": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["context", "authMechanism", "peerName", "success"]), offset=0)}, name="alljoyn_authlistenerasync_callbacks", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["callbacks", "context"]),
        # 
        'alljoyn_authlistener_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["listener"]),
        # 
        'alljoyn_authlistenerasync_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["listener"]),
        # 
        'alljoyn_authlistener_setsharedsecret': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["listener", "sharedSecret", "sharedSecretSize"]),
        # 
        'alljoyn_credentials_create': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        # 
        'alljoyn_credentials_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["cred"]),
        # 
        'alljoyn_credentials_isset': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["cred", "creds"]),
        # 
        'alljoyn_credentials_setpassword': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cred", "pwd"]),
        # 
        'alljoyn_credentials_setusername': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cred", "userName"]),
        # 
        'alljoyn_credentials_setcertchain': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cred", "certChain"]),
        # 
        'alljoyn_credentials_setprivatekey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cred", "pk"]),
        # 
        'alljoyn_credentials_setlogonentry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["cred", "logonEntry"]),
        # 
        'alljoyn_credentials_setexpiration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["cred", "expiration"]),
        # 
        'alljoyn_credentials_getpassword': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["cred"]),
        # 
        'alljoyn_credentials_getusername': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["cred"]),
        # 
        'alljoyn_credentials_getcertchain': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["cred"]),
        # 
        'alljoyn_credentials_getprivateKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["cred"]),
        # 
        'alljoyn_credentials_getlogonentry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["cred"]),
        # 
        'alljoyn_credentials_getexpiration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["cred"]),
        # 
        'alljoyn_credentials_clear': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["cred"]),
        # 
        'alljoyn_buslistener_create': SimTypeFunction([SimTypePointer(SimStruct({"listener_registered": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="alljoyn_busattachment")], SimTypeBottom(label="Void"), arg_names=["context", "bus"]), offset=0), "listener_unregistered": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0), "found_advertised_name": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="PSTR"), SimTypeShort(signed=False, label="UInt16"), SimTypeBottom(label="PSTR")], SimTypeBottom(label="Void"), arg_names=["context", "name", "transport", "namePrefix"]), offset=0), "lost_advertised_name": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="PSTR"), SimTypeShort(signed=False, label="UInt16"), SimTypeBottom(label="PSTR")], SimTypeBottom(label="Void"), arg_names=["context", "name", "transport", "namePrefix"]), offset=0), "name_owner_changed": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR")], SimTypeBottom(label="Void"), arg_names=["context", "busName", "previousOwner", "newOwner"]), offset=0), "bus_stopping": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0), "bus_disconnected": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0), "property_changed": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="alljoyn_msgarg")], SimTypeBottom(label="Void"), arg_names=["context", "prop_name", "prop_value"]), offset=0)}, name="alljoyn_buslistener_callbacks", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["callbacks", "context"]),
        # 
        'alljoyn_buslistener_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["listener"]),
        # 
        'alljoyn_interfacedescription_member_getannotationscount': SimTypeFunction([SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["member"]),
        # 
        'alljoyn_interfacedescription_member_getannotationatindex': SimTypeFunction([SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["member", "index", "name", "name_size", "value", "value_size"]),
        # 
        'alljoyn_interfacedescription_member_getannotation': SimTypeFunction([SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["member", "name", "value", "value_size"]),
        # 
        'alljoyn_interfacedescription_member_getargannotationscount': SimTypeFunction([SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["member", "argName"]),
        # 
        'alljoyn_interfacedescription_member_getargannotationatindex': SimTypeFunction([SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["member", "argName", "index", "name", "name_size", "value", "value_size"]),
        # 
        'alljoyn_interfacedescription_member_getargannotation': SimTypeFunction([SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["member", "argName", "name", "value", "value_size"]),
        # 
        'alljoyn_interfacedescription_property_getannotationscount': SimTypeFunction([SimStruct({"name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "access": SimTypeChar(label="Byte"), "internal_property": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_property", pack=False, align=None)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["property"]),
        # 
        'alljoyn_interfacedescription_property_getannotationatindex': SimTypeFunction([SimStruct({"name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "access": SimTypeChar(label="Byte"), "internal_property": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_property", pack=False, align=None), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["property", "index", "name", "name_size", "value", "value_size"]),
        # 
        'alljoyn_interfacedescription_property_getannotation': SimTypeFunction([SimStruct({"name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "access": SimTypeChar(label="Byte"), "internal_property": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_property", pack=False, align=None), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["property", "name", "value", "value_size"]),
        # 
        'alljoyn_interfacedescription_activate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["iface"]),
        # 
        'alljoyn_interfacedescription_addannotation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "name", "value"]),
        # 
        'alljoyn_interfacedescription_getannotation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iface", "name", "value", "value_size"]),
        # 
        'alljoyn_interfacedescription_getannotationscount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["iface"]),
        # 
        'alljoyn_interfacedescription_getannotationatindex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["iface", "index", "name", "name_size", "value", "value_size"]),
        # 
        'alljoyn_interfacedescription_getmember': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iface", "name", "member"]),
        # 
        'alljoyn_interfacedescription_addmember': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="alljoyn_messagetype"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "type", "name", "inputSig", "outSig", "argNames", "annotation"]),
        # 
        'alljoyn_interfacedescription_addmemberannotation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "member", "name", "value"]),
        # 
        'alljoyn_interfacedescription_getmemberannotation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iface", "member", "name", "value", "value_size"]),
        # 
        'alljoyn_interfacedescription_getmembers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["iface", "members", "numMembers"]),
        # 
        'alljoyn_interfacedescription_hasmember': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iface", "name", "inSig", "outSig"]),
        # 
        'alljoyn_interfacedescription_addmethod': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "name", "inputSig", "outSig", "argNames", "annotation", "accessPerms"]),
        # 
        'alljoyn_interfacedescription_getmethod': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iface", "name", "member"]),
        # 
        'alljoyn_interfacedescription_addsignal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "name", "sig", "argNames", "annotation", "accessPerms"]),
        # 
        'alljoyn_interfacedescription_getsignal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iface", "name", "member"]),
        # 
        'alljoyn_interfacedescription_getproperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimStruct({"name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "access": SimTypeChar(label="Byte"), "internal_property": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_property", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iface", "name", "property"]),
        # 
        'alljoyn_interfacedescription_getproperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "access": SimTypeChar(label="Byte"), "internal_property": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_property", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["iface", "props", "numProps"]),
        # 
        'alljoyn_interfacedescription_addproperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "name", "signature", "access"]),
        # 
        'alljoyn_interfacedescription_addpropertyannotation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "property", "name", "value"]),
        # 
        'alljoyn_interfacedescription_getpropertyannotation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iface", "property", "name", "value", "str_size"]),
        # 
        'alljoyn_interfacedescription_hasproperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iface", "name"]),
        # 
        'alljoyn_interfacedescription_hasproperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iface"]),
        # 
        'alljoyn_interfacedescription_getname': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["iface"]),
        # 
        'alljoyn_interfacedescription_introspect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["iface", "str", "buf", "indent"]),
        # 
        'alljoyn_interfacedescription_issecure': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iface"]),
        # 
        'alljoyn_interfacedescription_getsecuritypolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="alljoyn_interfacedescription_securitypolicy"), arg_names=["iface"]),
        # 
        'alljoyn_interfacedescription_setdescriptionlanguage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["iface", "language"]),
        # 
        'alljoyn_interfacedescription_getdescriptionlanguages': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["iface", "languages", "size"]),
        # 
        'alljoyn_interfacedescription_getdescriptionlanguages2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["iface", "languages", "languagesSize"]),
        # 
        'alljoyn_interfacedescription_setdescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["iface", "description"]),
        # 
        'alljoyn_interfacedescription_setdescriptionforlanguage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "description", "languageTag"]),
        # 
        'alljoyn_interfacedescription_getdescriptionforlanguage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["iface", "description", "maxLanguageLength", "languageTag"]),
        # 
        'alljoyn_interfacedescription_setmemberdescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "member", "description"]),
        # 
        'alljoyn_interfacedescription_setmemberdescriptionforlanguage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "member", "description", "languageTag"]),
        # 
        'alljoyn_interfacedescription_getmemberdescriptionforlanguage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["iface", "member", "description", "maxLanguageLength", "languageTag"]),
        # 
        'alljoyn_interfacedescription_setargdescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "member", "argName", "description"]),
        # 
        'alljoyn_interfacedescription_setargdescriptionforlanguage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "member", "arg", "description", "languageTag"]),
        # 
        'alljoyn_interfacedescription_getargdescriptionforlanguage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["iface", "member", "arg", "description", "maxLanguageLength", "languageTag"]),
        # 
        'alljoyn_interfacedescription_setpropertydescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "name", "description"]),
        # 
        'alljoyn_interfacedescription_setpropertydescriptionforlanguage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "name", "description", "languageTag"]),
        # 
        'alljoyn_interfacedescription_getpropertydescriptionforlanguage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["iface", "property", "description", "maxLanguageLength", "languageTag"]),
        # 
        'alljoyn_interfacedescription_setdescriptiontranslationcallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR")], SimTypeBottom(label="PSTR"), arg_names=["sourceLanguage", "targetLanguage", "sourceText"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["iface", "translationCallback"]),
        # 
        'alljoyn_interfacedescription_getdescriptiontranslationcallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeFunction([SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR")], SimTypeBottom(label="PSTR"), arg_names=["sourceLanguage", "targetLanguage", "sourceText"]), offset=0), arg_names=["iface"]),
        # 
        'alljoyn_interfacedescription_hasdescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iface"]),
        # 
        'alljoyn_interfacedescription_addargannotation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["iface", "member", "argName", "name", "value"]),
        # 
        'alljoyn_interfacedescription_getmemberargannotation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iface", "member", "argName", "name", "value", "value_size"]),
        # 
        'alljoyn_interfacedescription_eql': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["one", "other"]),
        # 
        'alljoyn_interfacedescription_member_eql': SimTypeFunction([SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None)], SimTypeInt(signed=True, label="Int32"), arg_names=["one", "other"]),
        # 
        'alljoyn_interfacedescription_property_eql': SimTypeFunction([SimStruct({"name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "access": SimTypeChar(label="Byte"), "internal_property": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_property", pack=False, align=None), SimStruct({"name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "access": SimTypeChar(label="Byte"), "internal_property": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_property", pack=False, align=None)], SimTypeInt(signed=True, label="Int32"), arg_names=["one", "other"]),
        # 
        'alljoyn_busobject_create': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimStruct({"property_get": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR"), SimTypeBottom(label="alljoyn_msgarg")], SimTypeInt(signed=False, label="QStatus"), arg_names=["context", "ifcName", "propName", "val"]), offset=0), "property_set": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR"), SimTypeBottom(label="alljoyn_msgarg")], SimTypeInt(signed=False, label="QStatus"), arg_names=["context", "ifcName", "propName", "val"]), offset=0), "object_registered": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0), "object_unregistered": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0)}, name="alljoyn_busobject_callbacks", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["path", "isPlaceholder", "callbacks_in", "context_in"]),
        # 
        'alljoyn_busobject_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["bus"]),
        # 
        'alljoyn_busobject_getpath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["bus"]),
        # 
        'alljoyn_busobject_emitpropertychanged': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["bus", "ifcName", "propName", "val", "id"]),
        # 
        'alljoyn_busobject_emitpropertieschanged': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["bus", "ifcName", "propNames", "numProps", "id"]),
        # 
        'alljoyn_busobject_getname': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["bus", "buffer", "bufferSz"]),
        # 
        'alljoyn_busobject_addinterface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "iface"]),
        # 
        'alljoyn_busobject_addmethodhandler': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeFunction([SimTypeBottom(label="alljoyn_busobject"), SimTypePointer(SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), offset=0), SimTypeBottom(label="alljoyn_message")], SimTypeBottom(label="Void"), arg_names=["bus", "member", "message"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "member", "handler", "context"]),
        # 
        'alljoyn_busobject_addmethodhandlers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"member": SimTypePointer(SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), offset=0), "method_handler": SimTypePointer(SimTypeFunction([SimTypeBottom(label="alljoyn_busobject"), SimTypePointer(SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), offset=0), SimTypeBottom(label="alljoyn_message")], SimTypeBottom(label="Void"), arg_names=["bus", "member", "message"]), offset=0)}, name="alljoyn_busobject_methodentry", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "entries", "numEntries"]),
        # 
        'alljoyn_busobject_methodreply_args': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "msg", "args", "numArgs"]),
        # 
        'alljoyn_busobject_methodreply_err': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "msg", "error", "errorMessage"]),
        # 
        'alljoyn_busobject_methodreply_status': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="QStatus")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "msg", "status"]),
        # 
        'alljoyn_busobject_getbusattachment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus"]),
        # 
        'alljoyn_busobject_signal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "destination", "sessionId", "signal", "args", "numArgs", "timeToLive", "flags", "msg"]),
        # 
        'alljoyn_busobject_cancelsessionlessmessage_serial': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "serialNumber"]),
        # 
        'alljoyn_busobject_cancelsessionlessmessage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "msg"]),
        # 
        'alljoyn_busobject_issecure': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bus"]),
        # 
        'alljoyn_busobject_getannouncedinterfacenames': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["bus", "interfaces", "numInterfaces"]),
        # 
        'alljoyn_busobject_setannounceflag': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="alljoyn_about_announceflag")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "iface", "isAnnounced"]),
        # 
        'alljoyn_busobject_addinterface_announced': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "iface"]),
        # 
        'alljoyn_proxybusobject_create': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus", "service", "path", "sessionId"]),
        # 
        'alljoyn_proxybusobject_create_secure': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus", "service", "path", "sessionId"]),
        # 
        'alljoyn_proxybusobject_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["proxyObj"]),
        # 
        'alljoyn_proxybusobject_addinterface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "iface"]),
        # 
        'alljoyn_proxybusobject_addinterface_by_name': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "name"]),
        # 
        'alljoyn_proxybusobject_getchildren': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["proxyObj", "children", "numChildren"]),
        # 
        'alljoyn_proxybusobject_getchild': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["proxyObj", "path"]),
        # 
        'alljoyn_proxybusobject_addchild': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "child"]),
        # 
        'alljoyn_proxybusobject_removechild': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "path"]),
        # 
        'alljoyn_proxybusobject_introspectremoteobject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj"]),
        # 
        'alljoyn_proxybusobject_introspectremoteobjectasync': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="QStatus"), SimTypeBottom(label="alljoyn_proxybusobject"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["status", "obj", "context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "callback", "context"]),
        # 
        'alljoyn_proxybusobject_getproperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "iface", "property", "value"]),
        # 
        'alljoyn_proxybusobject_getpropertyasync': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="QStatus"), SimTypeBottom(label="alljoyn_proxybusobject"), SimTypeBottom(label="alljoyn_msgarg"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["status", "obj", "value", "context"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "iface", "property", "callback", "timeout", "context"]),
        # 
        'alljoyn_proxybusobject_getallproperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "iface", "values"]),
        # 
        'alljoyn_proxybusobject_getallpropertiesasync': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="QStatus"), SimTypeBottom(label="alljoyn_proxybusobject"), SimTypeBottom(label="alljoyn_msgarg"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["status", "obj", "values", "context"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "iface", "callback", "timeout", "context"]),
        # 
        'alljoyn_proxybusobject_setproperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "iface", "property", "value"]),
        # 
        'alljoyn_proxybusobject_registerpropertieschangedlistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeBottom(label="alljoyn_proxybusobject"), SimTypeBottom(label="PSTR"), SimTypeBottom(label="alljoyn_msgarg"), SimTypeBottom(label="alljoyn_msgarg"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["obj", "ifaceName", "changed", "invalidated", "context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "iface", "properties", "numProperties", "callback", "context"]),
        # 
        'alljoyn_proxybusobject_unregisterpropertieschangedlistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypeBottom(label="alljoyn_proxybusobject"), SimTypeBottom(label="PSTR"), SimTypeBottom(label="alljoyn_msgarg"), SimTypeBottom(label="alljoyn_msgarg"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["obj", "ifaceName", "changed", "invalidated", "context"]), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "iface", "callback"]),
        # 
        'alljoyn_proxybusobject_setpropertyasync': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="QStatus"), SimTypeBottom(label="alljoyn_proxybusobject"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["status", "obj", "context"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "iface", "property", "value", "callback", "timeout", "context"]),
        # 
        'alljoyn_proxybusobject_methodcall': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "ifaceName", "methodName", "args", "numArgs", "replyMsg", "timeout", "flags"]),
        # 
        'alljoyn_proxybusobject_methodcall_member': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "method", "args", "numArgs", "replyMsg", "timeout", "flags"]),
        # 
        'alljoyn_proxybusobject_methodcall_noreply': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "ifaceName", "methodName", "args", "numArgs", "flags"]),
        # 
        'alljoyn_proxybusobject_methodcall_member_noreply': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "method", "args", "numArgs", "flags"]),
        # 
        'alljoyn_proxybusobject_methodcallasync': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypeBottom(label="alljoyn_message"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["message", "context"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "ifaceName", "methodName", "replyFunc", "args", "numArgs", "context", "timeout", "flags"]),
        # 
        'alljoyn_proxybusobject_methodcallasync_member': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeFunction([SimTypeBottom(label="alljoyn_message"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["message", "context"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "method", "replyFunc", "args", "numArgs", "context", "timeout", "flags"]),
        # 
        'alljoyn_proxybusobject_parsexml': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "xml", "identifier"]),
        # 
        'alljoyn_proxybusobject_secureconnection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "forceAuth"]),
        # 
        'alljoyn_proxybusobject_secureconnectionasync': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxyObj", "forceAuth"]),
        # 
        'alljoyn_proxybusobject_getinterface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["proxyObj", "iface"]),
        # 
        'alljoyn_proxybusobject_getinterfaces': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["proxyObj", "ifaces", "numIfaces"]),
        # 
        'alljoyn_proxybusobject_getpath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["proxyObj"]),
        # 
        'alljoyn_proxybusobject_getservicename': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["proxyObj"]),
        # 
        'alljoyn_proxybusobject_getuniquename': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["proxyObj"]),
        # 
        'alljoyn_proxybusobject_getsessionid': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["proxyObj"]),
        # 
        'alljoyn_proxybusobject_implementsinterface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["proxyObj", "iface"]),
        # 
        'alljoyn_proxybusobject_copy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["source"]),
        # 
        'alljoyn_proxybusobject_isvalid': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["proxyObj"]),
        # 
        'alljoyn_proxybusobject_issecure': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["proxyObj"]),
        # 
        'alljoyn_proxybusobject_enablepropertycaching': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["proxyObj"]),
        # 
        'alljoyn_permissionconfigurationlistener_create': SimTypeFunction([SimTypePointer(SimStruct({"factory_reset": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["context"]), offset=0), "policy_changed": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0), "start_management": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0), "end_management": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0)}, name="alljoyn_permissionconfigurationlistener_callbacks", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["callbacks", "context"]),
        # 
        'alljoyn_permissionconfigurationlistener_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["listener"]),
        # 
        'alljoyn_sessionlistener_create': SimTypeFunction([SimTypePointer(SimStruct({"session_lost": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="alljoyn_sessionlostreason")], SimTypeBottom(label="Void"), arg_names=["context", "sessionId", "reason"]), offset=0), "session_member_added": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="PSTR")], SimTypeBottom(label="Void"), arg_names=["context", "sessionId", "uniqueName"]), offset=0), "session_member_removed": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="PSTR")], SimTypeBottom(label="Void"), arg_names=["context", "sessionId", "uniqueName"]), offset=0)}, name="alljoyn_sessionlistener_callbacks", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["callbacks", "context"]),
        # 
        'alljoyn_sessionlistener_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["listener"]),
        # 
        'alljoyn_sessionportlistener_create': SimTypeFunction([SimTypePointer(SimStruct({"accept_session_joiner": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeBottom(label="PSTR"), SimTypeBottom(label="alljoyn_sessionopts")], SimTypeInt(signed=True, label="Int32"), arg_names=["context", "sessionPort", "joiner", "opts"]), offset=0), "session_joined": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="PSTR")], SimTypeBottom(label="Void"), arg_names=["context", "sessionPort", "id", "joiner"]), offset=0)}, name="alljoyn_sessionportlistener_callbacks", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["callbacks", "context"]),
        # 
        'alljoyn_sessionportlistener_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["listener"]),
        # 
        'alljoyn_aboutlistener_create': SimTypeFunction([SimTypePointer(SimStruct({"about_listener_announced": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="PSTR"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeBottom(label="alljoyn_msgarg"), SimTypeBottom(label="alljoyn_msgarg")], SimTypeBottom(label="Void"), arg_names=["context", "busName", "version", "port", "objectDescriptionArg", "aboutDataArg"]), offset=0)}, name="alljoyn_aboutlistener_callback", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["callback", "context"]),
        # 
        'alljoyn_aboutlistener_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["listener"]),
        # 
        'alljoyn_busattachment_create': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["applicationName", "allowRemoteMessages"]),
        # 
        'alljoyn_busattachment_create_concurrency': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["applicationName", "allowRemoteMessages", "concurrency"]),
        # 
        'alljoyn_busattachment_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_start': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_stop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_join': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_getconcurrency': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_getconnectspec': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_enableconcurrentcallbacks': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_createinterface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "name", "iface"]),
        # 
        'alljoyn_busattachment_createinterface_secure': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="alljoyn_interfacedescription_securitypolicy")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "name", "iface", "secPolicy"]),
        # 
        'alljoyn_busattachment_connect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "connectSpec"]),
        # 
        'alljoyn_busattachment_registerbuslistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["bus", "listener"]),
        # 
        'alljoyn_busattachment_unregisterbuslistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["bus", "listener"]),
        # 
        'alljoyn_busattachment_findadvertisedname': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "namePrefix"]),
        # 
        'alljoyn_busattachment_findadvertisednamebytransport': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "namePrefix", "transports"]),
        # 
        'alljoyn_busattachment_cancelfindadvertisedname': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "namePrefix"]),
        # 
        'alljoyn_busattachment_cancelfindadvertisednamebytransport': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "namePrefix", "transports"]),
        # 
        'alljoyn_busattachment_advertisename': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "name", "transports"]),
        # 
        'alljoyn_busattachment_canceladvertisename': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "name", "transports"]),
        # 
        'alljoyn_busattachment_getinterface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus", "name"]),
        # 
        'alljoyn_busattachment_joinsession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "sessionHost", "sessionPort", "listener", "sessionId", "opts"]),
        # 
        'alljoyn_busattachment_joinsessionasync': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="QStatus"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="alljoyn_sessionopts"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["status", "sessionId", "opts", "context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "sessionHost", "sessionPort", "listener", "opts", "callback", "context"]),
        # 
        'alljoyn_busattachment_registerbusobject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "obj"]),
        # 
        'alljoyn_busattachment_registerbusobject_secure': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "obj"]),
        # 
        'alljoyn_busattachment_unregisterbusobject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["bus", "object"]),
        # 
        'alljoyn_busattachment_requestname': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "requestedName", "flags"]),
        # 
        'alljoyn_busattachment_releasename': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "name"]),
        # 
        'alljoyn_busattachment_bindsessionport': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "sessionPort", "opts", "listener"]),
        # 
        'alljoyn_busattachment_unbindsessionport': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "sessionPort"]),
        # 
        'alljoyn_busattachment_enablepeersecurity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "authMechanisms", "listener", "keyStoreFileName", "isShared"]),
        # 
        'alljoyn_busattachment_enablepeersecuritywithpermissionconfigurationlistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "authMechanisms", "authListener", "keyStoreFileName", "isShared", "permissionConfigurationListener"]),
        # 
        'alljoyn_busattachment_ispeersecurityenabled': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_createinterfacesfromxml': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "xml"]),
        # 
        'alljoyn_busattachment_getinterfaces': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["bus", "ifaces", "numIfaces"]),
        # 
        'alljoyn_busattachment_deleteinterface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "iface"]),
        # 
        'alljoyn_busattachment_isstarted': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_isstopping': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_isconnected': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_disconnect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "unused"]),
        # 
        'alljoyn_busattachment_getdbusproxyobj': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_getalljoynproxyobj': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_getalljoyndebugobj': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_getuniquename': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_getglobalguidstring': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_registersignalhandler': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="alljoyn_message")], SimTypeBottom(label="Void"), arg_names=["member", "srcPath", "message"]), offset=0), SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "signal_handler", "member", "srcPath"]),
        # 
        'alljoyn_busattachment_registersignalhandlerwithrule': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="alljoyn_message")], SimTypeBottom(label="Void"), arg_names=["member", "srcPath", "message"]), offset=0), SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "signal_handler", "member", "matchRule"]),
        # 
        'alljoyn_busattachment_unregistersignalhandler': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="alljoyn_message")], SimTypeBottom(label="Void"), arg_names=["member", "srcPath", "message"]), offset=0), SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "signal_handler", "member", "srcPath"]),
        # 
        'alljoyn_busattachment_unregistersignalhandlerwithrule': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="alljoyn_message")], SimTypeBottom(label="Void"), arg_names=["member", "srcPath", "message"]), offset=0), SimStruct({"iface": SimTypeBottom(label="alljoyn_interfacedescription"), "memberType": SimTypeInt(signed=False, label="alljoyn_messagetype"), "name": SimTypeBottom(label="PSTR"), "signature": SimTypeBottom(label="PSTR"), "returnSignature": SimTypeBottom(label="PSTR"), "argNames": SimTypeBottom(label="PSTR"), "internal_member": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="alljoyn_interfacedescription_member", pack=False, align=None), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "signal_handler", "member", "matchRule"]),
        # 
        'alljoyn_busattachment_unregisterallhandlers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_registerkeystorelistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "listener"]),
        # 
        'alljoyn_busattachment_reloadkeystore': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_clearkeystore': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_clearkeys': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "guid"]),
        # 
        'alljoyn_busattachment_setkeyexpiration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "guid", "timeout"]),
        # 
        'alljoyn_busattachment_getkeyexpiration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "guid", "timeout"]),
        # 
        'alljoyn_busattachment_addlogonentry': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "authMechanism", "userName", "password"]),
        # 
        'alljoyn_busattachment_addmatch': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "rule"]),
        # 
        'alljoyn_busattachment_removematch': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "rule"]),
        # 
        'alljoyn_busattachment_setsessionlistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "sessionId", "listener"]),
        # 
        'alljoyn_busattachment_leavesession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "sessionId"]),
        # 
        'alljoyn_busattachment_secureconnection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "name", "forceAuth"]),
        # 
        'alljoyn_busattachment_secureconnectionasync': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "name", "forceAuth"]),
        # 
        'alljoyn_busattachment_removesessionmember': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "sessionId", "memberName"]),
        # 
        'alljoyn_busattachment_setlinktimeout': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "sessionid", "linkTimeout"]),
        # 
        'alljoyn_busattachment_setlinktimeoutasync': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="QStatus"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["status", "timeout", "context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "sessionid", "linkTimeout", "callback", "context"]),
        # 
        'alljoyn_busattachment_namehasowner': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "name", "hasOwner"]),
        # 
        'alljoyn_busattachment_getpeerguid': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "name", "guid", "guidSz"]),
        # 
        'alljoyn_busattachment_setdaemondebug': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "module", "level"]),
        # 
        'alljoyn_busattachment_gettimestamp': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        # 
        'alljoyn_busattachment_ping': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "name", "timeout"]),
        # 
        'alljoyn_busattachment_registeraboutlistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["bus", "aboutListener"]),
        # 
        'alljoyn_busattachment_unregisteraboutlistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["bus", "aboutListener"]),
        # 
        'alljoyn_busattachment_unregisterallaboutlisteners': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_whoimplements_interfaces': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "implementsInterfaces", "numberInterfaces"]),
        # 
        'alljoyn_busattachment_whoimplements_interface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "implementsInterface"]),
        # 
        'alljoyn_busattachment_cancelwhoimplements_interfaces': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "implementsInterfaces", "numberInterfaces"]),
        # 
        'alljoyn_busattachment_cancelwhoimplements_interface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "implementsInterface"]),
        # 
        'alljoyn_busattachment_getpermissionconfigurator': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus"]),
        # 
        'alljoyn_busattachment_registerapplicationstatelistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "listener"]),
        # 
        'alljoyn_busattachment_unregisterapplicationstatelistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["bus", "listener"]),
        # 
        'alljoyn_busattachment_deletedefaultkeystore': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["applicationName"]),
        # 
        'alljoyn_abouticonobj_create': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({}, name="_alljoyn_abouticon_handle", pack=False, align=None), offset=0)], SimTypePointer(SimStruct({}, name="_alljoyn_abouticonobj_handle", pack=False, align=None), offset=0), arg_names=["bus", "icon"]),
        # 
        'alljoyn_abouticonobj_destroy': SimTypeFunction([SimTypePointer(SimStruct({}, name="_alljoyn_abouticonobj_handle", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["icon"]),
        # 
        'alljoyn_abouticonproxy_create': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimStruct({}, name="_alljoyn_abouticonproxy_handle", pack=False, align=None), offset=0), arg_names=["bus", "busName", "sessionId"]),
        # 
        'alljoyn_abouticonproxy_destroy': SimTypeFunction([SimTypePointer(SimStruct({}, name="_alljoyn_abouticonproxy_handle", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["proxy"]),
        # 
        'alljoyn_abouticonproxy_geticon': SimTypeFunction([SimTypePointer(SimStruct({}, name="_alljoyn_abouticonproxy_handle", pack=False, align=None), offset=0), SimTypePointer(SimStruct({}, name="_alljoyn_abouticon_handle", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "icon"]),
        # 
        'alljoyn_abouticonproxy_getversion': SimTypeFunction([SimTypePointer(SimStruct({}, name="_alljoyn_abouticonproxy_handle", pack=False, align=None), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "version"]),
        # 
        'alljoyn_aboutdatalistener_create': SimTypeFunction([SimTypePointer(SimStruct({"about_datalistener_getaboutdata": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="alljoyn_msgarg"), SimTypeBottom(label="PSTR")], SimTypeInt(signed=False, label="QStatus"), arg_names=["context", "msgArg", "language"]), offset=0), "about_datalistener_getannouncedaboutdata": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="alljoyn_msgarg")], SimTypeInt(signed=False, label="QStatus"), arg_names=["context", "msgArg"]), offset=0)}, name="alljoyn_aboutdatalistener_callbacks", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["callbacks", "context"]),
        # 
        'alljoyn_aboutdatalistener_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["listener"]),
        # 
        'alljoyn_aboutobj_create': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="alljoyn_about_announceflag")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus", "isAnnounced"]),
        # 
        'alljoyn_aboutobj_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["obj"]),
        # 
        'alljoyn_aboutobj_announce': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["obj", "sessionPort", "aboutData"]),
        # 
        'alljoyn_aboutobj_announce_using_datalistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["obj", "sessionPort", "aboutListener"]),
        # 
        'alljoyn_aboutobj_unannounce': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["obj"]),
        # 
        'alljoyn_aboutobjectdescription_create': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        # 
        'alljoyn_aboutobjectdescription_create_full': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["arg"]),
        # 
        'alljoyn_aboutobjectdescription_createfrommsgarg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["description", "arg"]),
        # 
        'alljoyn_aboutobjectdescription_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["description"]),
        # 
        'alljoyn_aboutobjectdescription_getpaths': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["description", "paths", "numPaths"]),
        # 
        'alljoyn_aboutobjectdescription_getinterfaces': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["description", "path", "interfaces", "numInterfaces"]),
        # 
        'alljoyn_aboutobjectdescription_getinterfacepaths': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["description", "interfaceName", "paths", "numPaths"]),
        # 
        'alljoyn_aboutobjectdescription_clear': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["description"]),
        # 
        'alljoyn_aboutobjectdescription_haspath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["description", "path"]),
        # 
        'alljoyn_aboutobjectdescription_hasinterface': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["description", "interfaceName"]),
        # 
        'alljoyn_aboutobjectdescription_hasinterfaceatpath': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["description", "path", "interfaceName"]),
        # 
        'alljoyn_aboutobjectdescription_getmsgarg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["description", "msgArg"]),
        # 
        'alljoyn_aboutproxy_create': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus", "busName", "sessionId"]),
        # 
        'alljoyn_aboutproxy_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["proxy"]),
        # 
        'alljoyn_aboutproxy_getobjectdescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "objectDesc"]),
        # 
        'alljoyn_aboutproxy_getaboutdata': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "language", "data"]),
        # 
        'alljoyn_aboutproxy_getversion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "version"]),
        # 
        'alljoyn_pinglistener_create': SimTypeFunction([SimTypePointer(SimStruct({"destination_found": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR")], SimTypeBottom(label="Void"), arg_names=["context", "group", "destination"]), offset=0), "destination_lost": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="PSTR"), SimTypeBottom(label="PSTR")], SimTypeBottom(label="Void"), arg_names=["context", "group", "destination"]), offset=0)}, name="alljoyn_pinglistener_callback", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["callback", "context"]),
        # 
        'alljoyn_pinglistener_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["listener"]),
        # 
        'alljoyn_autopinger_create': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus"]),
        # 
        'alljoyn_autopinger_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["autopinger"]),
        # 
        'alljoyn_autopinger_pause': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["autopinger"]),
        # 
        'alljoyn_autopinger_resume': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["autopinger"]),
        # 
        'alljoyn_autopinger_addpinggroup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["autopinger", "group", "listener", "pinginterval"]),
        # 
        'alljoyn_autopinger_removepinggroup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["autopinger", "group"]),
        # 
        'alljoyn_autopinger_setpinginterval': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["autopinger", "group", "pinginterval"]),
        # 
        'alljoyn_autopinger_adddestination': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["autopinger", "group", "destination"]),
        # 
        'alljoyn_autopinger_removedestination': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="QStatus"), arg_names=["autopinger", "group", "destination", "removeall"]),
        # 
        'alljoyn_getversion': SimTypeFunction([], SimTypePointer(SimTypeChar(label="Byte"), offset=0)),
        # 
        'alljoyn_getbuildinfo': SimTypeFunction([], SimTypePointer(SimTypeChar(label="Byte"), offset=0)),
        # 
        'alljoyn_getnumericversion': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        # 
        'alljoyn_init': SimTypeFunction([], SimTypeInt(signed=False, label="QStatus")),
        # 
        'alljoyn_shutdown': SimTypeFunction([], SimTypeInt(signed=False, label="QStatus")),
        # 
        'alljoyn_routerinit': SimTypeFunction([], SimTypeInt(signed=False, label="QStatus")),
        # 
        'alljoyn_routerinitwithconfig': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["configXml"]),
        # 
        'alljoyn_routershutdown': SimTypeFunction([], SimTypeInt(signed=False, label="QStatus")),
        # 
        'alljoyn_proxybusobject_ref_create': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["proxy"]),
        # 
        'alljoyn_proxybusobject_ref_get': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["ref"]),
        # 
        'alljoyn_proxybusobject_ref_incref': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["ref"]),
        # 
        'alljoyn_proxybusobject_ref_decref': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["ref"]),
        # 
        'alljoyn_observerlistener_create': SimTypeFunction([SimTypePointer(SimStruct({"object_discovered": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="alljoyn_proxybusobject_ref")], SimTypeBottom(label="Void"), arg_names=["context", "proxyref"]), offset=0), "object_lost": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="alljoyn_proxybusobject_ref")], SimTypeBottom(label="Void"), arg_names=["context", "proxyref"]), offset=0)}, name="alljoyn_observerlistener_callback", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["callback", "context"]),
        # 
        'alljoyn_observerlistener_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["listener"]),
        # 
        'alljoyn_observer_create': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus", "mandatoryInterfaces", "numMandatoryInterfaces"]),
        # 
        'alljoyn_observer_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["observer"]),
        # 
        'alljoyn_observer_registerlistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["observer", "listener", "triggerOnExisting"]),
        # 
        'alljoyn_observer_unregisterlistener': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["observer", "listener"]),
        # 
        'alljoyn_observer_unregisteralllisteners': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["observer"]),
        # 
        'alljoyn_observer_get': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["observer", "uniqueBusName", "objectPath"]),
        # 
        'alljoyn_observer_getfirst': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["observer"]),
        # 
        'alljoyn_observer_getnext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["observer", "proxyref"]),
        # 
        'alljoyn_passwordmanager_setcredentials': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["authMechanism", "password"]),
        # 
        'alljoyn_securityapplicationproxy_getpermissionmanagementsessionport': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        # 
        'alljoyn_securityapplicationproxy_create': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["bus", "appBusName", "sessionId"]),
        # 
        'alljoyn_securityapplicationproxy_destroy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["proxy"]),
        # 
        'alljoyn_securityapplicationproxy_claim': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "caKey", "identityCertificateChain", "groupId", "groupSize", "groupAuthority", "manifestsXmls", "manifestsCount"]),
        # 
        'alljoyn_securityapplicationproxy_getmanifesttemplate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "manifestTemplateXml"]),
        # 
        'alljoyn_securityapplicationproxy_manifesttemplate_destroy': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["manifestTemplateXml"]),
        # 
        'alljoyn_securityapplicationproxy_getapplicationstate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="alljoyn_applicationstate"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "applicationState"]),
        # 
        'alljoyn_securityapplicationproxy_getclaimcapabilities': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "capabilities"]),
        # 
        'alljoyn_securityapplicationproxy_getclaimcapabilitiesadditionalinfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "additionalInfo"]),
        # 
        'alljoyn_securityapplicationproxy_getpolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "policyXml"]),
        # 
        'alljoyn_securityapplicationproxy_getdefaultpolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "policyXml"]),
        # 
        'alljoyn_securityapplicationproxy_policy_destroy': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["policyXml"]),
        # 
        'alljoyn_securityapplicationproxy_updatepolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "policyXml"]),
        # 
        'alljoyn_securityapplicationproxy_updateidentity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "identityCertificateChain", "manifestsXmls", "manifestsCount"]),
        # 
        'alljoyn_securityapplicationproxy_installmembership': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "membershipCertificateChain"]),
        # 
        'alljoyn_securityapplicationproxy_reset': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy"]),
        # 
        'alljoyn_securityapplicationproxy_resetpolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy"]),
        # 
        'alljoyn_securityapplicationproxy_startmanagement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy"]),
        # 
        'alljoyn_securityapplicationproxy_endmanagement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy"]),
        # 
        'alljoyn_securityapplicationproxy_geteccpublickey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["proxy", "eccPublicKey"]),
        # 
        'alljoyn_securityapplicationproxy_eccpublickey_destroy': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["eccPublicKey"]),
        # 
        'alljoyn_securityapplicationproxy_signmanifest': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["unsignedManifestXml", "identityCertificatePem", "signingPrivateKeyPem", "signedManifestXml"]),
        # 
        'alljoyn_securityapplicationproxy_manifest_destroy': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["signedManifestXml"]),
        # 
        'alljoyn_securityapplicationproxy_computemanifestdigest': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["unsignedManifestXml", "identityCertificatePem", "digest", "digestSize"]),
        # 
        'alljoyn_securityapplicationproxy_digest_destroy': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["digest"]),
        # 
        'alljoyn_securityapplicationproxy_setmanifestsignature': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0)], SimTypeInt(signed=False, label="QStatus"), arg_names=["unsignedManifestXml", "identityCertificatePem", "signature", "signatureSize", "signedManifestXml"]),
    }

lib.set_prototypes(prototypes)
