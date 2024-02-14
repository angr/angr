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
lib.set_library_names("tokenbinding.dll")
prototypes = \
    {
        #
        'TokenBindingGenerateBinding': SimTypeFunction([SimTypeInt(signed=False, label="TOKENBINDING_KEY_PARAMETERS_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="TOKENBINDING_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="TOKENBINDING_EXTENSION_FORMAT"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("TOKENBINDING_RESULT_DATA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["keyType", "targetURL", "bindingType", "tlsEKM", "tlsEKMSize", "extensionFormat", "extensionData", "tokenBinding", "tokenBindingSize", "resultData"]),
        #
        'TokenBindingGenerateMessage': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["tokenBindings", "tokenBindingsSize", "tokenBindingsCount", "tokenBindingMessage", "tokenBindingMessageSize"]),
        #
        'TokenBindingVerifyMessage': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="TOKENBINDING_KEY_PARAMETERS_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("TOKENBINDING_RESULT_LIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["tokenBindingMessage", "tokenBindingMessageSize", "keyType", "tlsEKM", "tlsEKMSize", "resultList"]),
        #
        'TokenBindingGetKeyTypesClient': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("TOKENBINDING_KEY_TYPES", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["keyTypes"]),
        #
        'TokenBindingGetKeyTypesServer': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("TOKENBINDING_KEY_TYPES", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["keyTypes"]),
        #
        'TokenBindingDeleteBinding': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["targetURL"]),
        #
        'TokenBindingDeleteAllBindings': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'TokenBindingGenerateID': SimTypeFunction([SimTypeInt(signed=False, label="TOKENBINDING_KEY_PARAMETERS_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("TOKENBINDING_RESULT_DATA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["keyType", "publicKey", "publicKeySize", "resultData"]),
        #
        'TokenBindingGenerateIDForUri': SimTypeFunction([SimTypeInt(signed=False, label="TOKENBINDING_KEY_PARAMETERS_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("TOKENBINDING_RESULT_DATA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["keyType", "targetUri", "resultData"]),
        #
        'TokenBindingGetHighestSupportedVersion': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["majorVersion", "minorVersion"]),
    }

lib.set_prototypes(prototypes)
