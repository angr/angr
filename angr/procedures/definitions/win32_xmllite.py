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
lib.set_library_names("xmllite.dll")
prototypes = \
    {
        # 
        'CreateXmlReader': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeBottom(label="IMalloc")], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppvObject", "pMalloc"]),
        # 
        'CreateXmlReaderInputWithEncodingCodePage': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IMalloc"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pInputStream", "pMalloc", "nEncodingCodePage", "fEncodingHint", "pwszBaseUri", "ppInput"]),
        # 
        'CreateXmlReaderInputWithEncodingName': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IMalloc"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pInputStream", "pMalloc", "pwszEncodingName", "fEncodingHint", "pwszBaseUri", "ppInput"]),
        # 
        'CreateXmlWriter': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeBottom(label="IMalloc")], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppvObject", "pMalloc"]),
        # 
        'CreateXmlWriterOutputWithEncodingCodePage': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IMalloc"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pOutputStream", "pMalloc", "nEncodingCodePage", "ppOutput"]),
        # 
        'CreateXmlWriterOutputWithEncodingName': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IMalloc"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pOutputStream", "pMalloc", "pwszEncodingName", "ppOutput"]),
    }

lib.set_prototypes(prototypes)
