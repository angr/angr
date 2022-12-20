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
lib.set_library_names("api-ms-win-core-winrt-l1-1-0.dll")
prototypes = \
    {
        #
        'RoInitialize': SimTypeFunction([SimTypeInt(signed=False, label="RO_INIT_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["initType"]),
        #
        'RoUninitialize': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'RoActivateInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IInspectable"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["activatableClassId", "instance"]),
        #
        'RoRegisterActivationFactories': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["activatableClassIds", "activationFactoryCallbacks", "count", "cookie"]),
        #
        'RoRevokeActivationFactories': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["cookie"]),
        #
        'RoGetActivationFactory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["activatableClassId", "iid", "factory"]),
        #
        'RoRegisterForApartmentShutdown': SimTypeFunction([SimTypeBottom(label="IApartmentShutdown"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["callbackObject", "apartmentIdentifier", "regCookie"]),
        #
        'RoUnregisterForApartmentShutdown': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["regCookie"]),
        #
        'RoGetApartmentIdentifier': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["apartmentIdentifier"]),
    }

lib.set_prototypes(prototypes)
