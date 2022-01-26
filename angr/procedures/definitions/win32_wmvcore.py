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
lib.set_library_names("wmvcore.dll")
prototypes = \
    {
        # 
        'WMIsContentProtected': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszFileName", "pfIsProtected"]),
        # 
        'WMCreateWriter': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IWMWriter"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnkCert", "ppWriter"]),
        # 
        'WMCreateReader': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IWMReader"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnkCert", "dwRights", "ppReader"]),
        # 
        'WMCreateSyncReader': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IWMSyncReader"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnkCert", "dwRights", "ppSyncReader"]),
        # 
        'WMCreateEditor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IWMMetadataEditor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppEditor"]),
        # 
        'WMCreateIndexer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IWMIndexer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppIndexer"]),
        # 
        'WMCreateBackupRestorer': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IWMLicenseBackup"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCallback", "ppBackup"]),
        # 
        'WMCreateProfileManager': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IWMProfileManager"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppProfileManager"]),
        # 
        'WMCreateWriterFileSink': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IWMWriterFileSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppSink"]),
        # 
        'WMCreateWriterNetworkSink': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IWMWriterNetworkSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppSink"]),
        # 
        'WMCreateWriterPushSink': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IWMWriterPushSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppSink"]),
    }

lib.set_prototypes(prototypes)
