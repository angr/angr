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
lib.set_library_names("certadm.dll")
prototypes = \
    {
        # 
        'CertSrvIsServerOnlineW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszServerName", "pfServerOnline"]),
        # 
        'CertSrvBackupGetDynamicFileListW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbc", "ppwszzFileList", "pcbSize"]),
        # 
        'CertSrvBackupPrepareW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="CSBACKUP_TYPE"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszServerName", "grbitJet", "dwBackupFlags", "phbc"]),
        # 
        'CertSrvBackupGetDatabaseNamesW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbc", "ppwszzAttachmentInformation", "pcbSize"]),
        # 
        'CertSrvBackupOpenFileW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimUnion({"Anonymous": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_Anonymous_e__Struct", pack=False, align=None), "u": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_u_e__Struct", pack=False, align=None), "QuadPart": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbc", "pwszAttachmentName", "cbReadHintSize", "pliFileSize"]),
        # 
        'CertSrvBackupRead': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbc", "pvBuffer", "cbBuffer", "pcbRead"]),
        # 
        'CertSrvBackupClose': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbc"]),
        # 
        'CertSrvBackupGetBackupLogsW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbc", "ppwszzBackupLogFiles", "pcbSize"]),
        # 
        'CertSrvBackupTruncateLogs': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbc"]),
        # 
        'CertSrvBackupEnd': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbc"]),
        # 
        'CertSrvBackupFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pv"]),
        # 
        'CertSrvRestoreGetDatabaseLocationsW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbc", "ppwszzDatabaseLocationList", "pcbSize"]),
        # 
        'CertSrvRestorePrepareW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszServerName", "dwRestoreFlags", "phbc"]),
        # 
        'CertSrvRestoreRegisterW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"pwszDatabaseName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pwszNewDatabaseName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="CSEDB_RSTMAPW", pack=False, align=None), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hbc", "pwszCheckPointFilePath", "pwszLogPath", "rgrstmap", "crstmap", "pwszBackupLogPath", "genLow", "genHigh"]),
        # 
        'CertSrvRestoreRegisterThroughFile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"pwszDatabaseName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pwszNewDatabaseName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="CSEDB_RSTMAPW", pack=False, align=None), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hbc", "pwszCheckPointFilePath", "pwszLogPath", "rgrstmap", "crstmap", "pwszBackupLogPath", "genLow", "genHigh"]),
        # 
        'CertSrvRestoreRegisterComplete': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hbc", "hrRestoreState"]),
        # 
        'CertSrvRestoreEnd': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbc"]),
        # 
        'CertSrvServerControlW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszServerName", "dwControlFlags", "pcbOut", "ppbOut"]),
    }

lib.set_prototypes(prototypes)
