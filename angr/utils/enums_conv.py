# pylint:disable=no-member
from __future__ import annotations
import logging

from angr.protos.primitives_pb2 import Edge

l = logging.getLogger(name=__name__)

_CFG_JUMPKINDS = {
    None: Edge.UnknownJumpkind,
    "Ijk_8jzf8": Edge._8jzf8,
    "Ijk_Boring": Edge.Boring,
    "Ijk_Call": Edge.Call,
    "Ijk_ClientReq": Edge.ClientReq,
    "Ijk_EmFail": Edge.EmFail,
    "Ijk_EmWarn": Edge.EmWarn,
    "Ijk_Exception": Edge.Exception,
    "Ijk_FakeRet": Edge.FakeReturn,
    "Ijk_FlushDCache": Edge.FlushDCache,
    "Ijk_InvalICache": Edge.InvalICache,
    "Ijk_MapFail": Edge.MapFail,
    "Ijk_NoDecode": Edge.NoDecode,
    "Ijk_NoRedir": Edge.NoRedir,
    "Ijk_Privileged": Edge.Privileged,
    "Ijk_Ret": Edge.Return,
    "Ijk_SigBUS": Edge.SigBUS,
    "Ijk_SigFPE": Edge.SigFPE,
    "Ijk_SigFPE_IntDiv": Edge.SigFPE_IntDiv,
    "Ijk_SigFPE_IntOvf": Edge.SigFPE_IntOvf,
    "Ijk_SigILL": Edge.SigILL,
    "Ijk_SigSEGV": Edge.SigSEGV,
    "Ijk_SigTRAP": Edge.SigTRAP,
    "Ijk_Syscall": Edge.Syscall,
    "Ijk_Sys_int": Edge.Sys_int,
    "Ijk_Sys_int128": Edge.Sys_int128,
    "Ijk_Sys_int129": Edge.Sys_int129,
    "Ijk_Sys_int130": Edge.Sys_int130,
    "Ijk_Sys_int145": Edge.Sys_int145,
    "Ijk_Sys_int210": Edge.Sys_int210,
    "Ijk_Sys_int32": Edge.Sys_int32,
    "Ijk_Sys_syscall": Edge.Sys_syscall,
    "Ijk_Sys_sysenter": Edge.Sys_sysenter,
    "Ijk_Yield": Edge.Yield,
}


_PB_TO_CFG_JUMPKINDS = {}
for k, v in _CFG_JUMPKINDS.items():
    _PB_TO_CFG_JUMPKINDS[v] = k


_FUNCTION_EDGETYPES = {
    None: Edge.UnknownJumpkind,
    "transition": Edge.Boring,
    "call": Edge.Call,
    "return": Edge.Return,
    "fake_return": Edge.FakeReturn,
    "syscall": Edge.Syscall,
    "exception": Edge.Exception,
}


_PB_TO_FUNCTION_EDGETYPES = {}
for k, v in _FUNCTION_EDGETYPES.items():
    _PB_TO_FUNCTION_EDGETYPES[v] = k


def cfg_jumpkind_to_pb(jk):
    try:
        return _CFG_JUMPKINDS[jk]
    except KeyError:
        l.error("Unsupported CFG jumpkind %s in cfg_jumpkind_to_pb. Please report it on GitHub.", jk)
        return None


def func_edge_type_to_pb(jk):
    try:
        return _FUNCTION_EDGETYPES[jk]
    except KeyError:
        l.error("Unsupported function edge type %s in func_edge_type_to_pb. Please report it on GitHub.", jk)
        return None


def cfg_jumpkind_from_pb(pb):
    try:
        return _PB_TO_CFG_JUMPKINDS[pb]
    except KeyError:
        l.error("Unsupported protobuf jumpkind %s in cfg_jumpkind_from_pb. Please report it on GitHub.", pb)
        return None


def func_edge_type_from_pb(pb):
    try:
        return _PB_TO_FUNCTION_EDGETYPES[pb]
    except KeyError:
        l.error("Unsupported protobuf jumpkind %s in func_edge_type_to_pb. Please report it on GitHub.", pb)
        return None
