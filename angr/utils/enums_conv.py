# pylint:disable=no-member
import logging

l = logging.getLogger(name=__name__)

from ..protos.primitives_pb2 import Edge


_CFG_JUMPKINDS = {
    None: Edge.UnknownJumpkind,
    "Ijk_Boring": Edge.Boring,
    "Ijk_Call": Edge.Call,
    "Ijk_Ret": Edge.Return,
    "Ijk_FakeRet": Edge.FakeReturn,
    "Ijk_Syscall": Edge.Syscall,
    "Ijk_Sys_syscall": Edge.Sys_syscall,
    "Ijk_Sys_int128": Edge.Sys_int128,
    "Ijk_NoDecode": Edge.NoDecode,
    "Ijk_EmWarn": Edge.EmWarn,
    "Ijk_SigFPE_IntDiv": Edge.SigFPE_IntDiv,
    "Ijk_SigTRAP": Edge.SigTRAP,
    "Ijk_SigSEGV": Edge.SigSEGV,
    "Ijk_MapFail": Edge.MapFail,
    "Ijk_NoRedir": Edge.NoRedir,
    "Ijk_ClientReq": Edge.ClientReq,
    "Ijk_Exception": Edge.Exception,
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
