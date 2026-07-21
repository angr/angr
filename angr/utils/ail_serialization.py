"""
Typed protobuf pack/parse helpers for AIL-typed containers.

AIL leaves (Block / Statement / Expression) serialize through their native ``to_bytes()`` methods (postcard,
implemented in Rust); the helpers here only encode the Python container structure around them using the typed
messages in :mod:`angr.protos.ail_types_pb2`. There is deliberately no generic fallback: any value shape that is not
covered by the schema raises ``TypeError`` naming the offender, so the schema stays the single source of truth.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angr.protos import ail_types_pb2
from angr.rustylib.ailment import Block, Expression

if TYPE_CHECKING:
    import networkx

    from angr.sim_variable import SimVariable


# ---------------------------------------------------------------------------------------------------------------------
# SimVariable polymorphic encoding
# ---------------------------------------------------------------------------------------------------------------------


def simvar_to_bytes_polymorphic(v: SimVariable) -> bytes:
    """Polymorphic SimVariable encoding: ``b"<ClassName>\\0<proto bytes>"``."""
    return type(v).__name__.encode("ascii") + b"\0" + v.serialize()


def simvar_from_bytes_polymorphic(b: bytes) -> SimVariable:
    import angr.sim_variable as sv_mod

    sep = b.index(b"\0")
    cls_name = b[:sep].decode("ascii")
    return getattr(sv_mod, cls_name).parse(b[sep + 1 :])


# ---------------------------------------------------------------------------------------------------------------------
# networkx.DiGraph[ailment.Block]
# ---------------------------------------------------------------------------------------------------------------------

_EDGE_TYPE_TO_ENUM = {
    "transition": ail_types_pb2.AIL_EDGE_TRANSITION,
    "exception": ail_types_pb2.AIL_EDGE_EXCEPTION,
    "fake_return": ail_types_pb2.AIL_EDGE_FAKE_RETURN,
    "call": ail_types_pb2.AIL_EDGE_CALL,
    "syscall": ail_types_pb2.AIL_EDGE_SYSCALL,
    "return": ail_types_pb2.AIL_EDGE_RETURN,
}
_ENUM_TO_EDGE_TYPE = {v: k for k, v in _EDGE_TYPE_TO_ENUM.items()}


def _pack_edge_data(data: dict[str, Any], out: ail_types_pb2.AilEdgeData) -> bool:
    """Fill an AilEdgeData message from a networkx edge-attribute dict. Returns True if any field was set.

    Attributes with value None are packed as unset (and come back as absent keys); unknown keys or value types raise
    ``TypeError`` -- extend the AilEdgeData schema when a new edge attribute is introduced.
    """
    any_set = False
    for key, value in data.items():
        if value is None:
            continue
        if key == "type":
            if value not in _EDGE_TYPE_TO_ENUM:
                raise TypeError(f"Unsupported AIL graph edge type {value!r}; extend AilEdgeType in ail_types.proto")
            out.type = _EDGE_TYPE_TO_ENUM[value]
        elif key == "outside":
            out.outside = bool(value)
        elif key == "confirmed":
            out.confirmed = bool(value)
        elif key == "ins_addr":
            out.ins_addr = value
        elif key == "stmt_idx":
            out.stmt_idx = value
        else:
            raise TypeError(f"Unsupported AIL graph edge attribute {key!r}; extend AilEdgeData in ail_types.proto")
        any_set = True
    return any_set


def _parse_edge_data(msg: ail_types_pb2.AilEdgeData) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if msg.HasField("type"):
        data["type"] = _ENUM_TO_EDGE_TYPE[msg.type]
    if msg.HasField("outside"):
        data["outside"] = msg.outside
    if msg.HasField("ins_addr"):
        data["ins_addr"] = msg.ins_addr
    if msg.HasField("stmt_idx"):
        data["stmt_idx"] = msg.stmt_idx
    if msg.HasField("confirmed"):
        data["confirmed"] = msg.confirmed
    return data


def pack_graph(graph: networkx.DiGraph) -> ail_types_pb2.AilGraph:
    """Encode a DiGraph of ailment Blocks. Node identity is preserved through per-graph block indices."""
    msg = ail_types_pb2.AilGraph()
    node_to_idx: dict[Any, int] = {}
    for i, node in enumerate(graph.nodes):
        if not isinstance(node, Block):
            raise TypeError(f"Unsupported AIL graph node type {type(node).__name__}; only ailment.Block is allowed")
        node_to_idx[node] = i
        msg.blocks.append(node.to_bytes())
    for src, dst, data in graph.edges(data=True):
        edge = msg.edges.add()
        edge.src = node_to_idx[src]
        edge.dst = node_to_idx[dst]
        if data:
            edge_data = ail_types_pb2.AilEdgeData()
            if _pack_edge_data(data, edge_data):
                edge.data.CopyFrom(edge_data)
    return msg


def parse_graph(msg: ail_types_pb2.AilGraph) -> networkx.DiGraph:
    import networkx

    graph = networkx.DiGraph()
    blocks = [Block.from_bytes(b) for b in msg.blocks]
    graph.add_nodes_from(blocks)
    for edge in msg.edges:
        data = _parse_edge_data(edge.data) if edge.HasField("data") else {}
        graph.add_edge(blocks[edge.src], blocks[edge.dst], **data)
    return graph


# ---------------------------------------------------------------------------------------------------------------------
# dict[int, tuple[VirtualVariable, SimVariable]]
# ---------------------------------------------------------------------------------------------------------------------


def pack_arg_vvars(arg_vvars: dict[int, tuple[Any, Any]]) -> ail_types_pb2.ArgVVars:
    msg = ail_types_pb2.ArgVVars()
    for idx, (vvar, simvar) in arg_vvars.items():
        entry = msg.entries[idx]
        entry.vvar = vvar.to_bytes()
        entry.simvar = simvar_to_bytes_polymorphic(simvar)
    return msg


def parse_arg_vvars(msg: ail_types_pb2.ArgVVars) -> dict[int, tuple[Any, Any]]:
    return {
        idx: (Expression.from_bytes(entry.vvar), simvar_from_bytes_polymorphic(entry.simvar))
        for idx, entry in msg.entries.items()
    }


# ---------------------------------------------------------------------------------------------------------------------
# set[tuple[int, Expression]]
# ---------------------------------------------------------------------------------------------------------------------


def pack_ite_exprs(ite_exprs: set[tuple[int, Any]]) -> ail_types_pb2.IteExprs:
    msg = ail_types_pb2.IteExprs()
    for addr, expr in sorted(ite_exprs, key=lambda t: t[0]):
        entry = msg.entries.add()
        entry.addr = addr
        entry.expr = expr.to_bytes()
    return msg


def parse_ite_exprs(msg: ail_types_pb2.IteExprs) -> set[tuple[int, Any]]:
    return {(entry.addr, Expression.from_bytes(entry.expr)) for entry in msg.entries}


# ---------------------------------------------------------------------------------------------------------------------
# Static buffer parameters (optimization_passes.static_vvar_rewriter)
# ---------------------------------------------------------------------------------------------------------------------


def pack_static_vvars(static_vvars: dict[int, Any]) -> ail_types_pb2.StaticVVars:
    from angr.analyses.decompiler.optimization_passes.static_vvar_rewriter import FixedBufferPtr

    msg = ail_types_pb2.StaticVVars()
    for varid, value in static_vvars.items():
        entry = msg.entries[varid]
        if isinstance(value, FixedBufferPtr):
            entry.ptr.buffer_ident = value.buffer_ident
            entry.ptr.offset = value.offset
        elif isinstance(value, Expression):
            entry.const_expr = value.to_bytes()
        else:
            raise TypeError(f"Unsupported static_vvars value type {type(value).__name__}")
    return msg


def parse_static_vvars(msg: ail_types_pb2.StaticVVars) -> dict[int, Any]:
    from angr.analyses.decompiler.optimization_passes.static_vvar_rewriter import FixedBufferPtr

    result: dict[int, Any] = {}
    for varid, entry in msg.entries.items():
        if entry.WhichOneof("v") == "ptr":
            result[varid] = FixedBufferPtr(entry.ptr.buffer_ident, offset=entry.ptr.offset)
        else:
            result[varid] = Expression.from_bytes(entry.const_expr)
    return result


def pack_static_buffers(static_buffers: dict[str, Any]) -> ail_types_pb2.StaticBuffers:
    msg = ail_types_pb2.StaticBuffers()
    for key, buf in static_buffers.items():
        entry = msg.entries[key]
        entry.ident = buf.ident
        entry.size = buf.size
        entry.content = buf.content
    return msg


def parse_static_buffers(msg: ail_types_pb2.StaticBuffers) -> dict[str, Any]:
    from angr.analyses.decompiler.optimization_passes.static_vvar_rewriter import FixedBuffer

    return {key: FixedBuffer(entry.ident, entry.size, entry.content) for key, entry in msg.entries.items()}
