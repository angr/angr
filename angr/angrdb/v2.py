from __future__ import annotations

from typing import TYPE_CHECKING

from angr.protos import primitives_pb2
from angr.utils.enums_conv import cfg_jumpkind_from_pb, cfg_jumpkind_to_pb

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg.cfg_model import CFGModel
    from angr.knowledge_plugins.cfg.spilling_cfg import SpillingCFG

NO_INS_ADDR = 0xFFFF_FFFF_FFFF_FFFF
NO_STMT_IDX = -1


class AngrDbV2:
    """
    Reader and writer of the angrDb v2-specific CFG layout: one Edge message per CFG edge, addressed by node address
    (v3 stores the graph as segment blobs instead). Static methods only.
    """

    @staticmethod
    def edge_data(edge_pb2) -> dict:
        return {
            "jumpkind": cfg_jumpkind_from_pb(edge_pb2.jumpkind),
            "ins_addr": edge_pb2.ins_addr if edge_pb2.ins_addr != NO_INS_ADDR else None,
            "stmt_idx": edge_pb2.stmt_idx if edge_pb2.stmt_idx != NO_STMT_IDX else None,
        }

    @staticmethod
    def parse_cfg_edges(cmsg, model: CFGModel) -> None:
        """Add the per-edge messages of a v2 CFG record to a model whose nodes are already in place."""
        for edge_pb2 in cmsg.edges:
            # more than one node at a given address is unsupported, grab the first one
            src = next(model.graph.nodes_by_addr(edge_pb2.src_ea))
            dst = next(model.graph.nodes_by_addr(edge_pb2.dst_ea))
            model.graph.add_edge(src, dst, **AngrDbV2.edge_data(edge_pb2))

    @staticmethod
    def parse_cfg_edges_spilled(cmsg, graph: SpillingCFG) -> None:
        """Like parse_cfg_edges, for a graph whose nodes were bulk-imported without CFGNode objects."""
        first_key_at_addr = graph.first_key_at_addr
        for edge_pb2 in cmsg.edges:
            src_key = first_key_at_addr(edge_pb2.src_ea)
            dst_key = first_key_at_addr(edge_pb2.dst_ea)
            if src_key is None or dst_key is None:
                raise KeyError(f"CFG edge {edge_pb2.src_ea:#x} -> {edge_pb2.dst_ea:#x} refers to a missing node")
            graph.add_edge_by_key(src_key, dst_key, **AngrDbV2.edge_data(edge_pb2))

    @staticmethod
    def serialize_cfg(model: CFGModel):
        """Serialize a CFG model in the v2 layout: nodes plus per-edge messages, no graph segments."""
        cmsg = model.serialize_to_cmessage()
        cmsg.ClearField("graph_header")
        cmsg.ClearField("graph_segments")
        del cmsg.edges[:]
        for src, dst, data in model.graph.edges(data=True):
            edge = primitives_pb2.Edge()  # type:ignore
            edge.src_ea = src.addr
            edge.dst_ea = dst.addr
            edge.jumpkind = cfg_jumpkind_to_pb(data.get("jumpkind"))
            ins_addr = data.get("ins_addr")
            edge.ins_addr = NO_INS_ADDR if ins_addr is None else ins_addr
            stmt_idx = data.get("stmt_idx")
            edge.stmt_idx = NO_STMT_IDX if stmt_idx is None else stmt_idx
            cmsg.edges.append(edge)
        return cmsg
