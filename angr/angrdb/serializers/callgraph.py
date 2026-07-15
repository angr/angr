from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import networkx

from angr.angrdb.models import DbCallGraph

if TYPE_CHECKING:
    from angr.angrdb.models import DbKnowledgeBase

l = logging.getLogger(name=__name__)


class CallGraphSerializer:
    """
    Serialize/unserialize the callgraph of a function manager (a networkx.MultiDiGraph whose nodes are function
    addresses).

    The graph is stored as a JSON document with the exact node set as well as all edges, including their keys and
    data dicts, so that edge multiplicity and edge data round-trip exactly.
    """

    @staticmethod
    def dump(session, db_kb: DbKnowledgeBase, callgraph: networkx.MultiDiGraph) -> None:
        """
        :param session:
        :param db_kb:       The database object for KnowledgeBase.
        :param callgraph:   The callgraph to dump.
        """

        # remove the existing callgraph (if there is one)
        session.query(DbCallGraph).filter_by(kb=db_kb).delete()

        d = {
            "nodes": list(callgraph.nodes),
            "edges": [[src, dst, key, data] for src, dst, key, data in callgraph.edges(keys=True, data=True)],
        }
        try:
            blob = json.dumps(d, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            # the callgraph contains data that cannot be JSON-serialized; do not store the callgraph. it will be
            # rebuilt from function transition graphs on load.
            l.warning("The callgraph cannot be JSON-serialized. It will not be stored in the angr database.")
            return

        db_callgraph = DbCallGraph(kb=db_kb, blob=blob)
        session.add(db_callgraph)

    @staticmethod
    def load(session, db_kb: DbKnowledgeBase) -> networkx.MultiDiGraph | None:
        """
        :param session:
        :param db_kb:   The database object for KnowledgeBase.
        :return:        The loaded callgraph, or None if no callgraph is stored in the database (e.g., for databases
                        created before callgraph serialization was introduced).
        """

        db_callgraph = session.query(DbCallGraph).filter_by(kb=db_kb).scalar()
        if db_callgraph is None or db_callgraph.blob is None:
            return None

        d = json.loads(db_callgraph.blob.decode("utf-8"))
        callgraph: networkx.MultiDiGraph = networkx.MultiDiGraph()
        callgraph.add_nodes_from(d["nodes"])
        for src, dst, key, data in d["edges"]:
            callgraph.add_edge(src, dst, key=key, **data)
        return callgraph
