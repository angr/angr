from __future__ import annotations

import json

from angr.angrdb.models import DbPattern
from angr.knowledge_plugins.patterns import Patterns, StoredPattern


class PatternsSerializer:
    """
    Serialize/unserialize user-authored fuzzy patterns to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb, patterns: Patterns):
        # rewritten wholesale, like bookmarks, so removals persist
        for db_pattern in list(db_kb.patterns):
            session.delete(db_pattern)
        for stored in patterns:
            session.add(
                DbPattern(
                    kb=db_kb,
                    name=stored.name,
                    enabled=stored.enabled,
                    min_similarity=stored.min_similarity,
                    origin_func=stored.origin_func,
                    require_verified=stored.require_verified,
                    created_at=stored.created_at,
                    pattern=json.dumps(stored.to_dict()["pattern"]),
                )
            )

    @staticmethod
    def load(session, db_kb, kb) -> Patterns:  # pylint:disable=unused-argument
        patterns = Patterns(kb)
        for db_pattern in db_kb.patterns:
            patterns.store(
                StoredPattern.from_dict(
                    {
                        "pattern": json.loads(db_pattern.pattern),
                        "enabled": db_pattern.enabled,
                        "min_similarity": db_pattern.min_similarity,
                        "origin_func": db_pattern.origin_func,
                        "require_verified": True
                        if db_pattern.require_verified is None
                        else db_pattern.require_verified,
                        "created_at": db_pattern.created_at,
                    }
                )
            )
        return patterns
