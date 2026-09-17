from __future__ import annotations

import json
import logging
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from sqlalchemy import create_engine
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from angr.errors import AngrCorruptDBError, AngrDBError, AngrIncompatibleDBError
from angr.procedures import SIM_PROCEDURES, SIM_TYPE_COLLECTIONS
from angr.procedures.definitions import load_type_collections
from angr.project import Project

from .models import Base, DbInformation
from .serializers import KnowledgeBaseSerializer, LoaderSerializer

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase


l = logging.getLogger(__name__)


class AngrDB:
    """
    AngrDB provides a storage solution for an angr project, its knowledge bases, and some other types of data. It is
    designed to use an SQL-based database as the storage backend.
    """

    ALL_TABLES = [
        "objects",
    ]

    VERSION = 1

    def __init__(self, project=None, nullpool=False):
        self.project = project
        self.config = {}
        self.engine = None
        self._nullpool = nullpool

    @contextmanager
    def open_db(self, db_str="sqlite:///:memory:"):
        try:
            kwargs = {}
            if self._nullpool:
                kwargs["poolclass"] = NullPool
            self.engine = create_engine(db_str, **kwargs)
            Base.metadata.create_all(self.engine)
            Session = sessionmaker(bind=self.engine)
            yield Session
        except DatabaseError as ex:
            raise AngrCorruptDBError("The target file may not be an angr database or it is corrupted.") from ex
        except Exception as ex:
            raise AngrDBError from ex

    @staticmethod
    @contextmanager
    def session_scope(Session):
        session = Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @staticmethod
    def save_info(session, key, value):
        """
        Save an information entry to the database.

        :param session:
        :param key:
        :param value:
        :return:
        """

        db_info = session.query(DbInformation).filter_by(key=key).scalar()
        if db_info is not None:
            db_info.value = value
        else:
            db_info = DbInformation(key=key, value=value)
            session.add(db_info)

    @staticmethod
    def loaded_type_collection_names() -> list[str]:
        """
        Primary names of all loaded type collections.
        """
        names: list[str] = []
        seen: set[int] = set()
        for tc in SIM_TYPE_COLLECTIONS.values():
            if id(tc) in seen or not tc.names:
                continue
            seen.add(id(tc))
            names.append(tc.names[0])
        return sorted(names)

    @staticmethod
    def load_type_collections(names: list[str]) -> None:
        """
        Make sure the type collections `names` are loaded; warn about the ones that cannot be found.
        """
        missing = [name for name in names if name not in SIM_TYPE_COLLECTIONS]
        if missing:
            load_type_collections(only=set(missing))
            missing = [name for name in missing if name not in SIM_TYPE_COLLECTIONS]
        if missing:
            l.warning(
                "Type collections %s were loaded when this database was created but are not available now. Struct "
                "references to types they define cannot be resolved.",
                missing,
            )

    @staticmethod
    def get_info(session, key):
        """
        Get an information entry from the database.

        :param session:
        :param key:
        :return:
        """

        db_info = session.query(DbInformation).filter_by(key=key).scalar()
        if db_info is None:
            return None
        return db_info.value

    def update_dbinfo(self, session, extra_info: dict[str, str] | None = None):
        """
        Update the information in database.

        :param session:
        :return:
        """

        self.save_info(session, "version", str(self.VERSION))
        self.save_info(session, "saved_at", str(int(time.time())))

        if extra_info:
            for key, value in extra_info.items():
                self.save_info(session, str(key), str(value))

    def get_dbinfo(self, session, extra_info: dict[str, str] | None = None):
        """
        Get database information.

        :param session:
        :return:        A dict of information entries.
        """

        d = {}

        # version
        version = self.get_info(session, "version")
        if version is not None:
            version = int(version)
        d["version"] = version

        # saved_at
        saved_at = self.get_info(session, "saved_at")
        if saved_at is not None:
            saved_at = int(saved_at)
        d["saved_at"] = saved_at

        if extra_info is not None:
            # store *everything* into the dict
            for entry in session.query(DbInformation):
                extra_info[entry.key] = entry.value

        return d

    def db_compatible(self, version):
        """
        Checks if the given database version is compatible with the current AngrDB class.

        :param int version: The version of the database.
        :return:            True if compatible, False otherwise.
        :rtype:             bool
        """

        return version == self.VERSION

    def invalidate(self):
        if self.engine is not None:
            self.engine.dispose()

    def dump(self, db_path, kbs: list[KnowledgeBase] | None = None, extra_info: dict[str, Any] | None = None):
        assert self.project is not None

        db_str = f"sqlite:///{db_path}"

        with self.open_db(db_str) as Session, self.session_scope(Session) as session:
            # Dump the loader
            LoaderSerializer.dump(session, self.project.loader)
            # Dump the knowledge base

            if kbs is None:
                kbs = [self.project.kb]

            for kb in kbs:
                KnowledgeBaseSerializer.dump(session, kb)

            # Save rust binary metadata
            if self.project.rustc_version is not None:
                self.save_info(session, "rustc_version", self.project.rustc_version)
            if self.project.rustc_optimization_level is not None:
                self.save_info(session, "rustc_optimization_level", self.project.rustc_optimization_level)

            # Save unresolvable target hook addresses so CFG edges can be resolved after load. CFGFast
            # allocates pseudo-addresses for UnresolvableCallTarget/JumpTarget via get_pseudo_addr(),
            # which are baked into CFG node/edge addresses. These addresses are not reproducible on a
            # fresh loader, so we must save and restore them explicitly.
            call_target_addrs: list[int] = []
            jump_target_addrs: list[int] = []
            for addr, proc in self.project._sim_procedures.items():
                name = type(proc).__name__
                if name == "UnresolvableCallTarget":
                    call_target_addrs.append(addr)
                elif name == "UnresolvableJumpTarget":
                    jump_target_addrs.append(addr)
            if call_target_addrs:
                self.save_info(session, "unresolvable_call_target_addrs", json.dumps(call_target_addrs))
            if jump_target_addrs:
                self.save_info(session, "unresolvable_jump_target_addrs", json.dumps(jump_target_addrs))

            # Save the names of loaded type collections. Named structs in prototypes are stored as references, which
            # can only be resolved after loading if the same type collections are available.
            self.save_info(session, "type_collections", json.dumps(self.loaded_type_collection_names()))

            # Update the information
            self.update_dbinfo(session, extra_info=extra_info)

    def load(
        self,
        db_path: str,
        kb_names: list[str] | None = None,
        other_kbs: dict[str, KnowledgeBase] | None = None,
        extra_info: dict[str, Any] | None = None,
    ):
        db_str = f"sqlite:///{db_path}"

        with self.open_db(db_str) as Session, self.session_scope(Session) as session:
            # Compatibility check
            dbinfo = self.get_dbinfo(session, extra_info=extra_info)
            if not self.db_compatible(dbinfo.get("version", None)):
                raise AngrIncompatibleDBError(
                    "Version {} is incompatible with the current version of angr.".format(dbinfo.get("version", None))
                )

            # Load type collections that were available when the database was created
            type_collections_str = self.get_info(session, "type_collections")
            if type_collections_str:
                self.load_type_collections(json.loads(type_collections_str))

            # Load the loader
            loader = LoaderSerializer.load(session)
            # Create the project
            rustc_version = self.get_info(session, "rustc_version")
            rustc_optimization_level = self.get_info(session, "rustc_optimization_level")
            proj = Project(
                loader,
                rustc_version=rustc_version,
                rustc_optimization_level=rustc_optimization_level,
            )

            # Restore unresolvable target hooks at the exact addresses used by the original CFGFast
            # analysis. These addresses are embedded in CFG edges and must be hooked with the correct
            # SimProcedure for Clinic's indirect call resolution to work.
            call_addrs_str = self.get_info(session, "unresolvable_call_target_addrs")
            if call_addrs_str:
                try:
                    call_addrs_list = json.loads(call_addrs_str)
                    if not isinstance(call_addrs_list, list):
                        raise TypeError("Expected a list of addresses")
                    for addr in call_addrs_list:
                        if isinstance(addr, int):
                            proj.hook(addr, SIM_PROCEDURES["stubs"]["UnresolvableCallTarget"](), replace=True)
                except (json.JSONDecodeError, TypeError):
                    pass

            jump_addrs_str = self.get_info(session, "unresolvable_jump_target_addrs")
            if jump_addrs_str:
                try:
                    jump_addrs_list = json.loads(jump_addrs_str)
                    if not isinstance(jump_addrs_list, list):
                        raise json.JSONDecodeError("Expected a list of addresses", "dummy", 0)
                    for addr in jump_addrs_list:
                        if isinstance(addr, int):
                            proj.hook(addr, SIM_PROCEDURES["stubs"]["UnresolvableJumpTarget"](), replace=True)
                except (json.JSONDecodeError, TypeError):
                    pass

            if kb_names is None:
                kb_names = ["global"]

            if (len(kb_names) != 1 or kb_names[0] != "global") and other_kbs is None:
                raise ValueError(
                    'You must provide a dict via "other_kbs" to collect angr KnowledgeBases '
                    "that are not the global one."
                )

            # Load knowledgebases
            for kb_name in kb_names:
                kb = KnowledgeBaseSerializer.load(session, proj, kb_name)
                if kb is not None:
                    if kb_name == "global":
                        proj.kb = kb
                    else:
                        other_kbs[kb_name] = kb

            return proj
