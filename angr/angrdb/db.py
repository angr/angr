from __future__ import annotations
from typing import Any, TYPE_CHECKING
import time
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import DatabaseError

from ..errors import AngrCorruptDBError, AngrIncompatibleDBError, AngrDBError
from ..project import Project
from .models import Base, DbInformation
from .serializers import LoaderSerializer, KnowledgeBaseSerializer

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase


class AngrDB:
    """
    AngrDB provides a storage solution for an angr project, its knowledge bases, and some other types of data. It is
    designed to use an SQL-based database as the storage backend.
    """

    ALL_TABLES = [
        "objects",
    ]

    VERSION = 1

    def __init__(self, project=None):
        self.project = project
        self.config = {}

    @staticmethod
    @contextmanager
    def open_db(db_str="sqlite:///:memory:"):
        try:
            engine = create_engine(db_str)
            Base.metadata.create_all(engine)
            Session = sessionmaker(bind=engine)
            yield Session
        except DatabaseError as ex:
            raise AngrCorruptDBError("The target file may not be an angr database or it is corrupted.") from ex
        except Exception as ex:
            raise AngrDBError(str(ex)) from ex

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

    def dump(self, db_path, kbs: list[KnowledgeBase] | None = None, extra_info: dict[str, Any] | None = None):
        db_str = f"sqlite:///{db_path}"

        with self.open_db(db_str) as Session, self.session_scope(Session) as session:
            # Dump the loader
            LoaderSerializer.dump(session, self.project.loader)
            # Dump the knowledge base

            if kbs is None:
                kbs = [self.project.kb]

            for kb in kbs:
                KnowledgeBaseSerializer.dump(session, kb)

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

            # Load the loader
            loader = LoaderSerializer.load(session)
            # Create the project
            proj = Project(loader)

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
