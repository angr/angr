
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ..project import Project
from .models import Base
from .serializers import LoaderSerializer, KnowledgeBaseSerializer


class AngrDB:
    """
    AngrDB provides a storage solution for an angr project, its knowledge bases, and some other types of data. It is
    designed to use an SQL-based database as the storage backend.
    """

    ALL_TABLES = ['objects', ]

    def __init__(self, project=None):
        self.project = project
        self.kbs = [ ]
        self.config = {}

        if project is not None:
            # register the default kb
            self.kbs.append(project.kb)

    @staticmethod
    @contextmanager
    def open_db(db_str="sqlite:///:memory:"):
        engine = create_engine(db_str)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        yield Session

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

    def dump(self, db_path):

        db_str = "sqlite:///%s" % db_path

        with self.open_db(db_str) as Session:
            with self.session_scope(Session) as session:
                # Dump the loader
                LoaderSerializer.dump(session, self.project.loader)
                # Dump the knowledge base
                KnowledgeBaseSerializer.dump(session, self.project.kb)

    def load(self, db_path):

        db_str = "sqlite:///%s" % db_path

        with self.open_db(db_str) as Session:
            with self.session_scope(Session) as session:
                # Load the loader
                loader = LoaderSerializer.load(session)
                # Create the project
                proj = Project(loader)

                # Load the kb
                kb = KnowledgeBaseSerializer.load(session, proj, "global")
                if kb is not None:
                    proj.kb = kb

                return proj
