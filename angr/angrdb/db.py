
from contextlib import contextmanager

import sqlite3

from .serializers import LoaderSerializer


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
    def open_db(db_path):
        conn = sqlite3.connect(db_path)
        yield conn
        conn.close()

    def db_initialized(self, conn):
        """
        Determine whether the current angr db has been initialized or not.

        :param conn:
        :return:
        """

        sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?;"
        cursor = conn.cursor()
        for table_name in self.ALL_TABLES:
            cursor.execute(sql, (table_name,))
            if cursor.fetchone() is None:
                # the table does not exist
                return False
        return True

    def init_db(self, conn):
        """
        Initialize the database.

        :return:
        """

        schemas = [
            """DROP TABLE IF EXISTS objects""",
            """CREATE TABLE objects (
                id INTEGER PRIMARY KEY,
                main_object INTEGER,
                path VARCHAR,
                content BLOB,
                backend VARCHAR,
                backend_args VARCHAR
                )
                """,
        ]

        cursor = conn.cursor()

        # create tables
        for schema_sql in schemas:
            cursor.execute(schema_sql)

        conn.commit()

    def dump(self, db_path):
        with self.open_db(db_path) as conn:
            if not self.db_initialized(conn):
                self.init_db(conn)

            # Dump the loader
            LoaderSerializer.dump(self.project.loader, conn)
