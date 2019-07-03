
import cle


class LoaderSerializer:
    """
    Serializes/unserializes a CLE Loader object into/from an angr DB.
    """

    @staticmethod
    def dump(loader, conn):

        backend2name = dict((v, k) for k, v in cle.ALL_BACKENDS.items())

        for obj in loader.all_objects:
            if isinstance(obj, (cle.ExternObject, cle.ELFTLSObject, cle.KernelObject,)):
                # skip dynamically created objects
                continue

            # does the object exist?
            obj_exists_sql = """SELECT COUNT(*) FROM objects WHERE path=?"""
            cursor = conn.cursor()
            cursor.execute(obj_exists_sql, (obj.binary, ))
            if cursor.fetchone()[0] > 0:
                # it exists. skip
                # TODO: Handle updates
                continue

            # save the object
            sql = """INSERT INTO objects(main_object, path, content, backend, backend_args) 
                VALUES (?, ?, ?, ?, ?)"""
            cursor = conn.cursor()
            cursor.execute(sql, (1 if loader.main_object is obj else 0,
                                 obj.binary,
                                 open(obj.binary, "rb").read(),  # TODO: We should load it when the object is first opened
                                 backend2name.get(obj.__class__),
                                 "", # TODO: We will need support from CLE to store loader arguments
                                 ))
        conn.commit()

    @staticmethod
    def load(conn):
        pass
