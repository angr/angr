from io import BytesIO
from typing import List

import cle

from ...errors import AngrCorruptDBError, AngrDBError
from ..models import DbObject


class LoaderSerializer:
    """
    Serialize/unserialize a CLE Loader object into/from an angr DB.
    """

    backend2name = {v: k for k, v in cle.ALL_BACKENDS.items()}

    @staticmethod
    def dump(session, loader):
        for obj in loader.all_objects:
            if isinstance(
                obj,
                (
                    cle.ExternObject,
                    cle.TLSObject,
                    cle.KernelObject,
                ),
            ):
                # skip dynamically created objects
                continue

            # does the object exist?
            exists = session.query(DbObject.id).filter_by(path=obj.binary).scalar() is not None
            if exists:
                # it exists. skip.
                continue

            try:
                content = obj.cached_content if hasattr(obj, "cached_content") else None
                if content is None:
                    # fall back to loading the file again from disk
                    with open(obj.binary, "rb") as the_file:
                        content = the_file.read()
            except OSError as ex:
                raise AngrDBError(f"Failed to load content for file {obj.binary}.") from ex

            # save the object
            o = DbObject(
                main_object=loader.main_object is obj,
                path=obj.binary,
                content=content,
                backend=LoaderSerializer.backend2name.get(obj.__class__),
                backend_args="",  # TODO: We will need support from CLE to store loader arguments
            )
            session.add(o)

    @staticmethod
    def load(session):
        all_objects = {}  # path to object
        main_object = None

        db_objects: List[DbObject] = session.query(DbObject)

        for db_o in db_objects:
            all_objects[db_o.path] = db_o
            if db_o.main_object:
                main_object = db_o

        if main_object is None:
            raise AngrCorruptDBError("Corrupt database: No main object.")

        # build params
        # FIXME: Load other objects

        loader = cle.Loader(
            BytesIO(main_object.content),
        )

        # fix the binary name of the main binary
        loader._main_binary_path = main_object.path
        loader.main_object.binary = main_object.path

        return loader
