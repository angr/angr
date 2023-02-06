from io import BytesIO
from typing import List

import cle

from ...errors import AngrCorruptDBError
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
                    cle.backends.tls.elf_tls.ELFTLSObject,
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

            # FIXME: We assume the binary and its libraries all still exist on the disk

            # save the object
            o = DbObject(
                main_object=loader.main_object is obj,
                path=obj.binary,
                content=open(obj.binary, "rb").read(),
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
