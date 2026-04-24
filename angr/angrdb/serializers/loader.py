from __future__ import annotations
from typing import Any
from pathlib import Path
import json
import binascii
import logging
from io import BytesIO
import archinfo

import cle

from angr.errors import AngrCorruptDBError, AngrDBError
from angr.angrdb.models import DbObject

_l = logging.getLogger(__name__)


class LoadArgsJSONEncoder(json.JSONEncoder):
    """
    A JSON encoder that supports serializing bytes.
    """

    def default(self, o):
        if isinstance(o, bytes):
            return {
                "__custom_type__": "bytes",
                "__v__": binascii.hexlify(o).decode("ascii"),
            }
        if isinstance(o, archinfo.Arch):
            return {"__custom_type__": "arch", "name": o.name, "endness": o.memory_endness, "bits": o.bits}
        return super().default(o)


class LoadArgsJSONDecoder(json.JSONDecoder):
    """
    A JSON decoder that supports unserializing into bytes.
    """

    def __init__(self):
        super().__init__(object_hook=self._objhook)

    def _objhook(self, d: dict):  # pylint:disable=no-self-use
        if "__custom_type__" in d:
            match d["__custom_type__"]:
                case "bytes":
                    if "__v__" in d:
                        return binascii.unhexlify(d["__v__"])
                case "arch":
                    return archinfo.arch_from_id(
                        d["name"],
                        d.get("endness", ""),
                        d.get("bits", ""),
                    )
        return d


class LoaderSerializer:
    """
    Serialize/unserialize a CLE Loader object into/from an angr DB.

    Corner cases:
    - For certain backends (e.g., CART), we do not store the data of the main object. angr will unpack the CART file
      again after loading the database.
    """

    NO_MAINBIN_BACKENDS = [cle.backends.CARTFile]
    LOAD_ARG_BLACKLIST = {"loader", "is_main_bin"}

    backend2name = {v: k for k, v in cle.ALL_BACKENDS.items()}

    @staticmethod
    def json_serialize_load_args(load_args: dict[str, Any]) -> str:
        serializable_keys = []
        encoder = LoadArgsJSONEncoder()
        for key, argv in load_args.items():
            if key in LoaderSerializer.LOAD_ARG_BLACKLIST:
                continue
            try:
                encoder.encode(argv)
            except TypeError:
                _l.warning("Cannot serialize %s: %s", key, argv)
            else:
                serializable_keys.append(key)

        return encoder.encode({k: load_args[k] for k in serializable_keys})

    @staticmethod
    def should_skip_main_binary(loader) -> tuple[bool, cle.backends.Backend | None]:
        for obj in loader.all_objects:
            for cls in LoaderSerializer.NO_MAINBIN_BACKENDS:
                if isinstance(obj, cls):
                    return True, obj
        return False, None

    @staticmethod
    def dump(session, loader):
        main_object_in_db = loader.main_object
        skip_mainbin, new_main_obj = LoaderSerializer.should_skip_main_binary(loader)
        if skip_mainbin and new_main_obj is not None:
            main_object_in_db = new_main_obj

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

            # should we skip the main object?
            if skip_mainbin and loader.main_object is obj:
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
                main_object=main_object_in_db is obj,
                path=obj.binary,
                content=content,
                backend=LoaderSerializer.backend2name.get(obj.__class__),
                backend_args=LoaderSerializer.json_serialize_load_args(obj.load_args),
            )
            session.add(o)

    @staticmethod
    def load(session):
        main_path = None
        main_bin = None
        lib_paths = []

        db_objects: list[DbObject] = session.query(DbObject)
        main_opts = None
        lib_opts = {}

        decoder = LoadArgsJSONDecoder()
        name_to_path = {}

        for db_o in db_objects:
            load_opts = decoder.decode(db_o.backend_args) if db_o.backend_args else {}

            if db_o.backend is not None:
                load_opts["backend"] = db_o.backend

            load_opts = {k: v for k, v in load_opts.items() if v is not None}

            path = Path(db_o.path)
            name_to_path[path.name] = str(path)

            # Use BytesIO instead of extracting to a temporary file.
            # Ref: https://github.com/angr/angr/issues/6367
            spec = BytesIO(db_o.content)
            spec.name = path.name

            if db_o.main_object:
                main_opts = load_opts
                main_bin = spec
                main_path = str(path)
            else:
                lib_opts[path.name] = load_opts
                lib_paths.append(spec)

        if main_bin is None:
            raise AngrCorruptDBError("Corrupt database: No main object.")

        loader = cle.Loader(main_bin, preload_libs=lib_paths, main_opts=main_opts, lib_opts=lib_opts)

        loader._main_binary_path = main_path
        # fix the binary name of each loaded object
        for obj in loader.all_objects:
            if obj.binary is None and obj.binary_basename is not None:
                obj.binary = name_to_path.get(obj.binary_basename)

        return loader
