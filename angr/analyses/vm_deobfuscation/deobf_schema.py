"""
Shared vocabulary for the deobfuscated-graph dump format.

This module is deliberately free of angr, pyvex and pushan imports so that it can be dropped
verbatim into another angr tree next to ``deobf_reader``.

The format is gzipped JSON.  Two decisions drive the encoding:

* Node addresses are arbitrary-precision integers (pushan encodes a whole ``BlockID`` into an
  address by concatenating decimal strings and reinterpreting the bytes, which lands at 90-160
  bits).  JSON numbers are doubles in most parsers, so **every integer that could be an address
  or a constant is written as a decimal string**.  This also rules out MessagePack/CBOR, whose
  integers top out at 64 bits.
* ``tyenv.types`` may contain the sentinel string ``"tmp removed"`` where a temporary was
  deleted.  It is not a valid ``Ity_*`` and must round-trip verbatim.
"""

FORMAT_VERSION = 1

# The writer refuses to emit anything outside these tables rather than dropping it silently.
STATEMENT_TAGS = frozenset(
    {
        "NoOp",
        "IMark",
        "AbiHint",
        "Put",
        "PutI",
        "WrTmp",
        "Store",
        "StoreG",
        "LoadG",
        "CAS",
        "LLSC",
        "MBE",
        "Dirty",
        "Exit",
    }
)

EXPRESSION_TAGS = frozenset(
    {
        "Binder",
        "VECRET",
        "GSPTR",
        "GetI",
        "RdTmp",
        "Get",
        "Qop",
        "Triop",
        "Binop",
        "Unop",
        "Load",
        "Const",
        "ITE",
        "CCall",
    }
)

# pushan subclasses a few pyvex classes to carry a `block_id`.  Nothing downstream of the dump
# point reads it, and ailment maps the subclasses onto the same handlers as the base classes, so
# the format stores the base tag and keeps `block_id` as optional metadata.
DATA_SENSITIVE_EXPR_CLASSES = ("DataSensitiveRdTmp",)
DATA_SENSITIVE_CONST_CLASSES = ("DataSensitiveU64", "DataSensitiveU32")

# The tyenv entry pushan writes in place of a deleted temporary.
TMP_TYPE_SENTINEL = "tmp removed"

ADDR_ENCODING_RAW = "raw"


class DeobfFormatError(Exception):
    """Raised when a dump cannot be produced or consumed."""


class UnsupportedIRError(DeobfFormatError):
    """Raised when the writer meets an IR construct it has no encoding for."""


def enc_int(value):
    """Encode a possibly-huge integer as a decimal string."""
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise DeobfFormatError(f"expected an int, got {type(value).__name__}: {value!r}")
    return str(value)


def dec_int(value):
    """Decode what :func:`enc_int` produced."""
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        # Tolerate a plain JSON number so hand-edited dumps still load.
        return value
    if not isinstance(value, str):
        raise DeobfFormatError(f"expected a decimal string, got {type(value).__name__}: {value!r}")
    return int(value, 10)


def enc_bytes(value):
    """Encode a bytestring as hex, or None."""
    if value is None:
        return None
    return value.hex()


def dec_bytes(value):
    if value is None:
        return None
    return bytes.fromhex(value)
