try:
    import sqlalchemy
except ImportError:
    sqlalchemy = None
    raise ImportError(
        "AngrDB relies on SQLAlchemy. Please install SQLAlchemy first by running:\n\tpip install sqlalchemy"
    )

from .db import AngrDB
