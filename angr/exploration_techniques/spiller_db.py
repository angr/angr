# pylint:disable=missing-class-docstring,unused-import
from __future__ import annotations
import datetime

try:
    import sqlalchemy
    from sqlalchemy import Column, Integer, String, Boolean, DateTime, create_engine
    from sqlalchemy.orm import declarative_base, sessionmaker
    from sqlalchemy.exc import OperationalError

    Base = declarative_base()

    class PickledState(Base):
        __tablename__ = "pickled_states"

        id = Column(String, primary_key=True)
        priority = Column(Integer)
        taken = Column(Boolean, default=False)
        stash = Column(String, default="")
        timestamp = Column(DateTime, default=datetime.datetime.utcnow)

except ImportError:
    sqlalchemy = None
    create_engine = None
    Base = None
    OperationalError = None
    sessionmaker = None
