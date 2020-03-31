
from sqlalchemy import (Column, Integer, String, Boolean, BLOB, ForeignKey)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class DbObject(Base):
    """
    Models a binary object.
    """
    __tablename__ = "objects"

    id = Column(Integer, primary_key=True)
    main_object = Column(Boolean, default=False)
    path = Column(String, default="", nullable=True)
    content = Column(BLOB, nullable=True)
    backend = Column(String)
    backend_args = Column(String, nullable=True)  # it's a JSON field but JSON is not supported in sqlite before 3.9


class DbKnowledgeBase(Base):
    """
    Models a knowledge base.
    """
    __tablename__ = "knowledgebases"

    id = Column(Integer, primary_key=True)
    name = Column(String, default="", nullable=True)

    cfgs = relationship("DbCFGModel", back_populates="kb")
    funcs = relationship('DbFunction', back_populates="kb")
    xrefs = relationship('DbXRefs', uselist=False, back_populates="kb")


class DbCFGModel(Base):
    """
    Models a CFGFast instance.
    """
    __tablename__ = "cfgs"

    id = Column(Integer, primary_key=True)
    kb_id = Column(Integer,
                   ForeignKey("knowledgebases.id"),
                   nullable=False,
                   )
    kb = relationship('DbKnowledgeBase', uselist=False, back_populates="cfgs")
    ident = Column(String)
    blob = Column(BLOB)


class DbFunction(Base):
    """
    Models a Function instance.
    """
    __tablename__ = "functions"

    id = Column(Integer, primary_key=True)
    kb_id = Column(Integer,
                   ForeignKey("knowledgebases.id"),
                   nullable=False,
                   )
    kb = relationship('DbKnowledgeBase', uselist=False, back_populates="funcs")
    addr = Column(Integer)
    blob = Column(BLOB)


class DbXRefs(Base):
    """
    Models an XRefManager instance.
    """
    __tablename__ = "xrefs"

    id = Column(Integer, primary_key=True)
    kb_id = Column(Integer,
                   ForeignKey("knowledgebases.id"),
                   nullable=False,
                   )
    kb = relationship("DbKnowledgeBase", uselist=False, back_populates="xrefs")
    blob = Column(BLOB, nullable=True)
