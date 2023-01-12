from sqlalchemy import Column, Integer, String, Boolean, BLOB, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class DbInformation(Base):
    """
    Stores information related to the current database. Basically a key-value store.
    """

    __tablename__ = "information"

    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True, index=True)
    value = Column(String)


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
    funcs = relationship("DbFunction", back_populates="kb")
    xrefs = relationship("DbXRefs", uselist=False, back_populates="kb")
    comments = relationship("DbComment", back_populates="kb")
    labels = relationship("DbLabel", back_populates="kb")
    var_collections = relationship("DbVariableCollection", back_populates="kb")
    structured_code = relationship("DbStructuredCode", back_populates="kb")


class DbCFGModel(Base):
    """
    Models a CFGFast instance.
    """

    __tablename__ = "cfgs"

    id = Column(Integer, primary_key=True)
    kb_id = Column(
        Integer,
        ForeignKey("knowledgebases.id"),
        nullable=False,
    )
    kb = relationship("DbKnowledgeBase", uselist=False, back_populates="cfgs")
    ident = Column(String)
    blob = Column(BLOB)


class DbFunction(Base):
    """
    Models a Function instance.
    """

    __tablename__ = "functions"

    id = Column(Integer, primary_key=True)
    kb_id = Column(
        Integer,
        ForeignKey("knowledgebases.id"),
        nullable=False,
    )
    kb = relationship("DbKnowledgeBase", uselist=False, back_populates="funcs")
    addr = Column(Integer)
    blob = Column(BLOB)


class DbVariableCollection(Base):
    """
    Models a VariableManagerInternal instance.
    """

    __tablename__ = "variables"

    id = Column(Integer, primary_key=True)
    kb_id = Column(
        Integer,
        ForeignKey("knowledgebases.id"),
        nullable=False,
    )
    kb = relationship("DbKnowledgeBase", uselist=False, back_populates="var_collections")
    func_addr = Column(Integer)
    ident = Column(String, nullable=True)
    blob = Column(BLOB)


class DbStructuredCode(Base):
    """
    Models a StructuredCode instance.
    """

    __tablename__ = "structured_code"

    id = Column(Integer, primary_key=True)
    kb_id = Column(
        Integer,
        ForeignKey("knowledgebases.id"),
        nullable=False,
    )
    kb = relationship("DbKnowledgeBase", uselist=False, back_populates="structured_code")
    func_addr = Column(Integer)
    flavor = Column(String)
    expr_comments = Column(BLOB, nullable=True)
    stmt_comments = Column(BLOB, nullable=True)
    configuration = Column(BLOB, nullable=True)
    const_formats = Column(BLOB, nullable=True)
    ite_exprs = Column(BLOB, nullable=True)


class DbXRefs(Base):
    """
    Models an XRefManager instance.
    """

    __tablename__ = "xrefs"

    id = Column(Integer, primary_key=True)
    kb_id = Column(
        Integer,
        ForeignKey("knowledgebases.id"),
        nullable=False,
    )
    kb = relationship("DbKnowledgeBase", uselist=False, back_populates="xrefs")
    blob = Column(BLOB, nullable=True)


class DbComment(Base):
    """
    Models a comment.
    """

    __tablename__ = "comments"

    id = Column(Integer, primary_key=True)
    kb_id = Column(
        Integer,
        ForeignKey("knowledgebases.id"),
        nullable=False,
    )
    kb = relationship("DbKnowledgeBase", uselist=False, back_populates="comments")
    addr = Column(Integer, index=True)
    comment = Column(String)
    type = Column(Integer)  # not really used for now, but we'd better get it prepared


class DbLabel(Base):
    """
    Models a label.
    """

    __tablename__ = "labels"

    id = Column(Integer, primary_key=True)
    kb_id = Column(
        Integer,
        ForeignKey("knowledgebases.id"),
        nullable=False,
    )
    kb = relationship("DbKnowledgeBase", uselist=False, back_populates="labels")
    addr = Column(Integer, index=True)
    name = Column(String)
