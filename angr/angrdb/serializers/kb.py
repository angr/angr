
from ...knowledge_base import KnowledgeBase
from ..models import DbKnowledgeBase
from .cfg_model import CFGModelSerializer
from .funcs import FunctionManagerSerializer
from .xrefs import XRefsSerializer
from .comments import CommentsSerializer
from .labels import LabelsSerializer
from .variables import VariableManagerSerializer
from .structured_code import StructuredCodeManagerSerializer


class KnowledgeBaseSerializer:
    """
    Serialize/unserialize a KnowledgeBase object.
    """

    @staticmethod
    def dump(session, kb):
        """

        :param session:             The database session object.
        :param KnowledgeBase kb:    The KnowledgeBase instance to serialize.
        :return:                    None
        """

        db_kb = session.query(DbKnowledgeBase).filter_by(name=kb.name).scalar()
        if db_kb is None:
            db_kb = DbKnowledgeBase(name=kb.name)
            session.add(db_kb)

        # dump other stuff
        if 'CFGFast' in kb.cfgs:
            cfg_model = kb.cfgs['CFGFast']
            if cfg_model is not None:
                CFGModelSerializer.dump(session, db_kb, 'CFGFast', cfg_model)

        FunctionManagerSerializer.dump(session, db_kb, kb.functions)
        XRefsSerializer.dump(session, db_kb, kb.xrefs)
        CommentsSerializer.dump(session, db_kb, kb.comments)
        LabelsSerializer.dump(session, db_kb, kb.labels)
        VariableManagerSerializer.dump(session, db_kb, kb.variables)
        StructuredCodeManagerSerializer.dump(session, db_kb, kb.structured_code)

    @staticmethod
    def load(session, project, name):
        """

        :param session:
        :return:
        """

        db_kb = session.query(DbKnowledgeBase).filter_by(name=name).scalar()
        if db_kb is None:
            return None

        kb = KnowledgeBase(project, name=name)

        # Load CFGs
        cfg_model = CFGModelSerializer.load(session, db_kb, 'CFGFast', kb.cfgs, loader=project.loader)
        if cfg_model is not None:
            kb.cfgs['CFGFast'] = cfg_model

        # Load functions
        funcs = FunctionManagerSerializer.load(session, db_kb, kb)
        if funcs is not None:
            kb.functions = funcs

        # Load xrefs
        xrefs = XRefsSerializer.load(session, db_kb, kb, cfg_model=cfg_model)
        if xrefs is not None:
            kb.xrefs = xrefs

        # Load comments
        comments = CommentsSerializer.load(session, db_kb, kb)
        if comments is not None:
            kb.comments = comments

        # Load labels
        labels = LabelsSerializer.load(session, db_kb, kb)
        if labels is not None:
            kb.labels = labels

        # Load variables
        variables = VariableManagerSerializer.load(session, db_kb, kb)
        if variables is not None:
            kb.variables = variables

        # Load structured code
        structured_code = StructuredCodeManagerSerializer.load(session, db_kb, kb)
        if structured_code is not None:
            kb.structured_code = structured_code

        # fill in CFGNode.function_address
        for func in funcs.values():
            for block_addr in func.block_addrs_set:
                node = cfg_model.get_any_node(block_addr)
                if node is not None:
                    node.function_address = func.addr

        # re-initialize CFGModel.insn_addr_to_memory_data
        # fill in insn_addr_to_memory_data
        for xrefs in xrefs.xrefs_by_ins_addr.values():
            for xref in xrefs:
                if xref.ins_addr is not None and xref.memory_data is not None:
                    cfg_model.insn_addr_to_memory_data[xref.ins_addr] = xref.memory_data

        return kb
