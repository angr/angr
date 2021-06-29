from typing import TYPE_CHECKING

from ...knowledge_plugins import VariableManager
from ..models import DbVariable

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase
    from angr.angrdb.models import DbKnowledgeBase


class VariableManagerSerializer:
    """
    Serialize/unserialize a variable manager and its variables.
    """

    @staticmethod
    def dump(session, db_kb: 'DbKnowledgeBase', var_manager: VariableManager):

        # Remove all existing variables
        session.query(DbVariable).filter_by(kb=db_kb).delete()

        # Dump all variables
        for internal in var_manager.function_managers.values():


    @staticmethod
    def load(session, db_kb: 'DbKnowledgeBase', kb: 'KnowledgeBase'):
        raise NotImplementedError()
