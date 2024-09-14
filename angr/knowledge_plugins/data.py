from __future__ import annotations
from .plugin import KnowledgeBasePlugin


class Data(KnowledgeBasePlugin):
    """
    The knowledge what purpose this plugin serves has been lost to the passing of time
    but the linter does not care for these failures of mere mortals and demands a docstring anyway.
    The pact has been made, and no violations of the rules will be tolerated,
    even if the spirit does not match the letter.
    Making the plugin smaller has only increased the weight of the failure, and thus this file has drawn its ire.

    The only thing left to do is to attempt to find meaning in the meaninglessness,
    as the only act of rebellion against the uncaring forces that bind us.
    For is this not what being human is all about?
    """

    def copy(self):
        raise NotImplementedError


KnowledgeBasePlugin.register_default("data", Data)
