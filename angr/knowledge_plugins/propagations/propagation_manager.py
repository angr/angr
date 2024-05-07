from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from .propagation_model import PropagationModel


class PropagationManager(KnowledgeBasePlugin):
    """
    Manages the results of Propagator, including intermediate results for unfinished Propagation runs.
    """

    def __init__(self, kb):
        super().__init__(kb=kb)
        self._propagations: dict[tuple, PropagationModel] = {}

    def exists(self, prop_key: tuple) -> bool:
        """
        Internal function to check if a func, specified as a CodeLocation
        exists in our known propagations

        :param prop_key:    A key of the propagation result.
        :return:            Whether such a key exists or not.
        """
        return prop_key in self._propagations

    def update(self, prop_key: tuple, model: PropagationModel) -> None:
        """
        Add the replacements to known propagations

        :param prop_key:        A key of the propagation result.
        :param model:           The propagation result to store
        """
        self._propagations[prop_key] = model

    def get(self, prop_key, default=None) -> PropagationModel:
        """
        Gets the replacements for a specified function location.
        If the replacement does not exist in the known propagations, it
        returns None.

        :param prop_key:    A key of the propagation result.
        :param default:     The default value to return if the prop_key does not exist in the cache.
        :return:            Dict or None
        """
        if prop_key in self._propagations:
            return self._propagations[prop_key]
        else:
            return default

    def copy(self):
        o = PropagationManager(self._kb)
        o._propagations = {}
        for k, v in self._propagations.items():
            o._propagations[k] = v

    def discard_by_prefix(self, prefix: str):
        for key in list(self._propagations.keys()):
            if key[0] == prefix:
                del self._propagations[key]


KnowledgeBasePlugin.register_default("propagations", PropagationManager)
