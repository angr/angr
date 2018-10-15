
import cle

from .plugin import KnowledgeBasePlugin


class Labels(KnowledgeBasePlugin):

    def __init__(self, kb):
        self._kb = kb
        self._labels = {}
        self._reverse_labels = {}
        for obj in kb._project.loader.all_objects:
            for v in obj.symbols:
                if v.name and not v.is_import and v.type not in {cle.Symbol.TYPE_OTHER, }:
                    self._labels[v.rebased_addr] = v.name
                    self._reverse_labels[v.name] = v.rebased_addr
            try:
                for v, k in obj.plt.items():
                    self._labels[k] = v
            except AttributeError:
                pass

    def __iter__(self):
        """
        Iterate over all labels (the strings)
        Use .lookup(name) if you need to find the address to it.
        """
        return self._reverse_labels.__iter__()

    def __getitem__(self, k):
        return self._labels[k]

    def __setitem__(self, k, v):
        del self[k]
        self._labels[k] = v
        self._reverse_labels[v] = k
        if k in self._kb.functions:
            self._kb.functions[k]._name = v

    def __delitem__(self, k):
        if k in self._labels:
            del self._reverse_labels[self._labels[k]]
            del self._labels[k]

    def __contains__(self, k):
        return k in self._labels

    def get(self, addr):
        """
        Get a label as string for a given address
        Same as .labels[x]
        """
        return self[addr]

    def lookup(self, name):
        """
        Returns an address to a given label
        To show all available labels, iterate over .labels or list(b.kb.labels)
        """
        return self._reverse_labels[name]

    def copy(self):
        o = Labels(self._kb)
        o._labels = {k: v for k, v in self._labels.items()}
        o._reverse_labels = {k: v for k, v in self._reverse_labels.items()}


KnowledgeBasePlugin.register_default('labels', Labels)
