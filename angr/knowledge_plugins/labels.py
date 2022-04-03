from archinfo.arch_arm import is_arm_arch
import cle

from .plugin import KnowledgeBasePlugin


class Labels(KnowledgeBasePlugin):

    def __init__(self, kb):
        self._kb = kb
        self._labels = {}
        self._reverse_labels = {}

        is_arm = is_arm_arch(kb._project.arch)
        for obj in kb._project.loader.all_objects:
            for v in obj.symbols:
                if is_arm and v.name in {"$d", "$t", "$a"}:
                    continue
                if v.name and not v.is_import and v.type not in {cle.SymbolType.TYPE_OTHER, }:
                    self._labels[v.rebased_addr] = v.name
                    self._reverse_labels[v.name] = v.rebased_addr
            try:
                for v, k in obj.plt.items():
                    self._labels[k] = v
            except AttributeError:
                pass

        # Artificial labels for the entry point
        entry = kb._project.loader.main_object.entry
        if entry not in self._labels:
            lbl = "_start"
            self._labels[entry] = self.get_unique_label(lbl)

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
            l = self._labels[k]
            if l in self._reverse_labels:
                del self._reverse_labels[l]
            del self._labels[k]

    def __contains__(self, k):
        return k in self._labels

    def items(self):
        return self._labels.items()

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

    def get_unique_label(self, label):
        """
        Get a unique label name from the given label name.

        :param str label:   The desired label name.
        :return:            A unique label name.
        """

        if label not in self._labels:
            return label

        # use it as the prefix
        i = 1
        while True:
            new_label = "%s_%d" % (label, i)
            if new_label not in self._labels:
                return new_label
            i += 1


KnowledgeBasePlugin.register_default('labels', Labels)
