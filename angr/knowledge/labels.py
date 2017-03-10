class Labels(object):
    def __init__(self, kb):
        self._kb = kb
        self._labels = {}
        self._reverse_labels = {}
        for obj in kb._project.loader.all_objects:
            for k, v in obj.symbols_by_addr.iteritems():
                if v.name:
                    self._labels[v.rebased_addr] = v.name
                    self._reverse_labels[v.name] = v.rebased_addr
            try:
                for v, k in obj.plt.iteritems():
                    self._labels[k] = v
            except AttributeError:
                pass

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
        return self[addr]

    def lookup(self, name):
        return self._reverse_labels[name]
