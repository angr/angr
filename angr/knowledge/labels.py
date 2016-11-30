class Labels(object):
    def __init__(self, kb):
        self._kb = kb
        self._labels = {}
        for obj in kb._project.loader.all_objects:
            for k, v in obj.symbols_by_addr.iteritems():
                if v.name:
                    self._labels[v.rebased_addr] = v.name
            try:
                for v, k in obj.plt.iteritems():
                    self._labels[k] = v
            except AttributeError:
                pass

    def __getitem__(self, k):
        return self._labels[k]

    def __setitem__(self, k, v):
        self._labels[k] = v
        if k in self._kb.functions:
            self._kb.functions[k] = v

    def __delitem__(self, k):
        if k in self._labels:
            del self._labels[k]

    def __contains__(self, k):
        return k in self._labels
