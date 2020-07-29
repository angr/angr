

class TaggedObject:
    """
    A class that takes arbitrary tags.
    """

    __slots__ = ('idx', 'tags', )

    def __init__(self, idx, **kwargs):
        self.tags = { }
        self.idx = idx
        if kwargs:
            self.initialize_tags(kwargs)

    def initialize_tags(self, tags):
        for k, v in tags.items():
            self.tags[k] = v

    def __getattr__(self, item):
        try:
            return self.tags[item]
        except KeyError:
            return super(TaggedObject, self).__getattribute__(item)
