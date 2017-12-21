

class KnowledgeBasePlugin(object):
    """
    This is a knowledge base plugin.  It is meant to represent one specific set
    of homogeneous facts about given object. These artifacts can be, for example,
    basic blocks boundaries, the results of the resolution of indirect jumps, and so on.

    TODO: Update documentation.
    """

    def __init__(self):
        super(KnowledgeBasePlugin, self).__init__()

    @classmethod
    def register_default(cls, name, plugin_cls):
        print "KnowledgeBasePlugin.register_default() is present for compatibility reasons " \
              "only. It does nothing."
