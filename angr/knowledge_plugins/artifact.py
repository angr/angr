from .plugin import KnowledgeBasePlugin


class KnowledgeArtifact(KnowledgeBasePlugin):
    """
    This represents one specific set of homogeneous artifacts about
    given object. These artifacts can be, for example, basic blocks
    boundaries, the results of the resolution of indirect jumps, and so on.

    Note, that the __init__() method doesn't take a `consumes` keyword argument,
    while taking the `provides` as an obligatory argument. This is because the
    artifacts are meant to be the source of all the knowledge, that is available
    in the knowledge base.
    """

    def __init__(self, kb, provides):
        super(KnowledgeArtifact, self).__init__(kb, provides)
