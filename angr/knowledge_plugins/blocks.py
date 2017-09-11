from .view import KnowledgeBaseView


class BlockView(KnowledgeBaseView):
    """
    """

    def __init__(self, kb):
        super(BlockView, self).__init__(kb)

    def get_block(self, addr, **block_opts):
        """

        :param addr:
        :return:
        """
        basic_block = self._kb.basic_blocks.get_block(addr)
        if basic_block is not None:
            return self._produce_block(basic_block, **block_opts)

    def iter_blocks(self, start=None, end=None, **block_opts):
        """

        :param start:
        :param end:
        :param opt_level:
        :param traceflags:
        :return:
        """
        for basic_block in self._kb.basic_blocks.iter_blocks(start, end):
            yield self._produce_block(basic_block, **block_opts)

    def _produce_block(self, basic_block, **block_opts):
        """

        :param basic_block:
        :param opt_level:
        :param traceflags:
        :return:
        """
        return self._kb._project.factory.block(basic_block.start,
                                               size=basic_block.size,
                                               **block_opts)
