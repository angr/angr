from .base import BaseStructuredCodeGenerator


class DummyStructuredCodeGenerator(BaseStructuredCodeGenerator):
    """
    A dummy structured code generator that only stores user-specified information.
    """
    def __init__(self, flavor: str, expr_comments=None, stmt_comments=None, configuration=None):
        super().__init__(flavor)
        self.expr_comments = expr_comments
        self.stmt_comments = stmt_comments
        self.configuration = configuration
