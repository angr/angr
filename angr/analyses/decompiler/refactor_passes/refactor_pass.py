class RefactorPass:
    NAME = "Base Refactor Pass"

    def __init__(self):
        self.out_node = None

    def _analyze(self):
        raise NotImplementedError()
