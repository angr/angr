class PrivilegedMixin:
    def __init__(self):
        self._priv_stack = [ False ]

    @property
    def priv(self):
        return self._priv_stack[-1]

    def push_priv(self, priv):
        self._priv_stack.append(priv)

    def pop_priv(self):
        self._priv_stack.pop()
        if len(self._priv_stack) == 0:
            raise SimValueError("Priv stack is empty")

    def store(self, *args, priv=None, **kwargs):
        if priv is not None:
            self.push_priv(priv)

        try:
            return super().store(*args, **kwargs)
        finally:
            if priv is not None:
                self.pop_priv()

    def load(self, *args, priv=None, **kwargs):
        if priv is not None:
            self.push_priv(priv)

        try:
            return super().load(*args, **kwargs)
        finally:
            if priv is not None:
                self.pop_priv()

from ...errors import SimValueError
