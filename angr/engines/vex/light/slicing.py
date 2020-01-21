from .light import VEXMixin
from ....utils.constants import DEFAULT_STATEMENT

class VEXSlicingMixin(VEXMixin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.__no_exit_sliced = False
        self._skip_stmts = 0
        self._last_stmt = None
        self._whitelist = None

    __tls = ('__no_exit_sliced', '_skip_stmts', '_last_stmt', '_whitelist')

    def process(self, *args, skip_stmts=0, last_stmt=None, whitelist=None, **kwargs):
        self._skip_stmts = skip_stmts
        self._last_stmt = last_stmt
        self._whitelist = whitelist
        return super().process(*args, **kwargs)

    def handle_vex_block(self, irsb):
        self.__no_exit_sliced = not self._check_vex_slice(DEFAULT_STATEMENT) and \
                                not any(self._check_vex_slice(stmt_idx) \
                                        for stmt_idx, stmt in enumerate(irsb.statements) \
                                        if stmt.tag == 'Ist_Exit')
        super().handle_vex_block(irsb)

    def _handle_vex_stmt(self, stmt):
        if self._check_vex_slice(self.stmt_idx):
            super()._handle_vex_stmt(stmt)

    def _handle_vex_defaultexit(self, expr, jumpkind):
        if self.__no_exit_sliced:
            super()._handle_vex_defaultexit(None, 'Ijk_Boring')
        elif self._check_vex_slice(DEFAULT_STATEMENT):
            super()._handle_vex_defaultexit(expr, jumpkind)

    def _check_vex_slice(self, stmt_idx):
        if stmt_idx == DEFAULT_STATEMENT:
            if self._last_stmt is not None and self._last_stmt != DEFAULT_STATEMENT:
                return False
            if self._whitelist is not None and DEFAULT_STATEMENT not in self._whitelist:
                return False
        else:
            if stmt_idx < self._skip_stmts:
                return False
            if self._last_stmt is not None and self._last_stmt != DEFAULT_STATEMENT and stmt_idx > self._last_stmt:
                return False
            if self._whitelist is not None and stmt_idx not in self._whitelist:
                return False
        return True


