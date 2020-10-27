import logging

from .stmt_dependency import StatementDependencyState
from ...engines.light import SimEngineLight, SimEngineLightVEXMixin
from ...errors import SimEngineError
from ...utils.constants import DEFAULT_STATEMENT

l = logging.getLogger(name=__name__)


class SimEngineSDVEX(SimEngineLightVEXMixin, SimEngineLight):
    def __init__(self, project):
        super(SimEngineSDVEX, self).__init__()
        self.project = project
        self._visited_blocks = None
        self._stmt_dep_graph = None

        self.state: StatementDependencyState

    def process(self, state, *args, **kwargs):
        self._stmt_dep_graph = kwargs.pop('stmt_dep_graph', None)
        self._visited_blocks = kwargs.pop('visited_blocks', None)

        # we are using a completely different state. Therefore, we directly call our _process() method before
        # SimEngine becomes flexible enough.
        try:
            self._process(
                state,
                None,
                block=kwargs.pop('block', None),
            )
        except SimEngineError as e:
            if kwargs.pop('fail_fast', False) is True:
                raise e
            l.error(e)
        return self.state, self._visited_blocks, self._stmt_dep_graph

    def _process_block_end(self):
        self.stmt_idx = DEFAULT_STATEMENT
        if self.block.vex.jumpkind == "Ijk_Call":
            # it has to be a function
            addr = self._expr(self.block.vex.next)
            self._handle_function(addr)
        elif self.block.vex.jumpkind == "Ijk_Boring":
            # test if the target addr is a function or not
            addr = self._expr(self.block.vex.next)
            if len(addr) == 1:
                addr_int = next(iter(addr.data))
                if isinstance(addr_int, int) and addr_int in self.functions:
                    # yes it's a jump to a function
                    self._handle_function(addr)

    def _handle_Stmt(self, stmt):

        if self.state.analysis:
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_BEFORE)

        super(SimEngineRDVEX, self)._handle_Stmt(stmt)

        if self.state.analysis:
            self.state.analysis.insn_observe(self.ins_addr, stmt, self.block, self.state, OP_AFTER)
