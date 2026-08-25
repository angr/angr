from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch, sentinel

import angr
from angr.procedures.posix.pthread import pthread_create


class TestPthreadCreate(unittest.TestCase):
    """Test static pthread procedure behavior."""

    def test_static_exits_symbol_fills_unspecified_registers(self):
        state = MagicMock()
        state.memory.load.return_value = sentinel.return_address
        cc = MagicMock()
        cc.get_args.return_value = (sentinel.thread, sentinel.attr, sentinel.start_routine)
        project = MagicMock()
        project.loader.memory = sentinel.loader_memory
        procedure = cast(
            pthread_create,
            SimpleNamespace(project=project, cc=cc, prototype=sentinel.prototype, arch=SimpleNamespace(bytes=8)),
        )

        with patch.object(angr, "SimState", return_value=state) as sim_state:
            exits = pthread_create.static_exits(procedure, [])

        sim_state.assert_called_once_with(
            project=project,
            mode="fastpath",
            cle_memory_backer=sentinel.loader_memory,
            add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
        )
        self.assertEqual(
            exits,
            [
                {"address": sentinel.start_routine, "jumpkind": "Ijk_Call", "namehint": "thread_entry"},
                {"address": sentinel.return_address, "jumpkind": "Ijk_Ret", "namehint": None},
            ],
        )


if __name__ == "__main__":
    unittest.main()
