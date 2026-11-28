from __future__ import annotations

import signal
import unittest
from types import SimpleNamespace
from unittest import mock

from angr.analyses.decompiler.binary_decompiler import BinaryDecompiler, _DecompilationTimeout


@unittest.skipUnless(hasattr(signal, "SIGALRM"), "requires SIGALRM")
class TestBinaryDecompilerTimeout(unittest.TestCase):
    def budget(self, timeout):
        return BinaryDecompiler._time_budget(SimpleNamespace(_timeout=timeout, _warned_timeout=False))

    def test_restores_remaining_timer_and_interval_after_exception(self):
        old_handler = mock.Mock()
        with (
            mock.patch("signal.getitimer", return_value=(10.0, 3.0)),
            mock.patch("signal.signal", return_value=old_handler) as handler,
            mock.patch("signal.setitimer") as timer,
            mock.patch("time.perf_counter", side_effect=[100.0, 102.0]),
        ):
            with self.assertRaisesRegex(ValueError, "failed"), self.budget(5.0):
                raise ValueError("failed")
            assert timer.call_args_list == [
                mock.call(signal.ITIMER_REAL, 5.0),
                mock.call(signal.ITIMER_REAL, 0),
                mock.call(signal.ITIMER_REAL, 8.0, 3.0),
            ]
            assert handler.call_args == mock.call(signal.SIGALRM, old_handler)

    def test_earlier_deadline_calls_previous_handler_and_retains_own_budget(self):
        old_handler = mock.Mock()
        now = [100.0]
        with (
            mock.patch("signal.getitimer", return_value=(2.0, 0.0)),
            mock.patch("signal.signal", return_value=old_handler) as handler,
            mock.patch("signal.setitimer") as timer,
            mock.patch("time.perf_counter", side_effect=lambda: now[0]),
        ):
            with self.budget(5.0):
                dispatch = handler.call_args.args[1]
                assert timer.call_args == mock.call(signal.ITIMER_REAL, 2.0)
                now[0] = 102.0
                dispatch(signal.SIGALRM, None)
                old_handler.assert_called_once_with(signal.SIGALRM, None)
                assert timer.call_args == mock.call(signal.ITIMER_REAL, 3.0)
                now[0] = 105.0
                with self.assertRaises(_DecompilationTimeout):
                    dispatch(signal.SIGALRM, None)
            assert timer.call_args == mock.call(signal.ITIMER_REAL, 0)

    def test_periodic_timer_is_restored_after_own_timeout(self):
        now = [100.0]
        with (
            mock.patch("signal.getitimer", return_value=(2.0, 4.0)),
            mock.patch("signal.signal", return_value=mock.Mock()) as handler,
            mock.patch("signal.setitimer") as timer,
            mock.patch("time.perf_counter", side_effect=lambda: now[0]),
        ):
            with self.assertRaises(_DecompilationTimeout), self.budget(5.0):
                dispatch = handler.call_args.args[1]
                now[0] = 102.0
                dispatch(signal.SIGALRM, None)
                now[0] = 105.0
                dispatch(signal.SIGALRM, None)
            assert timer.call_args == mock.call(signal.ITIMER_REAL, 1.0, 4.0)


if __name__ == "__main__":
    unittest.main()
