import logging
import sys

_original_emit = logging.StreamHandler.emit

class Loggers(object):
    def __init__(self, default_level=logging.WARNING):
        self.default_level = default_level
        self._loggers = {}
        self.load_all_loggers()

        if not self.detect_test_env():
            self._install_root_logger()

    IN_SCOPE = ('angr', 'claripy', 'cle', 'pyvex', 'archinfo', 'tracer', 'driller', 'rex', 'patcherex', 'identifier')

    def load_all_loggers(self):
        """
        A dumb and simple way to conveniently aggregate all loggers.

        Adds attributes to this instance of each registered logger, replacing '.' with '_'
        """
        for name, logger in logging.Logger.manager.loggerDict.iteritems():
            if any(name.startswith(x + '.') or name == x for x in self.IN_SCOPE):
                self._loggers[name] = logger

    def __getattr__(self, k):
        real_k = k.replace('_', '.')
        if real_k in self._loggers:
            return self._loggers[real_k]
        else:
            raise AttributeError(k)

    def __dir__(self):
        return super(Loggers, self).__dir__() + self._loggers.keys()

    def _install_root_logger(self):
        if len(logging.root.handlers) == 0:
            # The default level is INFO
            fmt='%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s'
            logging.basicConfig(format=fmt, level=self.default_level)
            logging.StreamHandler.emit = self._emit_wrap

    @staticmethod
    def setall(level):
        for name in logging.Logger.manager.loggerDict.keys():
            logging.getLogger(name).setLevel(level)

    @staticmethod
    def _emit_wrap(*args, **kwargs):
        record = args[1]
        color = hash(record.name) % 7 + 31
        try:
            record.name = ("\x1b[%dm" % color) + record.name + "\x1b[0m"
        except Exception:
            pass

        try:
            record.msg = ("\x1b[%dm" % color) + record.msg + "\x1b[0m"
        except Exception:
            pass
        _original_emit(*args, **kwargs)

    @staticmethod
    def detect_test_env():
        i = 0
        while True:
            i += 1
            try:
                frame_module = sys._getframe(i).f_globals.get('__name__')
            except ValueError:
                break

            if frame_module == '__main__' or frame_module == '__console__':
                return False
            elif frame_module is not None and frame_module.startswith('nose.'):
                break

        return True

# Set the default to INFO at import time
# Loggers.setall(logging.INFO)