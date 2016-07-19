import logging

_original_emit = logging.StreamHandler.emit

class Loggers(object):
    def __init__(self, default_level=logging.WARNING):
        """
        A dumb and simple way to aggregate all loggers in a convenient way
        """
        # All loggers are an attr of self for tab completion in iPython
        # (with . replaced with _)
        self._loggerdict = logging.Logger.manager.loggerDict
        for name, logger in self._loggerdict.iteritems():
            attr = name.replace('.', '_')
            setattr(self, attr, logger)

        if len(logging.root.handlers) == 0:
            # The default level is INFO
            fmt='%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s'
            logging.basicConfig(format=fmt, level=default_level)
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


# Set the default to INFO at import time
# Loggers.setall(logging.INFO)


