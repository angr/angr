import traceback
import logging
import zlib

from .ansi import Color, BackgroundColor, color, clear

from .testing import is_testing
from ..utils.formatting import ansi_color_enabled


class Loggers:
    """
    Implements a loggers manager for angr.
    """

    __slots__ = (
        "default_level",
        "_loggers",
        "profiling_enabled",
        "handler",
    )

    def __init__(self, default_level=logging.WARNING):
        self.default_level = default_level
        self._loggers = {}
        self.load_all_loggers()
        self.profiling_enabled = False

        self.handler = logging.StreamHandler()
        self.handler.setFormatter(CuteFormatter(ansi_color_enabled))

        if not is_testing and len(logging.root.handlers) == 0:
            self.enable_root_logger()
            logging.root.setLevel(self.default_level)

    IN_SCOPE = ("angr", "claripy", "cle", "pyvex", "archinfo", "tracer", "driller", "rex", "patcherex", "identifier")

    def load_all_loggers(self):
        """
        A dumb and simple way to conveniently aggregate all loggers.

        Adds attributes to this instance of each registered logger, replacing '.' with '_'
        """
        for name, logger in logging.Logger.manager.loggerDict.items():
            if any(name.startswith(x + ".") or name == x for x in self.IN_SCOPE):
                self._loggers[name] = logger

    def __getattr__(self, k):
        real_k = k.replace("_", ".")
        if real_k in self._loggers:
            return self._loggers[real_k]
        else:
            raise AttributeError(k)

    def __dir__(self):
        return list(super().__dir__()) + list(self._loggers.keys())

    def enable_root_logger(self):
        """
        Enable angr's default logger
        """
        logging.root.addHandler(self.handler)

    def disable_root_logger(self):
        """
        Disable angr's default logger
        """
        logging.root.removeHandler(self.handler)

    @staticmethod
    def setall(level):
        for name in logging.Logger.manager.loggerDict:
            logging.getLogger(name).setLevel(level)


class CuteFormatter(logging.Formatter):
    """
    A log formatter that can print log messages with colors.
    """

    __slots__ = ("_should_color",)

    def __init__(self, should_color: bool):
        super().__init__()
        self._should_color: bool = should_color

    def format(self, record: logging.LogRecord):
        name: str = record.name
        level: str = record.levelname
        message: str = record.getMessage()
        name_len: int = len(name)
        lvl_len: int = len(level)
        if self._should_color:
            # Color level
            if record.levelno >= logging.CRITICAL:
                level = color(Color.red, True) + level + clear
                level = color(BackgroundColor.yellow, False) + level + clear
            elif record.levelno >= logging.ERROR:
                level = color(Color.red, False) + level + clear
            elif record.levelno >= logging.WARNING:
                level = color(Color.yellow, False) + level + clear
            elif record.levelno >= logging.INFO:
                level = color(Color.blue, False) + level + clear
            # Color text
            c: int = zlib.adler32(record.name.encode()) % 7
            if c != 0:  # Do not color black or white, allow 'uncolored'
                col = Color(c + Color.black.value)
                message = color(col, False) + message + clear
                name = color(col, False) + name + clear
        # Finalize log message
        name = name.ljust(14 + len(name) - name_len)
        level = level.ljust(8 + len(level) - lvl_len)
        body: str = f"{level} | {self.formatTime(record, self.datefmt) : <23} | {name} | {message}"
        if record.exc_info:
            body += "\n" + "".join(traceback.format_exception(*record.exc_info))[:-1]
        return body


def is_enabled_for(logger, level):
    if level == 1:
        from .. import loggers

        return loggers.profiling_enabled
    return originalIsEnabledFor(logger, level)


originalIsEnabledFor = logging.Logger.isEnabledFor

# Override isEnabledFor() for Logger class
logging.Logger.isEnabledFor = is_enabled_for
