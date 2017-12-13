from collections import defaultdict, OrderedDict

from .successors import SimSuccessors
from .engine import SimEngine

from .vex import SimEngineVEX
from .procedure import SimEngineProcedure
from .unicorn import SimEngineUnicorn
from .failure import SimEngineFailure
from .syscall import SimEngineSyscall
from .hook import SimEngineHook
from .hub import EngineHub

from ..misc.plugins import PluginHub, PluginPreset
from ..errors import AngrError, NoPlugin


def global_default(): return {'any': SimEngineVEX}
default_engines = defaultdict(global_default)


def register_default_engine(loader_backend, engine, arch='any'):
    """
    Register the default execution engine to be used with a given CLE backend.
    Usually this is the SimEngineVEX, but if you're operating on something that isn't
    going to be lifted to VEX, you'll need to make sure the desired engine is registered here.

    :param loader_backend: The loader backend (a type)
    :param type engine: The engine to use for the loader backend (a type)
    :param arch: The architecture to associate with this engine. Optional.
    :return:
    """
    if not isinstance(loader_backend, type):
        raise TypeError("loader_backend must be a type")
    if not isinstance(engine, type):
        raise TypeError("engine must be a type")
    default_engines[loader_backend][arch] = engine


def get_default_engine(loader_backend, arch='any'):
    """
    Get some sort of sane default for a given loader and/or arch.
    Can be set with register_default_engine()
    :param loader_backend:
    :param arch:
    :return:
    """
    matches = default_engines[loader_backend]
    for k,v in matches.items():
        if k == arch or k == 'any':
            return v
    return None


class DefaultPluginPreset(PluginPreset):

    @classmethod
    def apply_preset(cls, engines, *args, **kwargs):
        """

        :param engines:
        :param project:
        :param stop_points:
        :param use_cache:
        :param support_selfmodifying_code:
        :return:
        """
        try:
            project = args[0]
        except IndexError:
            raise AngrError("This preset expects Project as the first argument")

        # Look up the default engine.
        stop_points = kwargs.get('stop_points')
        use_cache = kwargs.get('use_cache')
        support_selfmodifying_code = kwargs.get('support_selfmodifying_code')
        default_engine = cls._init_default_engine(project, stop_points, use_cache, support_selfmodifying_code)

        # Register the engines in the given EngineHub.
        engines.register_plugin('default', default_engine)
        engines.register_plugin('procedure', SimEngineProcedure())
        engines.register_plugin('failure', SimEngineFailure(project))
        engines.register_plugin('syscall', SimEngineSyscall(project))
        engines.register_plugin('hook', SimEngineHook(project))
        engines.register_plugin('unicorn', SimEngineUnicorn(stop_points))

        # Set processing order.
        del engines.processing_order[:]
        engines.processing_order.extend(('failure', 'syscall', 'hook', 'unicorn', 'default'))

    @classmethod
    def _init_default_engine(cls, project, stop_points, use_cache, support_selfmodifying_code):
        """

        :param project:
        :param stop_points:
        :param use_cache:
        :param support_selfmodifying_code:
        :return:
        """
        engine_cls = get_default_engine(type(project.loader.main_object))
        if not engine_cls:
            raise AngrError("No engine associated with loader %s" % str(type(project.loader.main_object)))
        return engine_cls(stop_points=stop_points, use_cache=use_cache,
                          support_selfmodifying_code=support_selfmodifying_code)


ALL_PRESETS = {
    'default': DefaultPluginPreset,
}
