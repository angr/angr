import multiprocessing
import platform


def mp_context():
    system = platform.system()
    spawn_methods = {
        "Windows": "spawn",
        "Linux": "fork",
        # Python<3.8 defaults to fork
        # https://bugs.python.org/issue33725
        "Darwin": "spawn",
    }
    spawn_method = spawn_methods.get(system, "fork")  # default to fork on other platforms
    return multiprocessing.get_context(spawn_method)
