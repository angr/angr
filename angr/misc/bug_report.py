import imp
import pkg_resources
import os
import sys
import datetime
import gc
import ctypes

have_gitpython = False
try:
    from git import Repo, InvalidGitRepositoryError
    have_gitpython = True
except ImportError:
    print("If you install gitpython (`pip install gitpython`), I can give you git info too!")

angr_modules = ['angr', 'ailment', 'cle', 'pyvex', 'claripy', 'archinfo', 'z3', 'unicorn']
native_modules = {'angr': 'angr.state_plugins.unicorn_engine._UC_NATIVE',
                  'unicorn': 'unicorn.unicorn._uc',
                  'pyvex': 'pyvex.pvc',
                  'z3': "[x for x in gc.get_objects() if type(x) is ctypes.CDLL and 'z3' in str(x)][0]"} # YIKES FOREVER
python_packages = {'z3': 'z3-solver'}


def get_venv():
    if 'VIRTUAL_ENV' in os.environ:
        return os.environ['VIRTUAL_ENV']
    return None


def import_module(module):
    try:
        # because we want to import using a variable, do it this way
        module_obj = __import__(module)
        # create a global object containging our module
        globals()[module] = module_obj
    except ImportError:
        sys.stderr.write("ERROR: missing python module: " + module + "\n")
        sys.exit(1)

def print_versions():
    for m in angr_modules:
        print("######## %s #########" % m)
        try:
            _, python_filename, _ = imp.find_module(m)
        except ImportError:
            print("Python could not find " + m)
            continue
        except Exception as e:
            print("An error occurred importing %s: %s" % (m, e))
        print("Python found it in %s" % (python_filename))
        try:
            pip_package = python_packages.get(m, m)
            pip_version = pkg_resources.get_distribution(pip_package)
            print("Pip version %s" % pip_version)
        except:
            print("Pip version not found!")
        print_git_info(python_filename)


def print_git_info(dirname):
    if not have_gitpython:
        return
    try:
        repo = Repo(dirname, search_parent_directories=True)
    except InvalidGitRepositoryError:
        print("Couldn't find git info")
        return
    cur_commit = repo.commit()
    cur_branch = repo.active_branch
    print("Git info:")
    print("\tCurrent commit %s from branch %s" % (cur_commit.hexsha, cur_branch.name))
    try:
        # EDG: Git is insane, but this should work 99% of the time
        cur_tb = cur_branch.tracking_branch()
        if cur_tb.is_remote():
            remote_name = cur_tb.remote_name
            remote_url = repo.remotes[remote_name].url
            print("\tChecked out from remote %s: %s" % (remote_name, remote_url))
        else:
            print("Tracking local branch %s" % cur_tb.name)
    except:
        print("Could not resolve tracking branch or remote info!")

def print_system_info():
    print("Platform: " + pkg_resources.get_build_platform())
    print("Python version: " + str(sys.version))


def print_native_info():
    print("######### Native Module Info ##########")
    for module, path in native_modules.items():
        try:
            import_module(module)
            print("%s: %s" % (module, str(eval(path))))
        except:
            print("%s: NOT FOUND" % (module))


def bug_report():
    print("angr environment report")
    print("=============================")
    print("Date: " + str(datetime.datetime.today()))
    if get_venv():
        print("Running in virtual environment at " + get_venv())
    else:
        print("!!! runninng in global environment.  Are you sure? !!!")
    print_system_info()
    print_versions()
    print_native_info()


if __name__ == "__main__":
    bug_report()
