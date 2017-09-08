import imp
import pkg_resources
import os
import sys
import datetime

have_pygit = False
try:
    import git
    have_pygit = True
except ImportError:
    print("If you install pygit (`pip install pygit`), I can give you git info too!")

angr_modules = ['angr', 'cle', 'pyvex', 'claripy', 'archinfo', 'ana', 'simuvex', 'z3', 'unicorn']
native_modules = {'angr': 'angr.state_plugins.unicorn_engine._UC_NATIVE',
                  'unicorn': 'unicorn.unicorn._uc',
                  'pyvex': 'pyvex.pvc',
                  'z3': 'z3.z3core.lib()'}


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
        except Exception, e:
            print("An error occured importing %s: %s" % (m, e.message))
        print("Python found it in %s" % (python_filename))
        try:
            pip_version = pkg_resources.get_distribution(m)
            print("Pip version %s" % pip_version)
        except:
            print("Pip version not found!")
        print_git_info(python_filename)


def print_git_info(dirname):
    if not have_pygit:
        return
    try:
        repo = git.Repository(dirname)
    except git.repository.InvalidRepositoryError:
        try:
            repo = git.Repository(os.path.split(dirname)[0])
        except:
            print("Couldn't find git info")
            return
    print("Git info:")
    print("\tChecked out from: " + repo.config['remote.origin.url'])
    print("\tCurrent commit %s from branch %s" % (repo.head.shortname, repo.head.refname))


def print_system_info():
    print("Platform: " + pkg_resources.get_build_platform())
    print("Python version: " + str(sys.version))


def print_native_info():
    print "######### Native Module Info ##########"
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
