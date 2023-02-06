import imp
import os
import sys
import datetime
import gc
import ctypes

from .import_hooks import remove_fake_pkg_resources


have_gitpython = False
try:
    from git import Repo, InvalidGitRepositoryError

    have_gitpython = True
except ImportError:
    print("If you install gitpython (`pip install gitpython`), I can give you git info too!")


angr_modules = ["angr", "ailment", "cle", "pyvex", "claripy", "archinfo", "z3", "unicorn"]
native_modules = {
    "angr": lambda: angr.state_plugins.unicorn_engine._UC_NATIVE,  # pylint: disable=undefined-variable
    "unicorn": lambda: unicorn.unicorn._uc,  # pylint: disable=undefined-variable
    "pyvex": lambda: pyvex.pvc,  # pylint: disable=undefined-variable
    "z3": lambda: [x for x in gc.get_objects() if type(x) is ctypes.CDLL and "z3" in str(x)][0],  # YIKES FOREVER
}
python_packages = {"z3": "z3-solver"}


def get_venv():
    if "VIRTUAL_ENV" in os.environ:
        return os.environ["VIRTUAL_ENV"]
    return None


def print_versions():
    remove_fake_pkg_resources()
    # import the real pkg_resources
    import pkg_resources  # pylint:disable=import-outside-toplevel

    for m in angr_modules:
        print("######## %s #########" % m)
        try:
            _, python_filename, _ = imp.find_module(m)
        except ImportError:
            print("Python could not find " + m)
            continue
        except Exception as e:  # pylint: disable=broad-except
            print(f"An error occurred importing {m}: {e}")
        print("Python found it in %s" % (python_filename))
        try:
            pip_package = python_packages.get(m, m)
            pip_version = pkg_resources.get_distribution(pip_package)
            print("Pip version %s" % pip_version)
        except Exception:  # pylint: disable-broad-except
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
    print(f"\tCurrent commit {cur_commit.hexsha} from branch {cur_branch.name}")
    try:
        # EDG: Git is insane, but this should work 99% of the time
        cur_tb = cur_branch.tracking_branch()
        if cur_tb.is_remote():
            remote_name = cur_tb.remote_name
            remote_url = repo.remotes[remote_name].url
            print(f"\tChecked out from remote {remote_name}: {remote_url}")
        else:
            print("Tracking local branch %s" % cur_tb.name)
    except Exception:  # pylint: disable=broad-except
        print("Could not resolve tracking branch or remote info!")


def print_system_info():
    remove_fake_pkg_resources()
    # import the real pkg_resources
    import pkg_resources  # pylint:disable=import-outside-toplevel

    print("Platform: " + pkg_resources.get_build_platform())
    print("Python version: " + str(sys.version))


def print_native_info():
    print("######### Native Module Info ##########")
    for module, funcs in native_modules.items():
        try:
            globals()[module] = __import__(module)
            try:
                print(f"{module}: {funcs()}")
            except Exception as e:  # pylint: disable=broad-except
                print(f"{module}: imported but path finding raised a {type(e)}: {e}")
        except ModuleNotFoundError:
            print(f"{module}: NOT FOUND")
        except ImportError:
            print(f"{module}: FOUND BUT FAILED TO IMPORT")
        except Exception as e:  # pylint: disable=broad-except
            print(f"{module}: __import__ raised a {type(e)}: {e}")


def bug_report():
    print("angr environment report")
    print("=============================")
    print("Date: " + str(datetime.datetime.today()))
    if get_venv():
        print("Running in virtual environment at " + get_venv())
    else:
        print("!!! running in global environment.  Are you sure? !!!")
    print_system_info()
    print_versions()
    print_native_info()


if __name__ == "__main__":
    bug_report()
