import os.path
import sys
import importlib.util


class FastPkgResources:
    @staticmethod
    def resource_filename(package, resource_name):
        spec = importlib.util.find_spec(package)
        if spec is None:
            return None
        if not spec.origin:
            return None
        if os.path.isfile(spec.origin):
            # get the directory
            base_dir = os.path.dirname(spec.origin)
        else:
            base_dir = spec.origin
        resource_path = os.path.join(base_dir, resource_name)
        if os.path.exists(resource_path):
            return resource_path
        return None


def import_fake_pkg_resources(force=False):
    if force or 'pkg_resources' not in sys.modules:
        sys.modules['pkg_resources'] = FastPkgResources


def remove_fake_pkg_resources():
    if sys.modules.get('pkg_resources') is FastPkgResources:
        sys.modules.pop('pkg_resources')
