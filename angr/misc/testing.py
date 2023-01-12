import sys


def detect_test_env():
    i = 0
    while True:
        i += 1
        try:
            frame_module = sys._getframe(i).f_globals.get("__name__")
        except ValueError:
            return False

        if frame_module == "__main__" or frame_module == "__console__":
            return False
        elif frame_module is not None and (frame_module.startswith("nose.") or frame_module.startswith("nose2.")):
            return True


is_testing = detect_test_env()
