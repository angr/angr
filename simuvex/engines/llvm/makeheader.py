import os
import re
import subprocess

LSHIFT_RE = re.compile(r"(\d+) *<< *(\d+)")
CXX_CHECK_START = """#ifdef __cplusplus
extern "C" {
#endif
"""
CXX_CHECK_END = """#ifdef __cplusplus
}
#endif
"""
DEFAULT_HEADERS = [
    "llvm-c/Types.h",
    "llvm-c/ErrorHandling.h",
    "llvm-c/Core.h",
    "llvm-c/IRReader.h",
]

def replace_lshifts(src):
    return LSHIFT_RE.sub(lambda m: str(int(m.group(1)) << int(m.group(2))), src, count=len(src))

def clean_header(h_path):
    with open(h_path, 'rb') as f:
        header = f.read()
    header = header[header.find(CXX_CHECK_START)+len(CXX_CHECK_START):]
    header = header[:header.rfind(CXX_CHECK_END)]
    header = replace_lshifts(header)
    return header

def concat_and_clean(base_path, headers):
    return '\n'.join(clean_header(os.path.join(base_path, h_path)) for h_path in headers)

def preprocess(header):
    proc = subprocess.Popen(
        ['gcc', '-E', '-'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate(header)
    if proc.returncode != 0:
        raise ValueError("something went wrong in preprocessing: %s" % stderr)
    return '\n'.join(line for line in stdout.split('\n') if not line.startswith('#'))

if __name__ == '__main__':
    import sys
    out = preprocess(concat_and_clean(sys.argv[1], DEFAULT_HEADERS))
    with open(sys.argv[2], 'wb') as f:
        f.write(out)
