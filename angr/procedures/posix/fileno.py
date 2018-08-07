from ..libc import files

class fileno(files.FileProcedure):
    def run(self, ptr):
        fp = self.get_file(ptr)
        return fp.fd
