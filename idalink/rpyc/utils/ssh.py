import os
from subprocess import Popen, PIPE
from rpyc.lib import safe_import
from rpyc.lib.compat import BYTES_LITERAL
signal = safe_import("signal")

# modified from the stdlib pipes module for windows
_safechars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@%_-+=:,./'
_funnychars = '"`$\\'
def shquote(text):
    if not text:
        return "''"
    for c in text:
        if c not in _safechars:
            break
    else:
        return text
    if "'" not in text:
        return "'" + text + "'"
    def escaped(c):
        if c in _funnychars:
            return '\\' + c 
        else:
            return c
    res = "".join(escaped(c) for c in text)
    return '"' + res + '"'

class ProcessExecutionError(Exception):
    """raised by :func:`SshContext.execute` should the executed process 
    terminate with an error"""
    pass

import subprocess
def _get_startupinfo():
    if subprocess.mswindows:
        import _subprocess
        sui = subprocess.STARTUPINFO()
        sui.dwFlags |= _subprocess.STARTF_USESHOWWINDOW #@UndefinedVariable
        sui.wShowWindow = _subprocess.SW_HIDE #@UndefinedVariable
        return sui
    else:
        return None

class SshTunnel(object):
    """
    Represents an active SSH tunnel (as created by ``ssh -L``).
    
    .. note:: 
       Do not instantiate this class yourself -- use the :func:`SshContext.tunnel`
       function for that.
    """
    
    PROGRAM = r"""import sys;sys.stdout.write("ready\n\n\n");sys.stdout.flush();sys.stdin.readline()"""

    def __init__(self, sshctx, loc_host, loc_port, rem_host, rem_port):
        self.loc_host = loc_host
        self.loc_port = loc_port
        self.rem_host = rem_host
        self.rem_port = rem_port
        self.sshctx = sshctx
        self.proc = sshctx.popen("python", "-u", "-c", self.PROGRAM,
            L = "[%s]:%s:[%s]:%s" % (loc_host, loc_port, rem_host, rem_port))
        banner = self.proc.stdout.readline().strip()
        if banner != BYTES_LITERAL("ready"):
            raise ValueError("tunnel failed", banner)
    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
    def __str__(self):
        return "%s:%s --> (%s)%s:%s" % (self.loc_host, self.loc_port, self.sshctx.host,
            self.rem_host, self.rem_port)
    def is_open(self):
        """returns True if the ``ssh`` process is alive, False otherwise"""
        return self.proc and self.proc.poll() is None
    def close(self):
        """closes (terminates) the SSH tunnel"""
        if not self.is_open():
            return
        self.proc.stdin.write(BYTES_LITERAL("foo\n\n\n"))
        self.proc.stdin.close()
        self.proc.stdout.close()
        self.proc.stderr.close()
        try:
            self.proc.kill()
        except AttributeError:
            if signal:
                os.kill(self.proc.pid, signal.SIGTERM)
        self.proc.wait()
        self.proc = None

class SshContext(object):
    """
    An *SSH context* encapsulates all the details required to establish an SSH 
    connection to other host. It includes the host name, user name, TCP port, 
    identity file, etc.
    
    Once constructed, it can serve as a factory for SSH operations, such as 
    executing a remote program and getting its stdout, or uploading/downloading
    files using ``scp``. It also serves for creating SSH tunnels. 
    
    Example::
    
        >>> sshctx = SshContext("mymachine", username="borg", keyfile="/home/foo/.ssh/mymachine-id")
        >>> sshctx.execute("ls")
        (0, "...", "")
    """
    def __init__(self, host, user = None, port = None, keyfile = None,
            ssh_program = "ssh", ssh_env = None, ssh_cwd = None,
            scp_program = "scp", scp_env = None, scp_cwd = None):
        self.host = host
        self.user = user
        self.port = port
        self.keyfile = keyfile
        self.ssh_program = ssh_program
        self.ssh_env = ssh_env
        self.ssh_cwd = ssh_cwd
        self.scp_program = scp_program
        self.scp_env = scp_env
        self.scp_cwd = scp_cwd

    def __str__(self):
        uri = "ssh://"
        if self.user:
            uri += "%s@%s" % (self.user, self.host)
        else:
            uri += self.host
        if self.port:
            uri += ":%d" % (self.port)
        return uri

    def _convert_kwargs_to_args(self, kwargs):
        args = []
        for k, v in kwargs.items():
            if v is True:
                args.append("-%s" % (k,))
            elif v is False:
                pass
            else:
                args.append("-%s" % (k,))
                args.append(str(v))
        return args

    def _process_scp_cmdline(self, kwargs):
        args = [self.scp_program]
        if "r" not in kwargs:
            kwargs["r"] = True
        if self.keyfile and "i" not in kwargs:
            kwargs["i"] = self.keyfile
        if self.port and "P" not in kwargs:
            kwargs["P"] = self.port
        args.extend(self._convert_kwargs_to_args(kwargs))
        if self.user:
            host = "%s@%s" % (self.user, self.host)
        else:
            host = self.host
        return args, host

    def _process_ssh_cmdline(self, kwargs):
        args = [self.ssh_program]
        if self.keyfile and "i" not in kwargs:
            kwargs["i"] = self.keyfile
        if self.port and "p" not in kwargs:
            kwargs["p"] = self.port
        args.extend(self._convert_kwargs_to_args(kwargs))
        if self.user:
            args.append("%s@%s" % (self.user, self.host))
        else:
            args.append(self.host)
        return args

    def popen(self, *args, **kwargs):
        """Runs the given command line remotely (over SSH), returning the 
        ``subprocess.Popen`` instance of the command
        
        :param args: the command line arguments
        :param kwargs: additional keyword arguments passed to ``ssh``
        
        :returns: a ``Popen`` instance
        
        Example::
            
            proc = ctx.popen("ls", "-la")
            proc.wait()
        """
        cmdline = self._process_ssh_cmdline(kwargs)
        cmdline.extend(shquote(a) for a in args)
        return Popen(cmdline, stdin = PIPE, stdout = PIPE, stderr = PIPE,
            cwd = self.ssh_cwd, env = self.ssh_env, shell = False, 
            startupinfo = _get_startupinfo())

    def execute(self, *args, **kwargs):
        """Runs the given command line remotely (over SSH), waits for it to finish,
        returning the return code, stdout, and stderr of the executed process.
        
        :param args: the command line arguments
        :param kwargs: additional keyword arguments passed to ``ssh``, except for
                       ``retcode`` and ``input``.
        :param retcode: *keyword only*, the expected return code (Defaults to 0 
                        -- success). An exception is raised if the return code does
                        not match the expected one, unless it is ``None``, in 
                        which case it will not be tested.
        :param input: *keyword only*, an input string that will be passed to 
                      ``Popen.communicate``. Defaults to ``None``
        
        :raises: :class:`ProcessExecutionError` if the expected return code 
                 is not matched
        
        :returns: a tuple of (return code, stdout, stderr)
        
        Example::
            
            rc, out, err = ctx.execute("ls", "-la")
        """
        retcode = kwargs.pop("retcode", 0)
        input = kwargs.pop("input", None)
        proc = self.popen(*args, **kwargs)
        stdout, stderr = proc.communicate(input)
        if retcode is not None and proc.returncode != retcode:
            raise ProcessExecutionError(proc.returncode, stdout, stderr)
        return proc.returncode, stdout, stderr

    def upload(self, src, dst, **kwargs):
        """
        Uploads *src* from the local machine to *dst* on the other side. By default, 
        ``-r`` (recursive copy) is given to ``scp``, so *src* can be either a file or 
        a directory. To override this behavior, pass ``r = False`` as a keyword argument. 
        
        :param src: the source path (on the local side)
        :param dst: the destination path (on the remote side)
        :param kwargs: any additional keyword arguments, passed to ``scp``.
        """
        cmdline, host = self._process_scp_cmdline(kwargs)
        cmdline.append(src)
        cmdline.append("%s:%s" % (host, dst))
        proc = Popen(cmdline, stdin = PIPE, stdout = PIPE, stderr = PIPE, shell = False,
            cwd = self.scp_cwd, env = self.scp_env, startupinfo = _get_startupinfo())
        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            raise ValueError("upload failed", stdout, stderr)

    def download(self, src, dst, **kwargs):
        """
        Downloads *src* from the other side to *dst* on the local side. By default, 
        ``-r`` (recursive copy) is given to ``scp``, so *src* can be either a file or 
        a directory. To override this behavior, pass ``r = False`` as a keyword argument.
        
        :param src: the source path (on the other side)
        :param dst: the destination path (on the local side)
        :param kwargs: any additional keyword arguments, passed to ``scp``.
        """
        cmdline, host = self._process_scp_cmdline(kwargs)
        cmdline.append("%s:%s" % (host, src))
        cmdline.append(dst)
        proc = Popen(cmdline, stdin = PIPE, stdout = PIPE, stderr = PIPE, shell = False,
            cwd = self.scp_cwd, env = self.scp_env, startupinfo = _get_startupinfo())
        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            raise ValueError("upload failed", stdout, stderr)

    def tunnel(self, loc_port, rem_port, loc_host = "localhost", rem_host = "localhost"):
        """
        Creates an SSH tunnel from the local port to the remote one. This is
        translated to ``ssh -L loc_host:loc_port:rem_host:rem_port``.
        
        :param loc_port: the local TCP port to forward
        :param rem_port: the remote (server) TCP port, to which the local port 
                         will be forwarded
        
        :returns: an :class:`SshTunnel` instance
        """
        return SshTunnel(self, loc_host, loc_port, rem_host, rem_port)

