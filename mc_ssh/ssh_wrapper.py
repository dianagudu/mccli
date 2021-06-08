import struct
import fcntl
import termios
import signal
import sys
import re
import pexpect
from functools import partial

from .logging import logger


SSH_PORT = 22
PASSWORD_REGEX = r"(?:[^\n]*)(?:Access Token:)$"


def ssh_exec(hostname, username, token, port, command):
    cmd = f"ssh -l {username} -p {port} {hostname} '{command}'"
    __process_wrap(cmd, token)


def ssh_interactive(hostname, username, token, port):
    command = f"ssh -l {username} -p {port} {hostname}"
    __process_wrap(command, token)


def scp_put(hostname, username, token, port, src, dest,
            recursive=False, preserve_times=False):
    scp_opts = __scp_opts_str(port, recursive, preserve_times)
    command = f"scp {scp_opts} {src} {username}@{hostname}:{dest}"
    __process_wrap(command, token)


def scp_get(hostname, username, token, port, src, dest,
            recursive=False, preserve_times=False):
    scp_opts = __scp_opts_str(port, recursive, preserve_times)
    command = f"scp {scp_opts} {username}@{hostname}:{src} {dest}"
    __process_wrap(command, token)


def __sigwinch_passthrough(sig=None, data=None, child_process=None):
    """ Pass window changes to child
    """
    s = struct.pack("HHHH", 0, 0, 0, 0)
    a = struct.unpack('hhhh', fcntl.ioctl(sys.stdout.fileno(),
                                          termios.TIOCGWINSZ, s))
    if not child_process.closed:
        child_process.setwinsize(a[0], a[1])


def __output_filter(data, info=None):
    """Checks output from child process for Access Token prompt
    and sends the token to the process.
    """
    if info and info["login"] and re.match(PASSWORD_REGEX, data.decode("utf-8")):
        info["child_process"].sendline(info["password"])
        info["child_process"].readline()  # to hide the token
        info["login"] = False
        return b""
    return data


def __process_wrap(command, password):
    try:
        child_process = pexpect.spawn(command)
        signal.signal(signal.SIGWINCH, partial(
            __sigwinch_passthrough, child_process=child_process))
        __sigwinch_passthrough(child_process=child_process)

        info = {
            "child_process": child_process,
            "password": password,
            "login": True
        }
        child_process.interact(
            output_filter=partial(__output_filter, info=info))
    except pexpect.ExceptionPexpect as e:
        child_process.logout()
        logger.error(e)
    except Exception as e:
        logger.error(e)


def __scp_opts_str(port, recursive, preserve_times):
    scp_opts = f"-P {port}"
    if recursive:
        scp_opts = f"{scp_opts} -r"
    if preserve_times:
        scp_opts = f"{scp_opts} -p"
    return scp_opts
