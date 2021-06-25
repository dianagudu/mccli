import struct
import fcntl
import termios
import signal
import sys
import re
import pexpect
from functools import partial
from click import echo

from .logging import logger


PASSWORD_REGEX = r"(?:[^\n]*)(?:Access Token:)$"
SSH_HOSTNAME_REGEX = r"debug1:\s+Connecting\s+to\s+(?P<host>\S+)\s+\[\S+\]\s+port\s+\d+."
SSH_HOSTNAME_PATTERN = re.compile(SSH_HOSTNAME_REGEX)
BIND_ADDRESS = "SOMETHING_OBVIOUSLY_WRONG_1234567890"
SSH_ERROR_BIND_ADDRESS = rf"getaddrinfo: {BIND_ADDRESS}: Name or service not known"


def ssh_wrap(ssh_args, username, token, str_get_token=None, dry_run=False):
    """Runs the ssh command given by list of ssh_args, using given username
    and given token as password.
    When dry_run is true, it only prints the sshpass command; when the string
    representation of the command to get the token is not defined (str_get_token),
    the actual token is printed.
    """
    ssh_command_str = " ".join(ssh_args)
    ssh_command_str = f"ssh -l {username} {ssh_command_str}"
    if dry_run:
        __dry_run(ssh_command_str, token, str_get_token)
    else:
        __process_wrap(ssh_command_str, [token])


def scp_wrap(scp_args, username, token, num_prompts=1, str_get_token=None, dry_run=False):
    """Runs the scp command given by list of scp_args, using given username
    and given token as password.
    This function only works for the SINGLE_REMOTE case, where there is a
    single motley_cue instance in the arguments.
    When dry_run is true, it only prints the sshpass command; when the string
    representation of the command to get the token is not defined (str_get_token),
    the actual token is printed.
    """
    scp_command_str = " ".join(scp_args)
    scp_command_str = f"scp -o User={username} {scp_command_str}"
    if dry_run:
        __dry_run(scp_command_str, token, str_get_token, num_prompts=num_prompts)
    else:
        __process_wrap(scp_command_str, [token]*num_prompts)


def scp_nowrap(scp_args, dry_run=False):
    """Runs the scp command given by the list of scp_args as it is,
    and lets the user interact with it for authentication.
    When dry_run is true, it only prints the scp command.
    """
    scp_command_str = f"scp {' '.join(scp_args)}"
    if dry_run:
        echo(scp_command_str)
    else:
        __process_passthrough(scp_command_str)


def scp_wrap_nouser_multipass(scp_args, tokens, str_get_tokens=None, dry_run=False):
    """Runs the scp command given by list of scp_args and inputs given token list
    when prompted multiple times for password..
    This function only works for the MULTIPLE_REMOTES case, where there are
    multiple motley_cue instances in the arguments, and the usernames have been added to scp_args.
    When dry_run is true, it only prints the tokens and the scp command; when the list of string
    representations of the commands to get the tokens is not defined (str_get_tokens),
    the actual tokens are printed.
    """
    scp_command_str = " ".join(scp_args)
    scp_command_str = f"scp {scp_command_str}"
    if dry_run:
        __dry_run(scp_command_str, tokens, str_get_tokens)
    else:
        __process_wrap(scp_command_str, tokens)


def get_hostname(ssh_args):
    """(HACKY) Try to get the ssh host from `ssh_args`
    by executing the ssh command with invalid `-b` option
    and parsing the output for the actual HOSTNAME.
    """
    # add strange option to make ssh fail without even sstarting pre-auth
    add_opts = ['ssh', '-v', '-b', BIND_ADDRESS]
    new_args = list(ssh_args)
    # remove possible duplicate -b options
    for i in range(new_args.count('-b')):
        index = new_args.index('-b')
        del new_args[index:index+2]
    new_args = add_opts + new_args
    command = " ".join(new_args)
    try:
        child_process = pexpect.spawn(command)
        child_process.expect(SSH_ERROR_BIND_ADDRESS)
        result = SSH_HOSTNAME_PATTERN.search(
            child_process.before.decode("utf-8"))
        if result:
            return result.group("host")
    except pexpect.ExceptionPexpect as e:
        logger.debug(e)
        logger.info("Error trying to get real hostname from ssh command")
    return None


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
    and sends the first password in list to the process.
    Removes the password from the list until the list is empty.
    """
    if info and info["passwords"] and len(info["passwords"]) and re.match(PASSWORD_REGEX, data.decode("utf-8")):
        info["child_process"].sendline(info["passwords"][0])
        info["child_process"].readline()  # to hide the token
        del info["passwords"][0]
        return b""
    return data


def __process_wrap(command, passwords):
    """Spawns a new process to run given command,
    and lets the user interact with it, except when prompted for
    Access Tokens, when it inputs the given passwords on
    behalf of the user, in the given order.
    """
    try:
        child_process = pexpect.spawn(command)
        signal.signal(signal.SIGWINCH, partial(
            __sigwinch_passthrough, child_process=child_process))
        __sigwinch_passthrough(child_process=child_process)

        info = {
            "child_process": child_process,
            "passwords": passwords
        }
        child_process.interact(
            output_filter=partial(__output_filter, info=info))
    except pexpect.ExceptionPexpect as e:
        child_process.logout()
        logger.error(e)
    except Exception as e:
        logger.error(e)


def __process_passthrough(command):
    """Spawns a new process to run given command,
    and lets the user interact with it.
    """
    try:
        child_process = pexpect.spawn(command)
        signal.signal(signal.SIGWINCH, partial(
            __sigwinch_passthrough, child_process=child_process))
        __sigwinch_passthrough(child_process=child_process)
        child_process.interact()
    except pexpect.ExceptionPexpect as e:
        child_process.logout()
        logger.error(e)
    except Exception as e:
        logger.error(e)


def __dry_run(command, token, str_get_token=None, num_prompts=1):
    """Print string representation of the sshpass command
    to run the given ssh/scp command and pass the access token
    when prompted for it.
    """
    if not str_get_token:
        str_get_token = token
    if not isinstance(token, list):
        if num_prompts == 1:
            echo(f"SSHPASS={str_get_token} sshpass -P 'Access Token' -e {command}")
        else:
            echo("# you'll need to input the token below every time you're prompted:")
            echo(f"echo {str_get_token}")
            echo(f"{command}")
    else:
        echo("# you'll need to input the tokens below when prompted in this order:")
        for str_at in str_get_token:
            echo(f"echo {str_at}")
        echo(f"{command}")
