import struct
import fcntl
import termios
import signal
import sys
import re
import pexpect
import os
from functools import partial
from click import echo
from random import randint

from .logging import logger


PASSWORD_REGEX = r"(?:[^\n]*)(?:Access Token:)$"
SSH_HOSTNAME_REGEX = r"debug1: Connecting to (?P<host>\S+) \[\S+\] port \d+."
SSH_HOSTNAME_PATTERN = re.compile(SSH_HOSTNAME_REGEX)
BIND_ADDRESS = "SOMETHING_OBVIOUSLY_WRONG_1234567890"
ERROR_MSG_1 = "Name or service not known"
ERROR_MSG_2 = "No address associated with hostname"
SSH_ERROR_BIND_ADDRESS = rf"(?P<errorprefix>getaddrinfo: {BIND_ADDRESS}:) (?P<errormsg>[^\r\n]+)"


def ssh_wrap(ssh_args, username, token, str_get_token=None, dry_run=False):
    """Runs the ssh command given by list of ssh_args, using given username
    and given token as password.

    When dry_run is true, it only prints the sshpass command; when the string
    representation of the command to get the token is not defined (str_get_token),
    the actual token is printed.
    """
    # add oidc-agent forwarding
    random_no = randint(10000, 99999)
    oidc_sock = os.getenv("OIDC_SOCK")
    if oidc_sock:
        ssh_args = ["-R", f"/tmp/oidc-forward-{random_no}:{oidc_sock}"] + ssh_args
    ssh_command_str = " ".join(ssh_args)
    ssh_command_str = f"ssh -l {username} {ssh_command_str}"
    if dry_run:
        __dry_run(ssh_command_str, tokens=token, str_get_tokens=str_get_token)
    else:
        __process_wrap(ssh_command_str, passwords=[token])


def scp_wrap(scp_args, username=None, tokens=None, str_get_tokens=None,
             num_prompts=1, dry_run=False):
    """Runs the scp command given by list of scp_args.

    If `username` and `tokens` are both None, we are in the NO_MOTLEY_CUE case
    and the process is simply started as it is; the user will interact with the process
    for any needed authentication; there is no motley_cue handling.

    If `username` is set, we are in the SINGLE_REMOTE case, where there is a
    single motley_cue instance in the arguments, so the user can be passed as an ssh
    option with '-o User'. The `tokens` argument must be a string in this case.
    The command will prompt for the token `num_prompts` times.

    If `username` is not set, but `tokens` is (must be a list), then we are in the MULTIPLE_REMOTES case,
    where the scp_args have been already augmented with usernames obtained from the motley_cue
    service(s). The `tokens` have to be input when prompted, in the given order. There should
    not be more prompts than tokens; any subsequent prompts will be forwarded to the user to handle.

    When dry_run is true, it only prints the needed command(s); if `str_get_tokens` is set,
    it prints the string representation(s) of the command(s) to get the token(s) instead
    of the actual token(s). 
    """
    if not username and not tokens:
        passwords = tokens
    elif username and isinstance(tokens, str):
        scp_args = ['-o', f"User={username}"] + scp_args   # scp_args is a tuple
        passwords = [tokens] * num_prompts
    elif not username and isinstance(tokens, list):
        passwords = tokens
    else:
        raise Exception("Unsupported use case")

    scp_command_str = f"scp {' '.join(scp_args)}"
    if dry_run:
        __dry_run(scp_command_str, tokens=tokens,
                  str_get_tokens=str_get_tokens, num_prompts=num_prompts)
    else:
        __process_wrap(scp_command_str, passwords=passwords)


def get_hostname(ssh_args):
    """(HACKY) Try to get the ssh host from `ssh_args`
    by executing the ssh command with invalid `-b` option
    and parsing the output for the actual HOSTNAME.
    """
    # add strange option to make ssh fail without even sstarting pre-auth
    add_opts = ['ssh', '-v', '-b', BIND_ADDRESS]
    new_args = ssh_args.copy()
    # remove possible duplicate -b options
    for i in range(new_args.count('-b')):
        index = new_args.index('-b')
        del new_args[index:index+2]
    new_args = add_opts + new_args
    command = " ".join(new_args)
    try:
        logger.debug(f"Running this command is expected to fail: {command}")
        child_process = pexpect.spawn(command)
        child_process.expect(SSH_ERROR_BIND_ADDRESS)
        errorprefix = child_process.match.group('errorprefix').decode('utf-8')
        errormsg = child_process.match.group('errormsg').decode('utf-8')
        logger.debug(f"Command failed with error message: '{errorprefix} {errormsg}'")
        result = SSH_HOSTNAME_PATTERN.search(
            child_process.before.decode("utf-8"))
        if result:
            hostname = result.group("host")
            logger.debug(f"Found hostname by parsing command error logs: {hostname}")
            return hostname
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


def __process_wrap(command, passwords=None):
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
        if passwords:
            info = {
                "child_process": child_process,
                "passwords": passwords
            }
            child_process.interact(
                output_filter=partial(__output_filter, info=info))
        else:
            child_process.interact()
    except pexpect.ExceptionPexpect as e:
        child_process.logout()
        logger.error(e)
    except Exception as e:
        logger.error(e)


def __dry_run(command, tokens=None, str_get_tokens=None, num_prompts=1):
    """Print string representation of the given ssh/scp `command`.

    If `tokens` is None, print `command` as it is.

    If `tokens` is a list, print the tokens first (or the string
    representation of the commands used to get the tokens, if
    `str_get_tokens` is set).

    If `tokens` is a string and only prompted for once, print the
    sshpass command to run the given ssh/scp command and to
    pass the access token when prompted for it. With multiple prompts,
    print the token and the command separately, with information.
    """
    if not str_get_tokens:
        str_get_tokens = tokens
    if not tokens:
        echo(command)
    elif isinstance(tokens, list):
        echo("# you'll need to input the tokens below when prompted, in this order:")
        for str_at in str_get_tokens:
            echo(f"echo {str_at}")
        echo(f"{command}")
    else:
        if num_prompts == 1:
            echo(f"SSHPASS={str_get_tokens} sshpass -P 'Access Token' -e {command}")
        else:
            echo(f"# you'll need to input the token below {num_prompts} times:")
            echo(f"echo {str_get_tokens}")
            echo(f"{command}")
