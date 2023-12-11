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
import regex
from requests import options

from .logging import logger
from . import exceptions


PASSWORD_REGEX = r"(?:[^\n]*)(?:Access Token:)$"
SSH_HOSTNAME_PATTERN = re.compile(
    r"^hostname\s+(?P<hostname>\S+)\s+$", flags=re.MULTILINE
)


def ssh_wrap(
    ssh_args, username, token, str_get_token=None, dry_run=False, set_remote_env=False
):
    """Runs the ssh command given by list of ssh_args, using given username
    and given token as password.

    When dry_run is true, it only prints the sshpass command; when the string
    representation of the command to get the token is not defined (str_get_token),
    the actual token is printed.

    When set_remote_env is true, it sets the environment variable OIDC_SOCK on the
    remote host to the forwarded oidc agent socket. This is useful for non-interactive
    ssh sessions, when the user does not have a shell on the remote host.
    """
    # add oidc-agent forwarding
    random_no = randint(10000, 99999)
    oidc_sock = os.getenv("OIDC_SOCK")
    if oidc_sock:
        remote_oidc_sock = f"/tmp/oidc-agent-{random_no}"
        options_oidc_sock = [
            "-R",
            f"{remote_oidc_sock}:{oidc_sock}",
        ]
        if set_remote_env:
            options_oidc_sock += [
                "-o",
                f'SetEnv="OIDC_SOCK={remote_oidc_sock}"',
            ]
        ssh_args = options_oidc_sock + ssh_args
    ssh_command_str = " ".join(ssh_args)
    ssh_command_str = f"ssh -l {username} {ssh_command_str}"
    if dry_run:
        __dry_run(ssh_command_str, tokens=token, str_get_tokens=str_get_token)
    elif sys.__stdin__.isatty():
        logger.debug("is a tty")
        __process_wrap(ssh_command_str, passwords=[token])
    else:
        logger.debug("is not a tty")
        ssh_args = ["-o", "StrictHostKeyChecking=no", "-T"] + ssh_args
        ssh_command_str = " ".join(ssh_args)
        ssh_command_str = f"ssh -l {username} {ssh_command_str}"
        __non_interactive_ssh(ssh_command_str, token)


def scp_wrap(
    scp_args,
    username=None,
    tokens=None,
    str_get_tokens=None,
    num_prompts=1,
    dry_run=False,
):
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
        scp_args = ["-o", f"User={username}"] + scp_args  # scp_args is a tuple
        passwords = [tokens] * num_prompts
    elif not username and isinstance(tokens, list):
        passwords = tokens
    else:
        raise Exception("Unsupported use case")

    if sys.__stdin__.isatty():
        scp_args = ["-o", "StrictHostKeyChecking=no"] + scp_args

    scp_command_str = f"scp {' '.join(scp_args)}"
    if dry_run:
        __dry_run(
            scp_command_str,
            tokens=tokens,
            str_get_tokens=str_get_tokens,
            num_prompts=num_prompts,
        )
    else:
        __process_wrap(scp_command_str, passwords=passwords)


def get_hostname(ssh_args):
    """Try to get the ssh host from `ssh_args`
    by executing the ssh command with `-G` option
    and parsing the output for the actual HOSTNAME.
    """
    # add -G option to make ssh print its configuration
    # option added to the beginning of the list to avoid clashes with
    #   parameters from command to be executed remotely, e.g.:
    #   `ssh host ls -l`
    ssh_args = ssh_args.copy()
    if "-G" not in ssh_args:
        ssh_args.insert(0, "-G")

    command = f"ssh {' '.join(ssh_args)}"

    try:
        logger.debug(f"Running this command to get ssh configuration: {command}")
        output = pexpect.run(command).decode("utf-8")
        pattern_match = SSH_HOSTNAME_PATTERN.search(output)
        if not pattern_match:
            logger.error(f"Could not find hostname from ssh command {command}")
            return None
        hostname = pattern_match.group("hostname")
        logger.debug(f"Found hostname by parsing command output: {hostname}")
        return hostname
    except pexpect.ExceptionPexpect as e:
        logger.debug(e)
        logger.error(f"Error trying to get real hostname from ssh command {command}")
    return None


def __parse_ssh_args(ssh_args):
    """Parses the ssh command arguments and returns a tuple with the
    list of arguments to be passed to ssh, and the remote command to be executed.
    """
    ssh_command = []
    remote_command = []
    ssh_args_copy = ssh_args.copy()
    while len(ssh_args_copy) > 0:
        if regex.match("-[46AaCfGgKkMNnqsTtVvXxYy]", ssh_args[0]):
            ssh_command.append(ssh_args_copy.pop(0))
            ssh_args = ssh_args[1:]
        if regex.match("-[BbcDEeFIiJLlmOopQRSWw]", ssh_args[0]):
            ssh_command.append(ssh_args_copy.pop(0))
            ssh_command.append(ssh_args_copy.pop(0))
            ssh_args = ssh_args[2:]
        else:
            # hostname
            ssh_command.append(ssh_args_copy.pop(0))
            break
    if len(ssh_args_copy) > 0:
        remote_command = ssh_args_copy
    logger.debug(f"ssh command: {ssh_command}")
    logger.debug(f"remote command: {remote_command}")
    return ssh_command, remote_command


def __sigwinch_passthrough(sig=None, data=None, child_process=None):
    """Pass window changes to child"""
    s = struct.pack("HHHH", 0, 0, 0, 0)
    try:
        a = struct.unpack(
            "hhhh", fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, s)
        )
        if child_process is not None and not child_process.closed:
            child_process.setwinsize(a[0], a[1])
    except Exception as e:
        logger.info(f"Error trying to set window size: {e}")


def __output_filter(data, info=None):
    """Checks output from child process for Access Token prompt
    and sends the first password in list to the process.
    Removes the password from the list until the list is empty.
    """
    if (
        info
        and info["passwords"]
        and len(info["passwords"])
        and re.match(PASSWORD_REGEX, data.decode("utf-8"))
    ):
        info["child_process"].sendline(info["passwords"][0])
        info["child_process"].readline()  # to hide the token
        del info["passwords"][0]
        return b""
    return data


def __non_interactive_ssh(command, token):
    """Runs the ssh command in non-interactive mode,
    sending the token as a password when prompted.
    """
    child = pexpect.spawn(command)
    child.expect(PASSWORD_REGEX)
    logger.debug("Got token prompt. Sending token as password")
    child.sendline(token)
    child.readline()  # to hide the token
    logger.debug("Logged in")

    child.setecho(False)
    for line in sys.stdin:
        logger.debug(f"Sending line to child: {line}")
        child.sendline(line)
    child.sendeof()

    for line in child.readlines():
        logger.debug(f"Received line from child: {line}")
        sys.stdout.write(line)
    child.close()


def __process_wrap(command, passwords=None):
    """Spawns a new process to run given command,
    and lets the user interact with it, except when prompted for
    Access Tokens, when it inputs the given passwords on
    behalf of the user, in the given order.
    """
    try:
        child_process = pexpect.spawn(command)
    except pexpect.ExceptionPexpect as e:
        raise exceptions.FatalMccliException(e)
    try:
        signal.signal(
            signal.SIGWINCH,
            partial(__sigwinch_passthrough, child_process=child_process),
        )
        __sigwinch_passthrough(child_process=child_process)
        if passwords:
            info = {"child_process": child_process, "passwords": passwords}
            child_process.interact(output_filter=partial(__output_filter, info=info))
        else:
            child_process.interact()
    except pexpect.ExceptionPexpect as e:
        if child_process and not child_process.closed:
            child_process.close()
        raise exceptions.FatalMccliException(e)
    except Exception as e:
        raise exceptions.FatalMccliException(e)


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
    if tokens is None:
        echo(command)
    elif isinstance(tokens, list):
        echo("# you'll need to input the tokens below when prompted, in this order:")
        if str_get_tokens is None:
            str_get_tokens = tokens
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
