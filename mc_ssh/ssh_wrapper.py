import struct
import fcntl
import termios
import signal
import sys
import pexpect
from pexpect import pxssh
from functools import partial

from .logging import logger


TIMEOUT = 10
SSH_PORT = 22
ORIGINAL_PROMPT = '[#$] '
NEW_PROMPT = "$PS1"
TERMINAL_TYPE = 'xterm-256color'
PASSWORD_REGEX = r"(?:[^\n]*)(?:Access Token:)$"
PASSPHRASE_REGEX = r"(?:passphrase for key)"
TERMINAL_TYPE_PROMPT = r"(?i)terminal type\?"
PERMISSION_DENIED = r"(?i)permission denied"
CONNECTION_CLOSED = r"(?i)connection closed by remote host"
HOSTKEY_NEW_CONFIRM = r"(?i)are you sure you want to continue connecting"
HOSTKEY_VERIFY_FAILED = r"(?i)host key verification failed"
HOSTKEY_VERIFY_PROMPT = r"(?i)please type 'yes', 'no' or the fingerprint"


def ssh_exec(hostname, username, token, port, command):
    try:
        ssh_client = __ssh_connect(
            hostname, username, token, port,
            sync_original_prompt=False)
        ssh_client.sendline(command)
        ssh_client.readline()
        ssh_client.prompt(TIMEOUT)
        ssh_client.write_to_stdout(ssh_client.before)
        ssh_client.logout()
    except pxssh.ExceptionPxssh as e:
        logger.error(e)


def ssh_interactive(hostname, username, token, port):
    try:
        ssh_client = __ssh_connect(
            hostname, username, token, port,
            auto_prompt_reset=False, prompt=NEW_PROMPT)
        ssh_client.interact()
    except pxssh.ExceptionPxssh as e:
        ssh_client.logout()
        logger.error(e)


def scp_put(hostname, username, token, port, src, dest,
            recursive=False, preserve_times=False):
    try:
        scp_opts = __scp_opts_str(port, recursive, preserve_times)
        command = f"scp {scp_opts} {src} {username}@{hostname}:{dest}"
        __scp(command, password=token)
    except Exception as e:
        logger.error(e)


def scp_get(hostname, username, token, port, src, dest,
            recursive=False, preserve_times=False):
    try:
        scp_opts = __scp_opts_str(port, recursive, preserve_times)
        command = f"scp {scp_opts} {username}@{hostname}:{src} {dest}"
        __scp(command, password=token)
    except Exception as e:
        logger.error(e)


def __sigwinch_passthrough(sig=None, data=None, expect_obj=None):
    """ Pass window changes to child
    """
    s = struct.pack("HHHH", 0, 0, 0, 0)
    a = struct.unpack('hhhh', fcntl.ioctl(sys.stdout.fileno(),
                                          termios.TIOCGWINSZ, s))
    if not expect_obj.closed:
        expect_obj.setwinsize(a[0], a[1])


def __scp_opts_str(port, recursive, preserve_times):
    scp_opts = f"-P {port}"
    if recursive:
        scp_opts = f"{scp_opts} -r"
    if preserve_times:
        scp_opts = f"{scp_opts} -p"
    return scp_opts


def __ssh_connect(hostname, username, token, port,
                  auto_prompt_reset=True,
                  sync_original_prompt=True,
                  prompt="[\\$\\#] "):
    try:
        ssh_client = pxssh.pxssh()
        if not auto_prompt_reset:
            ssh_client.PROMPT = prompt
        ssh_client.login(hostname, username=username,
                         password=token, port=port,
                         password_regex=PASSWORD_REGEX,
                         auto_prompt_reset=auto_prompt_reset,
                         sync_original_prompt=sync_original_prompt,
                         terminal_type=TERMINAL_TYPE,
                         login_timeout=TIMEOUT)

        signal.signal(signal.SIGWINCH, partial(
            __sigwinch_passthrough, expect_obj=ssh_client))
        __sigwinch_passthrough(expect_obj=ssh_client)

        return ssh_client
    except pxssh.ExceptionPxssh as e:
        logger.error(e)
        logger.error("pxssh failed on login.")


def __scp(command, password):
    try:
        regex_array = [
            HOSTKEY_NEW_CONFIRM, HOSTKEY_VERIFY_PROMPT, HOSTKEY_VERIFY_FAILED,
            PASSWORD_REGEX, TERMINAL_TYPE_PROMPT,
            PERMISSION_DENIED, CONNECTION_CLOSED, pexpect.EOF
        ]

        scp_process = pexpect.spawn(command)
        signal.signal(signal.SIGWINCH, partial(
            __sigwinch_passthrough, expect_obj=scp_process))
        __sigwinch_passthrough(expect_obj=scp_process)

        i = scp_process.expect(regex_array, timeout=TIMEOUT)

        # First phase
        if i == 0:
            # This is what you get if SSH does not have the remote host's
            # public key stored in the 'known_hosts' cache.
            # Ask the user what to do.
            print(scp_process.before.decode('utf-8', 'replace'), end='')
            answer = input("Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
            scp_process.sendline(answer)
            while True:
                i = scp_process.expect(regex_array)
                if i == 1:
                    answer = input("Please type 'yes', 'no' or the fingerprint: ")
                    scp_process.sendline(answer)
                elif i == 2:
                    scp_process.close()
                    raise pexpect.ExceptionPexpect("Host key verification failed.")
                else:
                    break
        if i == 3:  # password or passphrase
            scp_process.sendline(password)
            scp_process.readline()
            i = scp_process.expect(regex_array)
        if i == 4:
            scp_process.sendline(TERMINAL_TYPE)
            i = scp_process.expect(regex_array)

        # Second phase
        if i == 0:
            # This is weird. This should not happen twice in a row.
            scp_process.close()
            raise pexpect.ExceptionPexpect(
                'Weird error. Got "are you sure" prompt twice.')
        elif i == 1:
            # This is weird. This should not happen twice in a row.
            scp_process.close()
            raise pexpect.ExceptionPexpect(
                'Weird error. Got "please type" prompt twice.')
        elif i == 2:
            # This is weird. This should not happen twice in a row.
            scp_process.close()
            raise pexpect.ExceptionPexpect(
                'Weird error. Hostkey verification failed again.')
        elif i == 3:  # password prompt again
            scp_process.close()
            raise pexpect.ExceptionPexpect('password refused')
        elif i == 4:  # terminal type again? WTF?
            scp_process.close()
            raise pexpect.ExceptionPexpect(
                'Weird error. Got "terminal type" prompt twice.')
        elif i == 5:  # permission denied -- password was bad.
            scp_process.close()
            raise pexpect.ExceptionPexpect('permission denied')
        elif i == 6:  # Connection closed by remote host
            scp_process.close()
            raise pexpect.ExceptionPexpect('connection closed')
        elif i == 7:  # EOF
            # this is good
            scp_process.write_to_stdout(scp_process.before)
        else:  # Unexpected
            scp_process.close()
            raise pexpect.ExceptionPexpect('unexpected login response')
    except pexpect.ExceptionPexpect as e:
        logger.error("scp failed on pexpect")
        logger.error(e)
