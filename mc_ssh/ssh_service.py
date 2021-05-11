import os
import hashlib
import base64
import socket
import getpass
import paramiko
from paramiko.py3compat import input
import scp
import sys

from . import interactive
from .logging import logger


TIMEOUT = 10
SSH_PORT = 22


def ssh_exec(hostname, username, token, port, command):
    ssh_client = __ssh_connect(hostname, username, token, port)
    if ssh_client is not None:
        stdin, stdout, stderr = ssh_client.exec_command(
            command, timeout=TIMEOUT)
        for output in [stdout, stderr]:
            for line in output:
                print(line.strip('\n'))
        ssh_client.close()


def ssh_interactive(hostname, username, token, port):
    ssh_client = __ssh_connect(hostname, username, token, port)
    if ssh_client is not None:
        channel = ssh_client.invoke_shell()
        # print("*** Here we go!\n")
        interactive.interactive_shell(channel)
        channel.close()
        ssh_client.close()


def scp_put(hostname, username, token, port, src, dest,
            recursive=False, preserve_times=False):
    ssh_client = __ssh_connect(hostname, username, token, port)
    scp_client = scp.SCPClient(
        ssh_client.get_transport(), progress4=__progress4)
    scp_client.put(src, dest,
                   recursive=recursive, preserve_times=preserve_times)
    scp_client.close()


def scp_get(hostname, username, token, port, src, dest,
            recursive=False, preserve_times=False):
    ssh_client = __ssh_connect(hostname, username, token, port)
    scp_client = scp.SCPClient(
        ssh_client.get_transport(), progress4=__progress4)
    scp_client.get(src, dest,
                   recursive=recursive, preserve_times=preserve_times)
    scp_client.close()


def __ssh_connect(hostname, username, token, port):
    try:
        ssh_client = McSSHClient()
        ssh_client.load_system_host_keys()
        ssh_client.connect(hostname, username, token,
                           port=port, timeout=TIMEOUT)
        return ssh_client
    except Exception as e:
        logger.error(e)
        logger.error("SSH login failed.")
        try:
            ssh_client.close()
        except Exception:
            pass
    return None


class McSSHClient(paramiko.SSHClient):
    def __init__(self):
        super().__init__()
        self.set_missing_host_key_policy(AskUserHostKeyPolicy())

    def connect(self, hostname, username, token, port=SSH_PORT, timeout=None):
        """
        Override connect function of SSHClient to only use keyboard-interactive
        authentication via OIDC tokens.

        Connect to an SSH server and authenticate to it.  The server's host key
        is checked against the system host keys (see L{load_system_host_keys})
        and any local host keys (L{load_host_keys}).  If the server's hostname
        is not found in either set of host keys, the missing host key policy
        is used (see L{set_missing_host_key_policy}).  The default policy is
        to ask the user.

        @param hostname: the server to connect to
        @type hostname: str
        @param username: the username to authenticate as
        @type username: str
        @param token: an OIDC token to use for authentication
        @type token: str
        @param port: the server port to connect to
        @type port: int
        @param timeout: an optional timeout (in seconds) for the TCP connect
        @type timeout: float

        @raise BadHostKeyException: if the server's host key could not be
            verified
        @raise AuthenticationException: if authentication failed
        @raise SSHException: if there was any other error connecting or
            establishing an SSH session
        @raise socket.error: if a socket error occurred while connecting
        """
        # create sock
        for (family, socktype, proto, canonname, sockaddr) in socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            if socktype == socket.SOCK_STREAM:
                af = family
                addr = sockaddr
                break
        else:
            # some OS like AIX don't indicate SOCK_STREAM support, so just guess. :(
            af, _, _, _, addr = socket.getaddrinfo(
                hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        sock = socket.socket(af, socket.SOCK_STREAM)
        if timeout is not None:
            try:
                sock.settimeout(timeout)
            except Exception:
                pass
        paramiko.util.retry_on_signal(lambda: sock.connect(addr))

        t = self._transport = paramiko.transport.Transport(sock)
        if self._log_channel is not None:
            t.set_log_channel(self._log_channel)
        t.start_client()

        # host key negotiation
        server_key = t.get_remote_server_key()
        keytype = server_key.get_name()

        if port == SSH_PORT:
            server_hostkey_name = hostname
        else:
            server_hostkey_name = "[%s]:%d" % (hostname, port)
        our_server_key = self._system_host_keys.get(
            server_hostkey_name, {}).get(keytype, None)
        if our_server_key is None:
            our_server_key = self._host_keys.get(
                server_hostkey_name, {}).get(keytype, None)
        if our_server_key is None:
            # will raise exception if the key is rejected; let that fall out
            self._policy.missing_host_key(
                self, server_hostkey_name, server_key)
            # if the callback returns, assume the key is ok
            our_server_key = server_key

        if server_key != our_server_key:
            raise paramiko.ssh_exception.BadHostKeyException(
                hostname, server_key, our_server_key)

        if username is None:
            username = getpass.getuser()

        # OIDC token authentication
        if token is None:
            raise paramiko.ssh_exception.SSHException(
                "No token was found, no other authentication methods available.")

        def handler(title, instructions, prompt_list):
            if len(prompt_list) > 1:
                raise paramiko.ssh_exception.SSHException(
                    "Expecting one field only.")
            if len(prompt_list) > 0:
                if prompt_list[0][0] == "Access Token:":
                    return [token]
            return []

        self._transport.auth_interactive(username, handler)


class AskUserHostKeyPolicy(paramiko.client.MissingHostKeyPolicy):
    def missing_host_key(self, ssh_client, hostname, remote_key):
        known_hosts_file = os.path.expanduser('~/.ssh/known_hosts')

        # Treat missing/bad hosts files as unknown host
        try:
            known_host_keys = paramiko.hostkeys.HostKeys(
                filename=known_hosts_file)
        except Exception:
            known_host_keys = paramiko.hostkeys.HostKeys()

        if known_host_keys.check(hostname, remote_key) is False:
            print("The authenticity of host '"
                  + hostname
                  + "' can't be established.")

            key_name = remote_key.get_name()
            if key_name == "ssh-ed25519":
                key_name = "ED25519"
            elif key_name == "ssh-ecdsa":
                key_name = "ECDSA"
            elif key_name == "ssh-dsa":
                key_name = "DSA"
            elif key_name == "ssh-rsa":
                key_name = "RSA"

            m = hashlib.sha256()
            m.update(remote_key.get_fingerprint())
            fingerprint = base64.b64encode(m.digest()).decode("utf-8")

            print(key_name + " key fingerprint is SHA256:" + fingerprint)

            answer = None
            while answer not in ("yes", "y", "no", "n"):
                answer = input(
                    "Are you sure you want to continue connecting (yes/no)? ")

            if answer in ('no', 'n'):
                raise Exception("Host key verification failed.")

            known_host_keys.add(hostname,
                                remote_key.get_name(),
                                remote_key)
            known_host_keys.save(known_hosts_file)
            ssh_client.load_host_keys(known_hosts_file)
        return


def __progress(filename, size, sent):
    """progress callback that prints the current percentage completed
    for the scp-ed file
    """
    sys.stdout.write("%s's progress: %.2f%%   \r" %
                     (filename, float(sent)/float(size)*100))


def __progress4(filename, size, sent, peername):
    """progress callback that prints the current percentage completed for
    the scp-ed file, and also adds a 4th parameter to track IP and port.

    useful with multiple threads to track source
    """
    sys.stdout.write("(%s:%s) %s's progress: %.2f%%   \r" % (
        peername[0], peername[1], filename, float(sent)/float(size)*100))
