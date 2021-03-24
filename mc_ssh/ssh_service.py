import os
import hashlib
import base64
import paramiko
from paramiko.py3compat import input
import scp
import sys

from . import interactive


TIMEOUT = 10


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
        print("*** Here we go!\n")
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
        ssh_client = paramiko.SSHClient()
        ssh_client.load_system_host_keys()
        try:
            ssh_client.connect(hostname, port=port,
                               username=username, password=token,
                               timeout=TIMEOUT)
        except paramiko.ssh_exception.SSHException as e:
            if "not found in known_hosts" in e.__str__():
                __host_key_verification(ssh_client, hostname)
                ssh_client.connect(hostname, username=username, password=token,
                                   timeout=TIMEOUT)
            else:
                raise e
        return ssh_client
    except Exception as e:
        print(e)
        print("SSH login failed.")
        try:
            ssh_client.close()
        except Exception:
            pass
    return None


def __host_key_verification(ssh_client, hostname):
    t = ssh_client.get_transport()
    known_hosts_file = os.path.expanduser('~/.ssh/known_hosts')
    remote_key = t.get_remote_server_key()

    # Treat missing/bad hosts files as unknown host
    try:
        host_keys = ssh_client.get_host_keys()
    except Exception:
        host_keys = paramiko.hostkeys.HostKeys()

    if host_keys.check(hostname, remote_key) is False:
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

        host_keys.add(hostname,
                      remote_key.get_name(),
                      remote_key)
        host_keys.save(known_hosts_file)


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
