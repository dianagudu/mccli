#!/usr/bin/env python3

import click
from click_option_group import optgroup, MutuallyExclusiveOptionGroup
import liboidcagent as agent
import re
import requests
from requests.exceptions import SSLError
from requests.packages import urllib3

from .motley_cue_client import local_username
from .ssh_service import ssh_exec, ssh_interactive, scp_put, scp_get


def __valid_remote_path(value):
    """
    Validate a remote path of the form:
        [host:]path
    and return the two components in a dict.
    """
    value_dict = {}
    # split into host and path
    parts = value.split(":")
    if len(parts) == 1:
        value_dict["path"] = parts[0]
    elif len(parts) == 2:
        try:
            # validate host
            value_dict = re.match(
                r"^((?P<host>((\w|\w[\w\-]*\w)\.)*(\w|\w[\w\-]*\w)))?$",
                parts[0]).groupdict()
        except Exception:
            raise Exception(
                f"Invalid remote hostname: {value}")
        value_dict["path"] = "." if parts[1] == "" else parts[1]
    else:
        raise Exception(
            f"Invalid scp argument {value}: must be of form [host:]path")
    return value_dict


def validate_scp_target(ctx, param, value):
    """
    Validate scp target -- must be of following form:
        [host:]path
    No user is allowed since it will be retrieved from the motley_cue endpoint.
    """
    try:
        return __valid_remote_path(value)
    except Exception as e:
        print(e)
        ctx.exit()


def validate_scp_source(ctx, param, value):
    """
    Validate scp source -- must be of following form:
        [host:]path
    or a tuple containing multiple entries of the form:
        [host:]path
    No user is allowed since it will be retrieved from the motley_cue endpoint.
    """
    try:
        if isinstance(value, tuple):
            val_dicts = []
            for val in value:
                val_dicts += [__valid_remote_path(val)]
            return val_dicts
        else:
            return [__valid_remote_path(value)]
    except Exception as e:
        print(e)
        ctx.exit()


def __init_token(oa_account, token):
    """Retrieve an oidc token from the oidc-agent,
    if an oidc-agent account is set,
    otherwise use set token
    """
    if oa_account is not None:
        try:
            token = agent.get_access_token(oa_account)
        except Exception as e:
            raise Exception(f"Failed to get access token for oidc-agent account '{oa_account}': {e}")
    if token is None:
        raise Exception("No access token or oidc-agent account set")
    return token


def __init_endpoint(hostname, verify=True):
    """Initialise motley_cue endpoint when not specified.
    Default value: https://HOSTNAME
    If this is not reachable, issue warning and try: http://HOSTNAME:8080
    If also not reachable, exit and ask user to specify it using --mc-endpoint
    """
    # try https
    mc_endpoint = f"https://{hostname}"
    try:
        response = requests.get(mc_endpoint, verify=verify)
        if response.status_code == 200:
            if not verify:
                print(f"InsecureRequestWarning: Unverified HTTPS request is being made to host '{hostname}'. Adding certificate verification is strongly advised.")
            return mc_endpoint
    except SSLError:
        msg = "Error: SSL certificate verification failed\n" + \
              "Use --insecure if you wish to ignore SSL certificate verification"
        raise Exception(msg)
    except Exception:
        pass
    # try http on port 8080
    mc_endpoint = f"http://{hostname}:8080"
    try:
        response = requests.get(mc_endpoint)
        if response.status_code == 200:
            # issue warning
            print(
                f"Warning: using unencrypted motley_cue endpoint: http://{hostname}:8080")
            return mc_endpoint
    except Exception:
        pass
    # ask user to specify endpoint
    msg = f"No motley_cue service found on host '{hostname}' on port 443 or 8080\n" + \
        "Please specify motley_cue endpoint via --mc-endpoint"
    raise Exception(msg)


def __init_user(mc_endpoint, token, hostname, verify=True):
    """Get remote username, will be deployed if it doesn't exist.
    """
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if mc_endpoint is None:
        mc_endpoint = __init_endpoint(hostname, verify=verify)
    username = local_username(mc_endpoint, token, verify=verify)
    return username


@click.group()
def cli():
    """
    ssh client wrapper for oidc-based authentication
    """
    pass

# TODO: use existing .ssh/config
# TODO: print .ssh/config entry
# Host <config_name>
#     HostName <hostname>
#     User <local_username>
#     Port <ssh_port>


@cli.command(name="ssh", short_help="open a login shell or execute a command via ssh")
@click.option("--dry-run", is_flag=True, help="print sshpass command and exit")
@click.option("--mc-endpoint", help="motley_cue API endpoint, default URLs: https://HOSTNAME, http://HOSTNAME:8080")
@click.option("--insecure", is_flag=True, default=False,
              help="ignore verifying the SSL certificate for motley_cue endpoint, NOT RECOMMENDED")
@optgroup.group("Access Token sources",
                # help="the sources for retrieving the access token",
                cls=MutuallyExclusiveOptionGroup)
@optgroup.option("--oa-account", show_envvar=True,
                 envvar=["OIDC_AGENT_ACCOUNT"],
                 help="name of configured account in oidc-agent, has priority over --token")
@optgroup.option("--token", show_envvar=True,
                 envvar=["ACCESS_TOKEN", "OIDC", "OS_ACCESS_TOKEN",
                         "OIDC_ACCESS_TOKEN", "WATTS_TOKEN", "WATTSON_TOKEN"],
                 help="pass token directly, env variables are checked in given order")
@optgroup("ssh options", help="supported options to be passed to SSH")
@optgroup.option("-p", metavar="<int>", type=int, default=22,
                 help="port to connect to on remote host")
# @optgroup
@click.argument("hostname")
@click.argument("command", required=False, default=None)
def ssh(dry_run, mc_endpoint, insecure, oa_account, token, p, hostname, command):
    try:
        token = __init_token(oa_account, token)
        username = __init_user(
            mc_endpoint, token, hostname, verify=not insecure)
        if dry_run:
            if oa_account:
                password = f"`oidc-token {oa_account}`"
            else:
                password = token
            ssh_opts = ""
            if p and p != 22:
                ssh_opts += f" -p {p}"
            sshpass_cmd = f"sshpass -P 'Access Token' -p {password} ssh {ssh_opts} {username}@{hostname}"
            if command:
                sshpass_cmd = f"{sshpass_cmd} '{command}'"
            print(sshpass_cmd)
        else:
            if command is None:
                ssh_interactive(hostname, username, token, p)
            else:
                ssh_exec(hostname, username, token, p, command)
    except Exception as e:
        print(e)


@cli.command(name="scp", short_help="secure file copy")
@click.option("--dry-run", is_flag=True, help="print sshpass command and exit")
@click.option("--mc-endpoint", help="motley_cue API endpoint, default URLs: https://HOSTNAME, http://HOSTNAME:8080")
@click.option("--insecure", is_flag=True, default=False,
              help="ignore verifying the SSL certificate for motley_cue endpoint, NOT RECOMMENDED")
@optgroup.group("Access Token sources",
                # help="the sources for retrieving the access token",
                cls=MutuallyExclusiveOptionGroup)
@optgroup.option("--oa-account", show_envvar=True,
                 envvar=["OIDC_AGENT_ACCOUNT"],
                 help="name of configured account in oidc-agent, has priority over --token")
@optgroup.option("--token", show_envvar=True,
                 envvar=["ACCESS_TOKEN", "OIDC", "OS_ACCESS_TOKEN",
                         "OIDC_ACCESS_TOKEN", "WATTS_TOKEN", "WATTSON_TOKEN"],
                 help="pass token directly, env variables are checked in given order")
@optgroup("scp options", help="supported options to be passed to SCP")
@optgroup.option("-P", "port", metavar="<int>", type=int, default=22,
                 help="port to connect to on remote host")
@optgroup.option("-r", "recursive", is_flag=True, help="recursively copy entire directories")
@optgroup.option("-p", "preserve_times", is_flag=True,
                 help="preserve modification times and access times from the original file")
@click.argument("source", nargs=-1, callback=validate_scp_source)
@click.argument("target", callback=validate_scp_target)
def scp(dry_run, mc_endpoint, insecure, oa_account, token, port,
        recursive, preserve_times, source, target):
    if dry_run:
        if oa_account:
            password = f"`oidc-token {oa_account}`"
        else:
            password = token
        scp_opts = ""
        if recursive:
            scp_opts += " -r"
        if preserve_times:
            scp_opts += " -p"
        if port and port != 22:
            scp_opts += f" -P {port}"
        sshpass_cmd = f"sshpass -P 'Access Token' -p {password} scp {scp_opts}"
    try:
        dest_path = target.get("path", ".")
        dest_host = target.get("host", None)
        dest_is_remote = dest_host is not None
        if dest_is_remote:
            token = __init_token(oa_account, token)
            username = __init_user(
                mc_endpoint, token, dest_host, verify=not insecure)
        for src in source:
            src_path = src.get("path", ".")
            src_host = src.get("host", None)
            src_is_remote = src_host is not None
            if src_is_remote:
                token = __init_token(oa_account, token)
                username = __init_user(
                    mc_endpoint, token, src_host, verify=not insecure)

            if not src_is_remote and not dest_is_remote:
                raise Exception(
                    "No remote host specified. Use regular cp instead.")
            elif src_is_remote and dest_is_remote:
                raise Exception("scp between remote hosts not yet supported.")
            elif src_is_remote:
                if dry_run:
                    sshpass_cmd += f" {username}@{src_host}:{src_path}"
                else:
                    scp_get(src_host, username, token, port,
                            src_path, dest_path,
                            recursive=recursive, preserve_times=preserve_times)
            else:
                if dry_run:
                    sshpass_cmd += f" {src_path}"
                else:
                    scp_put(dest_host, username, token, port,
                            src_path, dest_path,
                            recursive=recursive, preserve_times=preserve_times)
        if dry_run:
            if dest_is_remote:
                sshpass_cmd += f" {username}@{dest_host}:{dest_path}"
            else:
                sshpass_cmd += f" {dest_path}"
            print(sshpass_cmd)
    except PermissionError as e:
        print(f"{e.filename.decode('utf-8')}: Permission denied")
    except IsADirectoryError as e:
        print((f"{e.filename}: not a regular file"))
    except FileNotFoundError as e:
        print(f"{e.filename}: No such file or directory")
    except Exception as e:
        print(e)


@cli.command(name="sftp", short_help="--- Not implemented ---")
def sftp():
    print("Not implemented.")


if __name__ == '__main__':
    cli()
