#!/usr/bin/env python3

from functools import wraps
import click
from click_option_group import optgroup, MutuallyExclusiveOptionGroup
import liboidcagent as agent
import re
import requests
from requests.exceptions import SSLError
from requests.packages import urllib3

from .motley_cue_client import local_username
from .ssh_service import ssh_exec, ssh_interactive, scp_put, scp_get, SSH_PORT


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


def validate_insecure_flip2verify(ctx, param, value):
    """
    Disable warnings when insecure is set.
    """
    if value:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return not value


def init_token(token, oa_account, iss):
    """Retrieve an oidc token:
    * use token if set,
    * retrieve from the oidc-agent via given account if oidc-agent account is set
    * retrieve from the oidc-agent via given iss if iss is set
    * ... (use iss from service, if only one iss is supported)
    * fail
    """
    if token is not None:
        return token
    if oa_account is not None:
        try:
            print(f"Using oidc-agent account: {oa_account}")
            return agent.get_access_token(oa_account)
        except Exception:
            print(f"Failed to get access token for oidc-agent account '{oa_account}'")
    if iss is not None:
        try:
            print(f"Using issuer: {iss}")
            return agent.get_access_token_by_issuer_url(iss)
        except Exception:
            print(f"Failed to get access token for issuer url '{iss}'")
    raise Exception("No access token found")


def str_init_token(token, oa_account, iss):
    """String representation of command used to get access token:
    * full token if token is set
    * `oidc-token oa_account` if oidc-agent account is set
    * `oidc-token iss` if issuer is set
    *  ... (`oidc-token iss` is iss can be retrieved from service)
    """
    if token:
        return f"'{token}'"
    if oa_account:
        return f"`oidc-token {oa_account}`"
    elif iss:
        return f"`oidc-token {iss}`"
    raise Exception("No access token found")


def init_endpoint(mc_endpoint, ssh_host, verify=True):
    """Initialise motley_cue endpoint.

    If specified, test for valid URL and return `mc_endpoint`.
    Raise exception for invalid URL.

    If `mc_endpoint` not specified, try default value: https://HOSTNAME
    If this is not reachable, issue warning and try: http://HOSTNAME:8080
    If also not reachable, exit and ask user to specify it using --mc-endpoint
    """
    if mc_endpoint:
        try:
            response = requests.get(mc_endpoint, verify=verify)
            if response.status_code == 200:
                if not verify:
                    print(f"InsecureRequestWarning: Unverified HTTPS request is being made to host '{ssh_host}'. Adding certificate verification is strongly advised.")
                return mc_endpoint
        except SSLError:
            msg = "Error: SSL certificate verification failed\n" + \
                "Use --insecure if you wish to ignore SSL certificate verification"
            raise Exception(msg)
        except Exception:
            msg = f"No motley_cue service found at '{mc_endpoint}'\n" + \
                    "Please specify a valid motley_cue endpoint"
            raise Exception(msg)
    # try https
    mc_endpoint = f"https://{ssh_host}"
    try:
        response = requests.get(mc_endpoint, verify=verify)
        if response.status_code == 200:
            if not verify:
                print(f"InsecureRequestWarning: Unverified HTTPS request is being made to host '{ssh_host}'. Adding certificate verification is strongly advised.")
            return mc_endpoint
    except SSLError:
        msg = "Error: SSL certificate verification failed\n" + \
              "Use --insecure if you wish to ignore SSL certificate verification"
        raise Exception(msg)
    except Exception:
        pass
    # try http on port 8080
    mc_endpoint = f"http://{ssh_host}:8080"
    try:
        response = requests.get(mc_endpoint)
        if response.status_code == 200:
            # issue warning
            print(
                f"Warning: using unencrypted motley_cue endpoint: http://{ssh_host}:8080")
            return mc_endpoint
    except Exception:
        pass
    # ask user to specify endpoint
    msg = f"No motley_cue service found on host '{ssh_host}' on port 443 or 8080\n" + \
        "Please specify motley_cue endpoint via --mc-endpoint"
    raise Exception(msg)


def init_user(mc_endpoint, token, verify=True):
    """Get remote username, will be deployed if it doesn't exist.
    """
    return local_username(mc_endpoint, token, verify=verify)


def common_options(func):
    @click.option("--mc-endpoint", help="motley_cue API endpoint, default URLs: https://HOSTNAME, http://HOSTNAME:8080")
    @click.option("--insecure", "verify", is_flag=True, default=False, callback=validate_insecure_flip2verify,
                    help="ignore verifying the SSL certificate for motley_cue endpoint, NOT RECOMMENDED")
    @optgroup.group("Access Token sources",
                    help="the sources for retrieving the access token, odered by priority",
                    cls=MutuallyExclusiveOptionGroup)
    @optgroup.option("--token", show_envvar=True,
                    envvar=["ACCESS_TOKEN", "OIDC", "OS_ACCESS_TOKEN",
                            "OIDC_ACCESS_TOKEN", "WATTS_TOKEN", "WATTSON_TOKEN"],
                    help="pass token directly, env variables are checked in given order")
    @optgroup.option("--oa-account", show_envvar=True,
                    envvar=["OIDC_AGENT_ACCOUNT"],
                    help="name of configured account in oidc-agent")
    @optgroup.option("--iss", "--issuer", show_envvar=True,
                    envvar=["OIDC_ISS", "OIDC_ISSUER"],
                    help="url of issuer, oidc-agent defaults for this issuer will be used")
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


@click.group()
@common_options
def cli(**kwargs):
    """
    ssh client wrapper for oidc-based authentication
    """
    pass


@cli.command(name="ssh", short_help="open a login shell or execute a command via ssh")
@common_options
@click.option("--dry-run", is_flag=True, help="print sshpass command and exit")
@optgroup("ssh options", help="supported options to be passed to SSH")
@optgroup.option("-p", metavar="<int>", type=int, default=SSH_PORT,
                 help="port to connect to on remote host")
@click.argument("hostname")
@click.argument("command", required=False, default=None)
def ssh(dry_run, mc_endpoint, verify, token, oa_account, iss, p, hostname, command):
    try:
        at = init_token(token, oa_account, iss)
        mc_url = init_endpoint(mc_endpoint, hostname, verify)
        username = init_user(mc_url, at, verify)
        if dry_run:
            password = str_init_token(token, oa_account, iss)
            ssh_opts = ""
            if p and p != SSH_PORT:
                ssh_opts += f" -p {p}"
            sshpass_cmd = f"sshpass -P 'Access Token' -p {password} ssh {ssh_opts} {username}@{hostname}"
            if command:
                sshpass_cmd = f"{sshpass_cmd} '{command}'"
            print(sshpass_cmd)
        else:
            if command is None:
                ssh_interactive(hostname, username, at, p)
            else:
                ssh_exec(hostname, username, at, p, command)
    except Exception as e:
        print(e)


@cli.command(name="scp", short_help="secure file copy")
@common_options
@click.option("--dry-run", is_flag=True, help="print sshpass command and exit")
@optgroup("scp options", help="supported options to be passed to SCP")
@optgroup.option("-P", "port", metavar="<int>", type=int, default=SSH_PORT,
                 help="port to connect to on remote host")
@optgroup.option("-r", "recursive", is_flag=True, help="recursively copy entire directories")
@optgroup.option("-p", "preserve_times", is_flag=True,
                 help="preserve modification times and access times from the original file")
@click.argument("source", nargs=-1, required=True, callback=validate_scp_source)
@click.argument("target", callback=validate_scp_target)
def scp(dry_run, mc_endpoint, verify, token, oa_account, iss, port,
        recursive, preserve_times, source, target):
    if dry_run:
        password = str_init_token(token, oa_account, iss)
        scp_opts = ""
        if recursive:
            scp_opts += " -r"
        if preserve_times:
            scp_opts += " -p"
        if port and port != SSH_PORT:
            scp_opts += f" -P {port}"
        sshpass_cmd = f"sshpass -P 'Access Token' -p {password} scp {scp_opts}"
    try:
        dest_path = target.get("path", ".")
        dest_host = target.get("host", None)
        dest_is_remote = dest_host is not None
        if dest_is_remote:
            at = init_token(token, oa_account, iss)
            dest_endpoint = init_endpoint(mc_endpoint, dest_host, verify)
            username = init_user(dest_endpoint, at, verify)
        for src in source:
            src_path = src.get("path", ".")
            src_host = src.get("host", None)
            src_is_remote = src_host is not None
            if src_is_remote:
                at = init_token(token, oa_account, iss)
                src_endpoint = init_endpoint(mc_endpoint, src_host, verify)
                username = init_user(src_endpoint, at, verify)

            if not src_is_remote and not dest_is_remote:
                raise Exception(
                    "No remote host specified. Use regular cp instead.")
            elif src_is_remote and dest_is_remote:
                raise Exception("scp between remote hosts not yet supported.")
            elif src_is_remote:
                if dry_run:
                    sshpass_cmd += f" {username}@{src_host}:{src_path}"
                else:
                    scp_get(src_host, username, at, port,
                            src_path, dest_path,
                            recursive=recursive, preserve_times=preserve_times)
            else:
                if dry_run:
                    sshpass_cmd += f" {src_path}"
                else:
                    scp_put(dest_host, username, at, port,
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
