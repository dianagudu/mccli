#!/usr/bin/env python3

from functools import wraps
import click
from click_option_group import optgroup, MutuallyExclusiveOptionGroup
import click_logging
import json

from .ssh_wrapper import ssh_exec, ssh_interactive, scp_put, scp_get, SSH_PORT
from .utils import validate_insecure_flip2verify, validate_scp_source, validate_scp_target
from .utils import init_endpoint, init_token, init_user
from .motley_cue_client import str_info_all
from .logging import logger


def common_options(func):
    @click.option("--mc-endpoint", metavar="URL",
                  help="motley_cue API endpoint, default URLs: https://HOSTNAME, http://HOSTNAME:8080")
    @click.option("--insecure", "verify", is_flag=True, default=False,
                  callback=validate_insecure_flip2verify,
                  help="ignore verifying the SSL certificate for motley_cue endpoint, NOT RECOMMENDED")
    @optgroup.group("Access Token sources",
                    help="the sources for retrieving the access token, odered by priority",
                    cls=MutuallyExclusiveOptionGroup)
    @optgroup.option("--token", metavar="TOKEN",
                     envvar=["ACCESS_TOKEN", "OIDC",
                             "OS_ACCESS_TOKEN", "OIDC_ACCESS_TOKEN",
                             "WATTS_TOKEN", "WATTSON_TOKEN"],
                     show_envvar=True,
                     help="pass token directly, env variables are checked in given order")
    @optgroup.option("--oa-account", metavar="SHORTNAME",
                     envvar=["OIDC_AGENT_ACCOUNT"], show_envvar=True,
                     help="name of configured account in oidc-agent")
    @optgroup.option("--iss", "--issuer", metavar="URL",
                     envvar=["OIDC_ISS", "OIDC_ISSUER"], show_envvar=True,
                     help="url of token issuer; configured account in oidc-agent for this issuer will be used")
    @click_logging.simple_verbosity_option(logger, default="ERROR", metavar="LEVEL")
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


@click.group()
@common_options
def cli(**kwargs):
    """
    ssh client wrapper with OIDC-based authentication
    """
    pass


@cli.command(name="info", short_help="get info about service")
@common_options
@click.argument("hostname")
def info(mc_endpoint, verify, token, oa_account, iss, hostname):
    """Get information about SSH service running on HOSTNAME:
    supported OIDC providers, service description and help.

    If a token is provided, also show authorisation information
    if issuer of token is supported on the service.
    """
    mc_url = init_endpoint(mc_endpoint, hostname, verify)
    try:
        at, _ = init_token(token, oa_account, iss, mc_url, verify)
    except Exception:
        at = None
    str_info = str_info_all(mc_url, at, verify)
    click.echo(json.dumps(str_info, indent=2))


@cli.command(name="ssh", short_help="remote login client")
@common_options
@optgroup("SSH options", help="supported options to be passed to SSH")
@optgroup.option("-p", metavar="<int>", type=int, default=SSH_PORT,
                 help="port to connect to on remote host")
@click.option("--dry-run", is_flag=True, help="print sshpass command and exit")
@click.argument("hostname")
@click.argument("command", required=False, default=None)
def ssh(mc_endpoint, verify, token, oa_account, iss,
        dry_run, p, hostname, command):
    """Connects and logs into HOSTNAME via SSH by using the provided OIDC
    Access Token to authenticate.

    If a COMMAND is specified, it is executed on the remote host
    instead of a login shell.

    When no Access Token source is specified, the service on the remote host
    is queried for supported issuers; if only one issuer is supported,
    this is used to retrieve the token from the oidc-agent.
    """
    try:
        mc_url = init_endpoint(mc_endpoint, hostname, verify)
        at, str_get_at = init_token(token, oa_account, iss, mc_url, verify)
        username = init_user(mc_url, at, verify)
        if dry_run:
            ssh_opts = ""
            if p and p != SSH_PORT:
                ssh_opts += f" -p {p}"
            sshpass_cmd = f"sshpass -P 'Access Token' -p {str_get_at} ssh{ssh_opts} {username}@{hostname}"
            if command:
                sshpass_cmd = f"{sshpass_cmd} '{command}'"
            click.echo(sshpass_cmd)
        else:
            if command is None:
                ssh_interactive(hostname, username, at, p)
            else:
                ssh_exec(hostname, username, at, p, command)
    except Exception as e:
        logger.error(e)


@cli.command(name="scp", short_help="secure file copy")
@common_options
@optgroup("SCP options", help="supported options to be passed to SCP")
@optgroup.option("-P", "port", metavar="<int>", type=int, default=SSH_PORT,
                 help="port to connect to on remote host")
@optgroup.option("-r", "recursive", is_flag=True,
                 help="recursively copy entire directories")
@optgroup.option("-p", "preserve_times", is_flag=True,
                 help="preserve modification times and access times from the original file")
@click.option("--dry-run", is_flag=True, help="print sshpass command and exit")
@click.argument("source", nargs=-1, required=True, callback=validate_scp_source)
@click.argument("target", callback=validate_scp_target)
def scp(mc_endpoint, verify, token, oa_account, iss,
        dry_run, port, recursive, preserve_times,
        source, target):
    """
    Copies files between hosts on a network over SSH using the provided OIDC
    Access Token to authenticate.

    The SOURCE and TARGET may be specified as a local pathname or a remote
    host in optional path in the form host[:path].

    When no Access Token source is specified, the remote host is queried for
    supported issuers; if only one issuer is supported, this is used to
    retrieve the token from the oidc-agent.
    """
    try:
        # start with target destination bc there can be multiple sources
        dest_path = target.get("path", ".")
        dest_host = target.get("host", None)
        dest_is_remote = dest_host is not None
        if dest_is_remote:
            dest_endpoint = init_endpoint(mc_endpoint, dest_host, verify)
            at, str_get_at = init_token(
                token, oa_account, iss, dest_endpoint, verify)
            username = init_user(dest_endpoint, at, verify)
        # stringify destination part of scp command
        if dry_run:
            dest_cmd = f" {username}@{dest_host}:{dest_path}" \
                if dest_is_remote else f" {dest_path}"
            src_cmd = ""
        # go through all sources
        for src in source:
            src_path = src.get("path", ".")
            src_host = src.get("host", None)
            src_is_remote = src_host is not None

            # deal with unsupported use cases
            if not src_is_remote and not dest_is_remote:
                raise Exception(
                    "No remote host specified. Use regular cp instead.")
            elif src_is_remote and dest_is_remote:
                raise Exception("scp between remote hosts not yet supported.")

            if src_is_remote:
                src_endpoint = init_endpoint(mc_endpoint, src_host, verify)
                at, str_get_at = init_token(
                    token, oa_account, iss, src_endpoint, verify)
                username = init_user(src_endpoint, at, verify)

            # stringify source part of scp command if dry_run, otherwise do scp
            if dry_run:
                src_cmd += f" {username}@{src_host}:{src_path}" \
                    if src_is_remote else f" {src_path}"
            else:
                if src_is_remote:
                    scp_get(src_host, username, at, port,
                            src_path, dest_path,
                            recursive=recursive, preserve_times=preserve_times)
                else:
                    scp_put(dest_host, username, at, port,
                            src_path, dest_path,
                            recursive=recursive, preserve_times=preserve_times)

        # assemble sshpass command from collected stringified components
        if dry_run:
            # stringify scp options
            scp_opts = ""
            if recursive:
                scp_opts += " -r"
            if preserve_times:
                scp_opts += " -p"
            if port and port != SSH_PORT:
                scp_opts += f" -P {port}"
            sshpass_cmd = f"sshpass -P 'Access Token' -p {str_get_at} "\
                f"scp{scp_opts}{src_cmd}{dest_cmd}"
            click.echo(sshpass_cmd)
    except PermissionError as e:
        logger.error(f"{e.filename.decode('utf-8')}: Permission denied")
    except IsADirectoryError as e:
        logger.error((f"{e.filename}: not a regular file"))
    except FileNotFoundError as e:
        logger.error(f"{e.filename}: No such file or directory")
    except Exception as e:
        logger.error(e)


@cli.command(name="sftp", short_help="secure file transfer")
def sftp():
    """
    --- Not implemented ---
    """
    logger.error("Not implemented.")


if __name__ == '__main__':
    cli()
