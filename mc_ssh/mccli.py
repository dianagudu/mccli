#!/usr/bin/env python3

import click

from .ssh_wrapper import ssh_wrap, scp_wrap, scp_nowrap, scp_wrap_nouser_multipass
from .init_utils import valid_mc_url, init_endpoint, init_token, init_user, augmented_scp_command
from .scp_utils import parse_scp_args
from .click_utils import SshUsageCommand, ScpUsageCommand, common_options
from .motley_cue_client import str_info_all
from .logging import logger


@click.group()
# @common_options
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
    try:
        if mc_endpoint:
            mc_url = valid_mc_url(mc_endpoint, verify)
        else:
            mc_url = init_endpoint([hostname], verify)
        try:
            at, _ = init_token(token, oa_account, iss, mc_url, verify)
        except Exception:
            at = None
        click.echo(str_info_all(mc_url, at, verify))
    except Exception as e:
        logger.error(e)


@cli.command(name="ssh", short_help="remote login client",
             cls=SshUsageCommand, context_settings={
                 "ignore_unknown_options": True,
                 "allow_extra_args": True
             })
@common_options
@click.option("--dry-run", is_flag=True, help="print sshpass command and exit")
@click.argument("ssh_command", nargs=-1, required=True, type=click.UNPROCESSED)
def ssh(mc_endpoint, verify, token, oa_account, iss, dry_run, ssh_command):
    """Connects and logs into HOSTNAME via SSH by using the provided OIDC
    Access Token to authenticate.

    If a COMMAND is specified, it is executed on the remote host instead
    of a login shell.

    The remote user must not be specified, since it will be obtained from
    the motley_cue service. Any specified username will be ignored.

    When no Access Token source is specified, the service on the remote host
    is queried for supported issuers; if only one issuer is supported,
    this is used to retrieve the token from the oidc-agent.
    """
    try:
        if mc_endpoint:
            mc_url = valid_mc_url(mc_endpoint, verify)
        else:
            mc_url = init_endpoint(ssh_command, verify)
        at, str_get_at = init_token(token, oa_account, iss, mc_url, verify)
        username = init_user(mc_url, at, verify)
        ssh_wrap(ssh_command, username, at,
                 str_get_token=str_get_at, dry_run=dry_run)
    except Exception as e:
        logger.error(e)


@cli.command(name="scp", short_help="secure file copy",
             cls=ScpUsageCommand, context_settings={
                 "ignore_unknown_options": True,
                 "allow_extra_args": True
             })
@common_options
@click.option("--dry-run", is_flag=True, help="print sshpass command and exit")
@click.argument("scp_command", nargs=-1, required=True, type=click.UNPROCESSED)
def scp(mc_endpoint, verify, token, oa_account, iss, dry_run, scp_command):
    """Copies files between hosts on a network over SSH using the provided
    OIDC Access Token to authenticate.

    The SOURCE and TARGET may be specified as a local pathname, a remote host
    with optional path in the form [user@]host:[path], or a URI in the form
    scp://[user@]host[:port][/path]

    The remote user should not be specified, since it will be obtained from
    the motley_cue service. If you specify a username for a host, then it
    will be used; it will be assumed that this specific host does not use
    motley_cue, and by extension, token authentication; you will have to handle
    authentication for this host on your own.

    When no Access Token source is specified, the remote host is queried for
    supported issuers; if only one issuer is supported, this is used to
    retrieve the token from the oidc-agent.
    """
    try:
        if mc_endpoint:
            mc_url = valid_mc_url(mc_endpoint, verify)
            at, str_get_at = init_token(token, oa_account, iss, mc_url, verify)
            username = init_user(mc_url, at, verify)
            scp_wrap(scp_command, username, at,
                     str_get_token=str_get_at, dry_run=dry_run)
        else:
            scp_args = parse_scp_args(scp_command)
            if scp_args.no_mc():
                logger.warning("No motley_cue handling will be done. "
                               "Either all specified paths are local, "
                               "or users are specified for remotes.")
                scp_nowrap(scp_command, dry_run)
            elif scp_args.single_mc():
                logger.info("Only one host with motley_cue detected. Easy.")
                mc_url = init_endpoint([scp_args.mc_host], verify)
                at, str_get_at = init_token(token, oa_account, iss, mc_url, verify)
                username = init_user(mc_url, at, verify)
                scp_wrap(scp_command, username, at, num_prompts=scp_args.num_prompts,
                         str_get_token=str_get_at, dry_run=dry_run)
            elif scp_args.multiple_mc():
                logger.info("Multiple hosts with motley_cue detected, "
                            "your commandline will be augmented with usernames. ")
                new_scp_command, tokens, str_get_tokens = \
                    augmented_scp_command(scp_args, token, oa_account, iss, verify)
                scp_wrap_nouser_multipass(new_scp_command, tokens, str_get_tokens, dry_run)
            else:
                raise Exception("Something went wrong when trying to find out "
                                "which paths are remote and which are local.")
    except Exception as e:
        logger.error(e)


# @cli.command(name="scp", short_help="secure file copy")
# @common_options
# @optgroup("SCP options", help="supported options to be passed to SCP")
# @optgroup.option("-P", "port", metavar="<int>", type=int, default=SSH_PORT,
#                  help="port to connect to on remote host")
# @optgroup.option("-r", "recursive", is_flag=True,
#                  help="recursively copy entire directories")
# @optgroup.option("-p", "preserve_times", is_flag=True,
#                  help="preserve modification times and access times from the original file")
# @click.option("--dry-run", is_flag=True, help="print sshpass command and exit")
# @click.argument("source", nargs=-1, required=True, callback=validate_scp_source)
# @click.argument("target", callback=validate_scp_target)
# def scp(mc_endpoint, verify, token, oa_account, iss,
#         dry_run, port, recursive, preserve_times,
#         source, target):
#     """
#     Copies files between hosts on a network over SSH using the provided OIDC
#     Access Token to authenticate.

#     The SOURCE and TARGET may be specified as a local pathname or a remote
#     host in optional path in the form host[:path].

#     When no Access Token source is specified, the remote host is queried for
#     supported issuers; if only one issuer is supported, this is used to
#     retrieve the token from the oidc-agent.
#     """
#     try:
#         # start with target destination bc there can be multiple sources
#         dest_path = target.get("path", ".")
#         dest_host = target.get("host", None)
#         dest_is_remote = dest_host is not None
#         if dest_is_remote:
#             dest_endpoint = init_endpoint(mc_endpoint, dest_host, verify)
#             at, str_get_at = init_token(
#                 token, oa_account, iss, dest_endpoint, verify)
#             username = init_user(dest_endpoint, at, verify)
#         # stringify destination part of scp command
#         if dry_run:
#             dest_cmd = f" {username}@{dest_host}:{dest_path}" \
#                 if dest_is_remote else f" {dest_path}"
#             src_cmd = ""
#         # go through all sources
#         for src in source:
#             src_path = src.get("path", ".")
#             src_host = src.get("host", None)
#             src_is_remote = src_host is not None

#             # deal with unsupported use cases
#             if not src_is_remote and not dest_is_remote:
#                 raise Exception(
#                     "No remote host specified. Use regular cp instead.")
#             elif src_is_remote and dest_is_remote:
#                 raise Exception("scp between remote hosts not yet supported.")

#             if src_is_remote:
#                 src_endpoint = init_endpoint(mc_endpoint, src_host, verify)
#                 at, str_get_at = init_token(
#                     token, oa_account, iss, src_endpoint, verify)
#                 username = init_user(src_endpoint, at, verify)

#             # stringify source part of scp command if dry_run, otherwise do scp
#             if dry_run:
#                 src_cmd += f" {username}@{src_host}:{src_path}" \
#                     if src_is_remote else f" {src_path}"
#             else:
#                 if src_is_remote:
#                     scp_get(src_host, username, at, port,
#                             src_path, dest_path,
#                             recursive=recursive, preserve_times=preserve_times)
#                 else:
#                     scp_put(dest_host, username, at, port,
#                             src_path, dest_path,
#                             recursive=recursive, preserve_times=preserve_times)

#         # assemble sshpass command from collected stringified components
#         if dry_run:
#             # stringify scp options
#             scp_opts = ""
#             if recursive:
#                 scp_opts += " -r"
#             if preserve_times:
#                 scp_opts += " -p"
#             if port and port != SSH_PORT:
#                 scp_opts += f" -P {port}"
#             sshpass_cmd = f"sshpass -P 'Access Token' -p {str_get_at} "\
#                 f"scp{scp_opts}{src_cmd}{dest_cmd}"
#             click.echo(sshpass_cmd)
#     except PermissionError as e:
#         logger.error(f"{e.filename.decode('utf-8')}: Permission denied")
#     except IsADirectoryError as e:
#         logger.error((f"{e.filename}: not a regular file"))
#     except FileNotFoundError as e:
#         logger.error(f"{e.filename}: No such file or directory")
#     except Exception as e:
#         logger.error(e)


@cli.command(name="sftp", short_help="secure file transfer")
def sftp():
    """
    --- Not implemented ---
    """
    logger.error("Not implemented.")


if __name__ == '__main__':
    cli()
