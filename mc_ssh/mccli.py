#!/usr/bin/env python3

import click

from .ssh_wrapper import ssh_wrap, scp_wrap
from .init_utils import valid_mc_url, init_endpoint, init_token, init_user, augmented_scp_command
from .scp_utils import parse_scp_args
from .click_utils import SshUsageCommand, ScpUsageCommand, common_options, tuple_to_list
from .motley_cue_client import str_info_all
from .logging import logger


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
    try:
        if mc_endpoint:
            mc_url = valid_mc_url(mc_endpoint, verify)
        else:
            mc_url = init_endpoint([hostname], verify)
        try:
            at, _ = init_token(token, oa_account, iss, mc_url, verify)
        except Exception as e:
            at = None
            logger.info(e)
            logger.warning("No access token found, will not show authorisation information")
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
@click.argument("ssh_command", nargs=-1, required=True, type=click.UNPROCESSED, callback=tuple_to_list)
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
@click.argument("scp_command", nargs=-1, required=True, type=click.UNPROCESSED, callback=tuple_to_list)
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
            scp_wrap(scp_command, username=username, tokens=at,
                     str_get_tokens=str_get_at, dry_run=dry_run)
        else:
            scp_args = parse_scp_args(scp_command)
            if scp_args.no_mc():
                logger.warning("No motley_cue handling will be done. "
                               "Either all specified paths are local, "
                               "or users are specified for remotes.")
                scp_wrap(scp_command, dry_run=dry_run)
            elif scp_args.single_mc():
                logger.info("Only one host with motley_cue detected. Easy.")
                mc_url = init_endpoint([scp_args.mc_host], verify)
                at, str_get_at = init_token(token, oa_account, iss, mc_url, verify)
                username = init_user(mc_url, at, verify)
                scp_wrap(scp_command, username=username, tokens=at,
                         str_get_tokens=str_get_at,
                         num_prompts=scp_args.num_prompts, dry_run=dry_run)
            elif scp_args.multiple_mc():
                logger.info("Multiple hosts with motley_cue detected, "
                            "your commandline will be augmented with usernames. ")
                new_scp_command, tokens, str_get_tokens = \
                    augmented_scp_command(scp_args, token, oa_account, iss, verify)
                scp_wrap(new_scp_command, tokens=tokens,
                         str_get_tokens=str_get_tokens, dry_run=dry_run)
            else:
                raise Exception("Something went wrong when trying to find out "
                                "which paths are remote and which are local.")
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
