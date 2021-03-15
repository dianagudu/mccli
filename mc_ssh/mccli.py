#!/usr/bin/env python3

import click
from click_option_group import optgroup, MutuallyExclusiveOptionGroup
import liboidcagent as agent

from .motley_cue_client import local_username
from .ssh_service import ssh_exec, ssh_interactive


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
@click.option("--mc-endpoint", help="motley_cue API endpoint, default: https://HOSTNAME")
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
@optgroup("SSH options", help="supported options to be passed to SSH")
@optgroup.option("-p", metavar="<int>", type=int, default=22,
                 help="port to connect to on remote host")
# @optgroup
@click.argument("hostname")
@click.argument("command", required=False, default=None)
def ssh(mc_endpoint, oa_account, token, p, hostname, command):
    if mc_endpoint is None:
        mc_endpoint = f"https://{hostname}"

    try:
        if oa_account is not None:
            token = agent.get_access_token(oa_account)
        if token is None:
            raise Exception("No access token found.")
        username = local_username(mc_endpoint, token)
        if command is None:
            ssh_interactive(hostname, username, token, p)
        else:
            ssh_exec(hostname, username, token, p, command)
    except Exception as e:
        print(e)


@cli.command(name="scp", short_help="secure file copy")
@click.option("--mc-endpoint", help="motley_cue API endpoint, default: https://HOSTNAME")
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
@optgroup("SCP options", help="supported options to be passed to SCP")
@optgroup.option("-P", "port", metavar="<int>", type=int, default=22,
                 help="port to connect to on remote host")
@optgroup.option("-r", "recursive", is_flag=True, help="recursively copy entire directories")
@optgroup.option("-p", "preserve_times", is_flag=True,
                 help="preserve modification times and access times from the original file")
# @optgroup
@click.argument("source", nargs=-1)
@click.argument("target")
def scp(**args):
    print("Not implemented.")


@cli.command(name="sftp", short_help="")
def sftp():
    print("Not implemented.")


if __name__ == '__main__':
    cli()
