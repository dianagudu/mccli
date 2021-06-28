import click
import click_logging
from click_option_group import optgroup, MutuallyExclusiveOptionGroup
from functools import wraps

from .logging import logger
from .version import __version__


class CustomUsageCommand(click.Command):
    def format_usage(self, ctx, formatter):
        formatter.write(self.usage_text)
        formatter.write_paragraph()


class SshUsageCommand(CustomUsageCommand):
    @property
    def usage_text(self):
        return "mccli [OPTIONS] ssh [SSH OPTIONS] HOSTNAME [COMMAND]"


class ScpUsageCommand(CustomUsageCommand):
    @property
    def usage_text(self):
        return "mccli [OPTIONS] scp [SCP_OPTIONS] SOURCE ... TARGET"


def validate_insecure_flip2verify(ctx, param, value):
    """
    Disable warnings when insecure is set.
    """
    if value:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return not value


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
    @click_logging.simple_verbosity_option(logger, "--log-level", default="ERROR", metavar="LEVEL")
    @click.version_option(__version__)
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


def tuple_to_list(ctx, param, value):
    try:
        if not value:
            logger.error("Empty command args list. Shouldn't have happened...")
            ctx.abort()
        elif not isinstance(value, tuple):
            logger.error("Weird, command args is not a tuple...")
        else:
            return list(value)
    except Exception as e:
        logger.debug(e)
        logger.error("Failed to convert command args tuple to list")
        ctx.abort()