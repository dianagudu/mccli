import click
import click_logging
from click_option_group import optgroup, MutuallyExclusiveOptionGroup
from functools import wraps
import urllib3
import logging

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


def validate_verify(ctx, param, value):
    """
    First, take over value from parent, if set.
    Disable warnings when insecure is set.
    Might seem weird: the flag is called --insecure, but the
    meaning of the value is verify:
    - True by default, verify if HTTPS requests are secure, verify certificates
    - False means do not verify, disable warnings.
    When the flag is set, verify will be False.
    """
    try:
        value = ctx.meta[param.name]
    except Exception:
        # set the verify in the context meta dict to be used by subcommands
        # only if it was set through the commandline
        if ctx.get_parameter_source(param.name) == click.core.ParameterSource.COMMANDLINE:
            ctx.meta[param.name] = value
    if not value:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return value


def validate_pass_from_parent(ctx, param, value):
    """If a param's value is set in the parent command,
    (via ctx.meta[param]) then take it over to the subcommand
    Otherwise, use given value and set it in the context
    to be propagated to subcommands
    """
    try:
        parent_value = ctx.meta[param.name]
        if parent_value:
            return parent_value
    except Exception:
        pass
    # set meta value to be used by subcommands only if it was set using the cmdline
    # envvar values should only be processed at subcommand level and not passed from parent
    # this way, the cmdline values take precedence over env vars or default values
    if value and ctx.get_parameter_source(param.name) == click.core.ParameterSource.COMMANDLINE:
        ctx.meta[param.name] = value
    return value


def my_logging_simple_verbosity_option(logger=None, *names, **kwargs):
    '''My version of @click_logging.simple_verbosity_option
    that takes over the value from the parent command.

    A decorator that adds a `--verbosity, -v` option to the decorated
    command.

    Name can be configured through ``*names``. Keyword arguments are passed to
    the underlying ``click.option`` decorator.
    '''
    if not names:
        names = ['--verbosity', '-v']

    kwargs.setdefault('default', 'INFO')
    kwargs.setdefault('metavar', 'LVL')
    kwargs.setdefault('expose_value', False)
    kwargs.setdefault('help', f'Either CRITICAL, ERROR, WARNING, INFO or DEBUG. Default value: {kwargs["default"]}.')
    kwargs.setdefault('is_eager', True)

    logger = click_logging.core._normalize_logger(logger)

    def decorator(f):
        def _set_level(ctx, param, value):
            value = value.upper()
            # check if log_level was set in the parent command and use it as default
            try:
                value = ctx.meta['log_level']
            except Exception as e:
                # set the log_level in the context meta dict to be used by subcommands
                # only if it was set through the commandline
                if ctx.get_parameter_source(param.name) == click.core.ParameterSource.COMMANDLINE:
                    ctx.meta['log_level'] = value

            x = getattr(logging, value, None)
            if x is None:
                raise click.BadParameter(
                    'Must be CRITICAL, ERROR, WARNING, INFO or DEBUG, not {}'.format(value)
                )
            logger.setLevel(x)

        return click.option(*names, callback=_set_level, **kwargs)(f)
    return decorator


def common_options(func):
    @click.option("--mc-endpoint", metavar="URL", callback=validate_pass_from_parent,
                  help="motley_cue API endpoint. Default URLs are checked in given order: https://HOSTNAME, https://HOSTNAME:8443, http://HOSTNAME:8080")
    @click.option("--insecure", "verify", is_flag=True, default=True, callback=validate_verify,
                  help="Ignore verifying the SSL certificate for motley_cue endpoint, NOT RECOMMENDED.")
    @optgroup.group("Access Token sources",
                    help="The sources for retrieving an Access Token, in the order they are checked. If no source is specified, it will try to retrieve the supported token issuer from the service.",
                    cls=MutuallyExclusiveOptionGroup)
    @optgroup.option("--token", metavar="TOKEN",
                     envvar=["ACCESS_TOKEN", "OIDC",
                             "OS_ACCESS_TOKEN", "OIDC_ACCESS_TOKEN",
                             "WATTS_TOKEN", "WATTSON_TOKEN"],
                     show_envvar=True, callback=validate_pass_from_parent,
                     help="Pass token directly. Environment variables are checked in given order.")
    @optgroup.option("--oa-account", "--oidc", metavar="SHORTNAME",
                     envvar=["OIDC_AGENT_ACCOUNT"], show_envvar=True,
                     callback=validate_pass_from_parent,
                     help="Name of configured account in oidc-agent.")
    @optgroup.option("--iss", "--issuer", metavar="URL",
                     envvar=["OIDC_ISS", "OIDC_ISSUER"], show_envvar=True,
                     callback=validate_pass_from_parent,
                     help="URL of token issuer. Configured account in oidc-agent for this issuer will be used. Environment variables are checked in given order.")
    @my_logging_simple_verbosity_option(logger, "--log-level", default="ERROR", metavar="LEVEL", envvar="LOG", show_envvar=True)
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