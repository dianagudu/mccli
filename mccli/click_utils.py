import typing as t
from gettext import gettext as _
import click
import click_logging
from click_option_group import optgroup, MutuallyExclusiveOptionGroup
from functools import wraps
import urllib3
import logging
import inspect

from .logging import logger
from .version import __version__


FC = t.TypeVar("FC", t.Callable[..., t.Any], click.Command)


class CustomUsageCommand(click.Command):
    @property
    def usage_text(self):
        return ""

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


def access_token_sources(func):
    @optgroup.group(
        "Access Token sources",
        help="The sources for retrieving an Access Token, in the order they are checked. If no source is specified, it will try to retrieve the supported token issuer from the service.",
        cls=MutuallyExclusiveOptionGroup,
    )
    @optgroup.option(
        "--token",
        metavar="TOKEN",
        envvar=[
            "ACCESS_TOKEN",
            "OIDC",
            "OS_ACCESS_TOKEN",
            "OIDC_ACCESS_TOKEN",
            "WATTS_TOKEN",
            "WATTSON_TOKEN",
        ],
        show_envvar=True,
        callback=validate_pass_from_parent,
        help="Pass token directly. Environment variables are checked in given order.",
    )
    @optgroup.option(
        "--oa-account",
        "--oidc",
        metavar="SHORTNAME",
        envvar=["OIDC_AGENT_ACCOUNT"],
        show_envvar=True,
        callback=validate_pass_from_parent,
        help="Name of configured account in oidc-agent.",
    )
    @optgroup.option(
        "--iss",
        "--issuer",
        metavar="URL",
        envvar=["OIDC_ISS", "OIDC_ISSUER"],
        show_envvar=True,
        callback=validate_pass_from_parent,
        help="URL of token issuer. Configured account in oidc-agent for this issuer will be used. Environment variables are checked in given order.",
    )
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def motley_cue_options(func):
    @optgroup.group("motley_cue options")
    @optgroup.option(
        "--mc-endpoint",
        metavar="URL",
        callback=validate_pass_from_parent,
        help="motley_cue API endpoint. Default URLs are checked in given order: https://HOSTNAME, https://HOSTNAME:8443, http://HOSTNAME:8080",
    )
    @optgroup.option(
        "--insecure",
        "verify",
        is_flag=True,
        default=True,
        callback=validate_verify,
        help="Ignore verifying the SSL certificate for motley_cue endpoint, NOT RECOMMENDED.",
    )
    @optgroup.option(
        "--no-cache",
        is_flag=True,
        default=False,
        callback=validate_pass_from_parent,
        help="Do not cache HTTP requests.",
    )
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def verbosity_options(func):
    @optgroup.group("Verbosity")
    @my_debug_option(logger)
    @my_logging_simple_verbosity_option(
        logger,
        "--log-level",
        default="ERROR",
        metavar="LEVEL",
        envvar="LOG",
        show_envvar=True,
    )
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def help_options(func):
    @optgroup.group("Help")
    @my_help_option("-h", "--help")
    @my_version_option(__version__, "-V", "--version")
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def basic_options(func):
    """The basic set of common options to be used by all commands.

    It still contains a hidden `--dry-run` option so that the user
    can pass it to the parent command as well.
    """

    @access_token_sources
    @motley_cue_options
    @verbosity_options
    @optgroup.option("--dry-run", is_flag=True, callback=validate_pass_from_parent, hidden=True)
    @help_options
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def extended_options(func):
    """Extends the basic common options by adding a `--dry-run` option to the verbosity group."""

    @access_token_sources
    @motley_cue_options
    @verbosity_options
    @optgroup.option(
        "--dry-run",
        is_flag=True,
        callback=validate_pass_from_parent,
        help="Print sshpass command and exit.",
    )
    @help_options
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


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
        if ctx.get_parameter_source(param.name) is click.core.ParameterSource.COMMANDLINE:
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
    if value and ctx.get_parameter_source(param.name) is click.core.ParameterSource.COMMANDLINE:
        ctx.meta[param.name] = value
    return value


def my_logging_simple_verbosity_option(logger=None, *names, **kwargs):
    """My version of @click_logging.simple_verbosity_option
    that takes over the value from the parent command.

    A decorator that adds a `--verbosity, -v` option to the decorated
    command.

    Name can be configured through ``*names``. Keyword arguments are passed to
    the underlying ``click.option`` decorator.
    """
    if not names:
        names = ["--verbosity", "-v"]

    kwargs.setdefault("default", "INFO")
    kwargs.setdefault("metavar", "LVL")
    kwargs.setdefault("expose_value", False)
    kwargs.setdefault(
        "help",
        f'Either CRITICAL, ERROR, WARNING, INFO or DEBUG. Default value: {kwargs["default"]}.',
    )
    kwargs.setdefault("is_eager", True)

    logger = click_logging.core._normalize_logger(logger)

    def decorator(f):
        def _set_level(ctx, param, value):
            value = value.upper()
            # check if log_level was set in the parent command and use it as default
            try:
                value = ctx.meta["log_level"]
            except Exception as e:
                # set the log_level in the context meta dict to be used by subcommands
                # only if it was set through the commandline
                if ctx.get_parameter_source(param.name) is click.core.ParameterSource.COMMANDLINE:
                    ctx.meta["log_level"] = value

            x = getattr(logging, value, None)
            if x is None:
                raise click.BadParameter(
                    "Must be CRITICAL, ERROR, WARNING, INFO or DEBUG, not {}".format(value)
                )
            logger.setLevel(x)

        return optgroup.option(*names, callback=_set_level, **kwargs)(f)

    return decorator


def my_debug_option(logger=None, *names, **kwargs):
    """A decorator that adds a `--debug` option to the decorated command.

    Name can be configured through ``*names``. Keyword arguments are passed to
    the underlying ``click.option`` decorator.
    """
    if not names:
        names = ["--debug"]

    kwargs.setdefault("default", False)
    kwargs.setdefault("is_flag", True)
    kwargs.setdefault("expose_value", False)
    kwargs.setdefault("help", "Sets the log level to DEBUG.")
    kwargs.setdefault("is_eager", True)

    logger = click_logging.core._normalize_logger(logger)

    def decorator(f):
        def _set_debug(ctx, param, value):
            if value:
                # this option overwrites any parent option or --log-level options
                # when enabled, log level is always debug
                ctx.meta["log_level"] = "DEBUG"
                logger.setLevel(logging.DEBUG)

        return optgroup.option(*names, callback=_set_debug, **kwargs)(f)

    return decorator


def my_help_option(*param_decls: str, **kwargs: t.Any) -> t.Callable[[FC], FC]:
    """My version of @click.help_option that adds --help to the optgroup.

    Add a ``--help`` option which immediately prints the help page
    and exits the program.

    This is usually unnecessary, as the ``--help`` option is added to
    each command automatically unless ``add_help_option=False`` is
    passed.

    :param param_decls: One or more option names. Defaults to the single
        value ``"--help"``.
    :param kwargs: Extra arguments are passed to :func:`option`.
    """

    def callback(ctx: click.Context, param: click.Parameter, value: bool) -> None:
        if not value or ctx.resilient_parsing:
            return

        click.echo(ctx.get_help(), color=ctx.color)
        ctx.exit()

    if not param_decls:
        param_decls = ("--help",)

    kwargs.setdefault("is_flag", True)
    kwargs.setdefault("expose_value", False)
    kwargs.setdefault("is_eager", True)
    kwargs.setdefault("help", _("Show this message and exit."))
    kwargs["callback"] = callback
    return optgroup.option(*param_decls, **kwargs)


def my_version_option(
    version: t.Optional[str] = None,
    *param_decls: str,
    package_name: t.Optional[str] = None,
    prog_name: t.Optional[str] = None,
    message: t.Optional[str] = None,
    **kwargs: t.Any,
) -> t.Callable[[FC], FC]:
    """My version of @click.version_option that adds --version to
    the optgroup.

    Add a ``--version`` option which immediately prints the version
    number and exits the program.

    If ``version`` is not provided, Click will try to detect it using
    :func:`importlib.metadata.version` to get the version for the
    ``package_name``. On Python < 3.8, the ``importlib_metadata``
    backport must be installed.

    If ``package_name`` is not provided, Click will try to detect it by
    inspecting the stack frames. This will be used to detect the
    version, so it must match the name of the installed package.

    :param version: The version number to show. If not provided, Click
        will try to detect it.
    :param param_decls: One or more option names. Defaults to the single
        value ``"--version"``.
    :param package_name: The package name to detect the version from. If
        not provided, Click will try to detect it.
    :param prog_name: The name of the CLI to show in the message. If not
        provided, it will be detected from the command.
    :param message: The message to show. The values ``%(prog)s``,
        ``%(package)s``, and ``%(version)s`` are available. Defaults to
        ``"%(prog)s, version %(version)s"``.
    :param kwargs: Extra arguments are passed to :func:`option`.
    :raise RuntimeError: ``version`` could not be detected.
    """
    if message is None:
        message = _("%(prog)s, version %(version)s")

    if version is None and package_name is None:
        frame = inspect.currentframe()
        assert frame is not None
        assert frame.f_back is not None
        f_globals = frame.f_back.f_globals if frame is not None else None
        # break reference cycle
        # https://docs.python.org/3/library/inspect.html#the-interpreter-stack
        del frame

        if f_globals is not None:
            package_name = f_globals.get("__name__")

            if package_name == "__main__":
                package_name = f_globals.get("__package__")

            if package_name:
                package_name = package_name.partition(".")[0]

    def callback(ctx: click.Context, param: click.Parameter, value: bool) -> None:
        if not value or ctx.resilient_parsing:
            return

        nonlocal prog_name
        nonlocal version

        if prog_name is None:
            prog_name = ctx.find_root().info_name

        if version is None and package_name is not None:
            metadata: t.Optional[types.ModuleType]

            try:
                from importlib import metadata  # type: ignore
            except ImportError:
                # Python < 3.8
                import importlib_metadata as metadata  # type: ignore

            try:
                version = metadata.version(package_name)  # type: ignore
            except metadata.PackageNotFoundError:  # type: ignore
                raise RuntimeError(
                    f"{package_name!r} is not installed. Try passing" " 'package_name' instead."
                )

        if version is None:
            raise RuntimeError(
                f"Could not determine the version for {package_name!r} automatically."
            )

        click.echo(
            t.cast(str, message) % {"prog": prog_name, "package": package_name, "version": version},
            color=ctx.color,
        )
        ctx.exit()

    if not param_decls:
        param_decls = ("--version",)

    kwargs.setdefault("is_flag", True)
    kwargs.setdefault("expose_value", False)
    kwargs.setdefault("is_eager", True)
    kwargs.setdefault("help", _("Show the version and exit."))
    kwargs["callback"] = callback
    return optgroup.option(*param_decls, **kwargs)


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
