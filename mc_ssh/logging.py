import logging
import click_logging


logger = logging.getLogger(__name__)
echo_kwargs = {
    'debug': dict(err=True),
    'info': dict(err=True),
    'warning': dict(err=True),
    'error': dict(err=True),
    'exception': dict(err=True),
    'critical': dict(err=True),
}
style_kwargs = {
    'info': dict(fg='green'),
}
click_logging.basic_config(
    logger, echo_kwargs=echo_kwargs, style_kwargs=style_kwargs
)
