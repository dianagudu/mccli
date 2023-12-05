import sys

from .logging import logger


class MccliException(Exception):
    """Base class for exceptions in this module."""

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class FatalMccliException(MccliException):
    """Exception raised for fatal errors.

    Attributes:
        message -- explanation of the error
    """

    exit_code = 1

    def __init__(self, message):
        super().__init__(message)
        logger.error(message)
        sys.exit(FatalMccliException.exit_code)


class MccliUsageError(MccliException):
    """Exception raised for errors in the usage of the CLI, such as missing or invalid arguments."""


class OidcError(MccliException):
    """Exception raised for OIDC-related errors, such as missing or invalid token or token source."""


class SshError(MccliException):
    """Exception raised for SSH-related errors, such as connection errors."""


class MotleyCueError(MccliException):
    """Exception raised for errors coming from the MotleyCue service."""
