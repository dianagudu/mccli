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
