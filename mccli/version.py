import pkg_resources  # part of setuptools

__version__ = pkg_resources.require("mccli")[0].version
