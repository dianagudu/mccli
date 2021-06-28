import pkg_resources  # part of setuptools

__version__ = pkg_resources.require("mc_ssh")[0].version
