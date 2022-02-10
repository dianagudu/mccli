import pkg_resources  # part of setuptools

try:
    __version__ = pkg_resources.get_distribution("mccli").version
except Exception:
    __version__ = "unknown"
