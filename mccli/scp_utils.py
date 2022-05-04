from rfc3986 import urlparse
from urllib import parse
import re
from click import UsageError
from enum import Enum

from .logging import logger


class ScpOperand:
    def __init__(
        self,
        remote=False,
        uri=False,
        user=None,
        host=None,
        path=None,
        port=None,
        original_str=None,
    ):
        self.__remote = remote
        self.__uri = uri
        self.__user = user
        self.__host = host
        self.__path = path
        self.__port = port
        self.__original_str = original_str

    @property
    def remote(self):
        """whether it is a remote path"""
        return self.__remote

    @property
    def uri(self):
        """whether the path is specified in URI form cf. RFCRFC3986"""
        return self.__uri

    @property
    def user(self):
        """remote user, if specified, or None if it is a local path"""
        return self.__user

    @property
    def host(self):
        """remote hostname or None if it is a local path"""
        return self.__host

    @property
    def path(self):
        """path, local or on remote host"""
        return self.__path

    @property
    def port(self):
        """port for SSH service"""
        return self.__port

    @property
    def original_str(self):
        """original string that was parsed into this class"""
        return self.__original_str

    def unsplit(self, user):
        if not self.remote:
            return self.path
        elif not self.uri:
            # format [user@]host[:path]
            if self.port:
                # should not happen
                raise Exception("Port cannot be specified in this format [user@]host[:path]")
            if not user:
                return f"{self.host}:{self.path}"
            else:
                return f"{user}@{self.host}:{self.path}"
        else:
            # format scp://[user@]host[:port][/path]
            return urlparse(self.original_str).copy_with(userinfo=user).unsplit()

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return (
            "ScpOperand["
            f"remote: {self.remote}, uri: {self.uri}, "
            f"user: {self.user}, host: {self.host}, "
            f"path: {self.path}, port: {self.port}"
            "]"
        )


class ScpUseCase(Enum):
    """Possible cases when running scp:

    * case 1: no motley_cue handling needed
        - all local paths, or
        - all remotes have user specified
    * case 2: a single motley_cue remote host
        - can also appear multiple times
        - the user can be passed as an ssh option with '-o'
        - no other remotes with specified users are present
    * case 3: multiple remotes
        - the sources/target have to be modified to pass the username
    """

    NO_MOTLEY_CUE = (1,)
    SINGLE_REMOTE = (2,)
    MULTIPLE_REMOTES = 3


class ScpCommand:
    def __init__(self, opts, sources, target):
        self.__opts = opts
        self.__sources = sources
        self.__target = target
        # default values
        self.__mc_host = None
        self.__num_prompts = 0
        # check which use case we're talking about
        number_of_remotes_with_user = 0
        number_of_unique_mc_remotes = 0
        number_of_pass_prompts = 0
        mc_host = None
        for operand in sources + [target]:
            if operand.remote and operand.user:
                # user is already set, do not handle via motley_cue
                number_of_remotes_with_user += 1
            elif operand.remote and operand.user is None:
                # this is definitely a motley_cue managed host
                if operand.host != mc_host:
                    # count unique mc remotes in command and reset pass prompts
                    number_of_unique_mc_remotes += 1
                    mc_host = operand.host
                    number_of_pass_prompts = 1
                else:
                    # increase number of password prompts for latest mc_host
                    number_of_pass_prompts += 1
        # set mc_host and pass_prompts only for SINGLE_REMOTE case
        if number_of_unique_mc_remotes == 0:
            self.__use_case = ScpUseCase.NO_MOTLEY_CUE
        elif number_of_unique_mc_remotes == 1 and not number_of_remotes_with_user:
            self.__use_case = ScpUseCase.SINGLE_REMOTE
            self.__mc_host = mc_host
            self.__num_prompts = number_of_pass_prompts
        else:
            self.__use_case = ScpUseCase.MULTIPLE_REMOTES

    @property
    def use_case(self):
        return self.__use_case

    @property
    def opts(self):
        return self.__opts

    @property
    def sources(self):
        return self.__sources

    @property
    def target(self):
        return self.__target

    @property
    def mc_host(self):
        return self.__mc_host

    @property
    def num_prompts(self):
        return self.__num_prompts

    def no_mc(self):
        return self.use_case == ScpUseCase.NO_MOTLEY_CUE

    def single_mc(self):
        return self.use_case == ScpUseCase.SINGLE_REMOTE

    def multiple_mc(self):
        return self.use_case == ScpUseCase.MULTIPLE_REMOTES

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return (
            "ScpCommand{\n"
            f"  use_case: {self.use_case}\n"
            f"  opts: {self.opts}\n"
            f"  sources: {self.sources}\n"
            f"  target: {self.target}\n"
            f"  mc_host: {self.mc_host}\n"
            f"  num_prompts: {self.num_prompts}\n"
            "}"
        )


def parse_scp_args(scp_args):
    """Extract source and target from the arguments
    of an scp command, represented as a list, and return
    an ScpCommand.
    """
    SCP_FLAGS = r"-[346ABCpqrTv]+"
    SCP_OPTS = r"-[cFiJloPS]"
    is_opt = False
    scp_opts = []
    operands = []
    for opt in scp_args:
        if opt.startswith("-") and re.match(SCP_FLAGS, opt):
            is_opt = False
            scp_opts += [opt]
        elif opt.startswith("-") and re.match(SCP_OPTS, opt):
            is_opt = True
            scp_opts += [opt]
        elif opt.startswith("-"):
            raise Exception(f"Invalid scp option: {opt}")
        elif is_opt:
            is_opt = False
            scp_opts += [opt]
        else:
            operands += [opt]

    if len(operands) < 2:
        raise UsageError("Please specify at least one SOURCE and TARGET for scp.")
    # target should be last
    target = __valid_path(operands[-1])
    # parse sources
    sources = [__valid_path(src) for src in operands[:-1]]
    return ScpCommand(opts=scp_opts, sources=sources, target=target)


def __valid_path(value):
    """Validates an scp operand (source/target) and returns ScpOperand
        - checks if it is a remote path
        - nothing to do for local paths
        - otherwise, parses the remote path and extracts info
    Parsing the remote path is similar to scp:
        - first try URI according to RFC3986
            scp://[user@]host[:port][/path]
        - otherwise remote path of the form:
            [user@]host:[path]
    """
    colon = __colon(value)
    if colon == -1:
        return ScpOperand(path=value, original_str=value)
    elif value.startswith("scp://"):
        logger.debug(f"{value} is of form scp://[user@]host[:port][/path]")
        try:
            parsed_uri = urlparse(value)
        except Exception as e:
            logger.debug(e)
            raise Exception(f"SCP operand {value} in URI form (cf RFC3986) could not be parsed")
        if not parsed_uri.host or parsed_uri.host == "":
            raise Exception(f"SCP operand {value} in URI form (cf RFC3986) does not contain a host")
        logger.debug(f"{parsed_uri}")
        return ScpOperand(
            remote=True,
            uri=True,
            user=parse.unquote(parsed_uri.userinfo)
            if parsed_uri.userinfo and parsed_uri.userinfo != ""
            else None,
            host=parse.unquote(parsed_uri.host),
            path=parse.unquote(parsed_uri.path)
            if parsed_uri.path and parsed_uri.path != ""
            else None,
            port=parsed_uri.port,
            original_str=value,
        )
    else:
        logger.debug(f"{value} is of form [user@]host:[path]")
        if colon == len(value):
            path = "."
        else:
            path = value[colon + 1 :]
        user_host = value[:colon].split("@")
        host = user_host[-1]
        user = "@".join(user_host[:-1])
        user = None if user == "" else user
        if host == "":
            raise Exception(f"SCP operand {value} in [user@]host:[path] does not contain a host")
        logger.debug(f"ParseResult: [user={user}, host={host}, path={path}]")
        return ScpOperand(remote=True, user=user, host=host, path=path, original_str=value)


def __colon(value):
    """This is the equivalent of the colon function in SCP

    Returns colon index or -1 when the host is not remote.
    """
    flag = False
    if value.startswith(":"):
        return -1
    if value.startswith("["):
        flag = True
    for i, v in enumerate(value):
        if v == "@" and len(value) > i + 1 and value[i + 1] == "[":
            flag = True
        if v == "]" and len(value) > i + 1 and value[i + 1] == ":" and flag:
            return i + 1
        if v == ":" and not flag:
            return i
        if v == "/":
            return -1
    return -1


# def extract_hostname_from_ssh(ssh_args):
#     """Extract the hostname from the arguments
#     of an ssh command, represented as a list
#     """
#     SSH_FLAGS = r"-[46AaCfGgKkMNnqsTtVvXxYy]+"
#     SSH_OPTS = r"-[BbcDEeFIiJLlmOopQRSWw]"
#     is_opt = False
#     for opt in ssh_args:
#         if opt.startswith("-") and re.match(SSH_FLAGS, opt):
#             is_opt = False
#         elif opt.startswith("-") and re.match(SSH_OPTS, opt):
#             is_opt = True
#         elif opt.startswith("-"):
#             raise Exception(f"Invalid ssh option: {opt}")
#         elif is_opt:
#             is_opt = False
#         else:
#             return opt
