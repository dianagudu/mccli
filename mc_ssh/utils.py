import liboidcagent as agent
import re
import requests
from requests.exceptions import SSLError
from requests.packages import urllib3

from .motley_cue_client import local_username, get_supported_ops
from .logging import logger


def __valid_remote_path(value):
    """
    Validate a remote path of the form:
        [host:]path
    and return the two components in a dict.
    """
    value_dict = {}
    # split into host and path
    parts = value.split(":")
    if len(parts) == 1:
        value_dict["path"] = parts[0]
    elif len(parts) == 2:
        try:
            # validate host
            value_dict = re.match(
                r"^((?P<host>((\w|\w[\w\-]*\w)\.)*(\w|\w[\w\-]*\w)))?$",
                parts[0]).groupdict()
        except Exception:
            raise Exception(
                f"Invalid remote hostname: {value}")
        value_dict["path"] = "." if parts[1] == "" else parts[1]
    else:
        raise Exception(
            f"Invalid scp argument {value}: must be of form [host:]path"
        )
    return value_dict


def validate_scp_target(ctx, param, value):
    """
    Validate scp target -- must be of following form:
        [host:]path
    No user is allowed since it will be retrieved from the motley_cue endpoint.
    """
    try:
        return __valid_remote_path(value)
    except Exception as e:
        logger.error(e)
        ctx.exit()


def validate_scp_source(ctx, param, value):
    """
    Validate scp source -- must be of following form:
        [host:]path
    or a tuple containing multiple entries of the form:
        [host:]path
    No user is allowed since it will be retrieved from the motley_cue endpoint.
    """
    try:
        if isinstance(value, tuple):
            val_dicts = []
            for val in value:
                val_dicts += [__valid_remote_path(val)]
            return val_dicts
        else:
            return [__valid_remote_path(value)]
    except Exception as e:
        logger.error(e)
        ctx.exit()


def validate_insecure_flip2verify(ctx, param, value):
    """
    Disable warnings when insecure is set.
    """
    if value:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return not value


def init_token(token, oa_account, iss, mc_endpoint=None, verify=True):
    """Retrieve an oidc token:

    * use token if set,
    * retrieve from the oidc-agent via given account if oa_account is set
    * retrieve from the oidc-agent via given issuer if iss is set
    * use iss from service, if only one iss is supported
    * fail

    return token and string representation of command to retrieve token
    """
    if token is not None:
        logger.debug(f"Using token: {token}")
        return token, _str_init_token(token=token)
    if oa_account is not None:
        try:
            logger.info(f"Using oidc-agent account: {oa_account}")
            return agent.get_access_token(
                    oa_account, application_hint="mccli"
                ), _str_init_token(oa_account=oa_account)
        except Exception:
            logger.warning(f"Failed to get access token for oidc-agent account '{oa_account}'")
    if iss is not None:
        try:
            logger.info(f"Using issuer: {iss}")
            return agent.get_access_token_by_issuer_url(
                    iss, application_hint="mccli"
                ), _str_init_token(iss=iss)
        except Exception:
            logger.warning(
                f"Failed to get access token for issuer url '{iss}'")
    if mc_endpoint is not None:
        logger.debug(f"Trying to get list of supported AT issuers from {mc_endpoint}...")
        supported_ops = get_supported_ops(mc_endpoint, verify)
        if len(supported_ops) == 1:
            iss = supported_ops[0]
            try:
                logger.debug(f"Using the only issuer supported on service: {iss}")
                return agent.get_access_token_by_issuer_url(
                        iss, application_hint="mccli"
                    ), _str_init_token(iss=iss)
            except Exception:
                logger.warning(f"Failed to get access token for issuer url '{iss}'")
        elif len(supported_ops) > 1:
            logger.debug("Multiple issuers supported on service. I don't know which one to use.")
    raise Exception("No access token found")


def _str_init_token(token=None, oa_account=None, iss=None):
    """String representation of command used to get access token:
    * full token if token is set
    * `oidc-token oa_account` if oidc-agent account is set
    * `oidc-token iss` if issuer is set
    *  ... (`oidc-token iss` is iss can be retrieved from service)
    """
    if token:
        return f"'{token}'"
    if oa_account:
        return f"`oidc-token {oa_account}`"
    elif iss:
        return f"`oidc-token {iss}`"
    raise Exception("No access token found")


def _try_get(mc_endpoint, verify=True):
    try:
        response = requests.get(mc_endpoint, verify=verify)
        if response.status_code == 200:
            if not verify:
                logger.warning(
                    "InsecureRequestWarning: Unverified HTTPS"
                    f"request is being made to '{mc_endpoint}'. "
                    "Adding certificate verification is strongly advised."
                )
            return True
    except SSLError:
        msg = "SSL certificate verification failed. "\
            "Use --insecure if you wish to ignore SSL certificate verification"
        logger.info(msg)
        raise Exception(msg)
    except Exception:
        pass
    return False


def init_endpoint(mc_endpoint, ssh_host, verify=True):
    """Initialise motley_cue endpoint.

    If specified, test for valid URL and return `mc_endpoint`.
    Raise exception for invalid URL.

    If `mc_endpoint` not specified, try default value: https://HOSTNAME
    If this is not reachable, issue warning and try: http://HOSTNAME:8080
    If also not reachable, exit and ask user to specify it using --mc-endpoint
    """
    if mc_endpoint:
        if _try_get(mc_endpoint, verify):
            return mc_endpoint
        else:
            msg = f"No motley_cue service found at '{mc_endpoint}'. "\
                "Please specify a valid motley_cue endpoint."
            raise Exception(msg)

    # try https
    endpoint = f"https://{ssh_host}"
    if _try_get(endpoint, verify):
        return endpoint

    # try http on 8080 but issue warning
    endpoint = f"http://{ssh_host}:8080"
    if _try_get(endpoint):
        logger.warning(f"using unencrypted motley_cue endpoint: {endpoint}")
        return endpoint

    # raise error and ask user to specify endpoint
    msg = f"No motley_cue service found on host '{ssh_host}' "\
        "on port 443 or 8080. "\
        "Please specify motley_cue endpoint via --mc-endpoint."
    raise Exception(msg)


def init_user(mc_endpoint, token, verify=True):
    """Get remote username, will be deployed if it doesn't exist.
    """
    return local_username(mc_endpoint, token, verify=verify)
