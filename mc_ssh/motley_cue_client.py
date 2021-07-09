import requests
import json
from rfc3986 import urlparse
import socket

from .logging import logger

infostring = "Please contact an administrator for more information."


def deploy(mc_endpoint, token, verify=True):
    endpoint = mc_endpoint + "/user/deploy"
    headers = {"Authorization": f"Bearer {token}"}

    return requests.get(endpoint, headers=headers, verify=verify)


def get_status(mc_endpoint, token, verify=True):
    endpoint = mc_endpoint + "/user/get_status"
    headers = {"Authorization": f"Bearer {token}"}

    return requests.get(endpoint, headers=headers, verify=verify)


def info(mc_endpoint, verify=True):
    endpoint = mc_endpoint + "/info"

    return requests.get(endpoint, verify=verify)


def info_authorisation(mc_endpoint, token, verify=True):
    endpoint = mc_endpoint + "/info/authorisation"
    headers = {"Authorization": f"Bearer {token}"}

    return requests.get(endpoint, headers=headers, verify=verify)


def str_info_all(mc_endpoint, token=None, verify=True):
    service_info = get_info(mc_endpoint, verify)
    if token is not None:
        authz_info = get_authorisation_info(mc_endpoint, token, verify)
        if authz_info is not None:
            service_info["authorisation"] = authz_info
    return json.dumps(service_info, indent=2)


def get_info(mc_endpoint, verify=True):
    try:
        resp = info(mc_endpoint, verify=verify)
        if resp.status_code == requests.codes.ok:
            return resp.json()
        else:
            resp.raise_for_status()
    except Exception as e:
        logger.debug(f"[motley_cue] {e}")
        logger.error("Failed to get service info")
    return None


def get_supported_ops(mc_endpoint, verify=True):
    service_info = get_info(mc_endpoint, verify)
    if service_info is not None:
        return service_info["supported OPs"]
    return None


def get_authorisation_info(mc_endpoint, token, verify=True):
    try:
        resp = info_authorisation(mc_endpoint, token, verify=verify)
        if resp.status_code == requests.codes.ok:
            return resp.json()
        else:
            resp.raise_for_status()
    except Exception as e:
        logger.debug(f"[motley_cue] {e}")
        logger.warning("Failed to get authorisation info from service")
    return None


def local_username(mc_endpoint, token, verify=True):
    try:
        resp = get_status(mc_endpoint, token, verify=verify)
        if resp.status_code == requests.codes.ok:
            output = resp.json()
            state = output["state"]
            logger.info(f"State of your local account: {state}")
            if state == "suspended":
                logger.warning(f"Your account on host is suspended, you might not be able to login. {infostring}")
                return output["message"].split()[1]
            elif state == "limited":
                logger.warning(f"Your account on host has limited capabilities, but you might still be able to login. {infostring}")
                return output["message"].split()[1]
            elif state == "pending":
                raise Exception(f"Your account creation on host is still pending approval. {infostring}")
            elif state == "unknown" or state == "not_deployed" or state == "deployed":
                if state == "unknown":
                    logger.warning("Your account on host is in an undefined state. Will try redeploying...")
                elif state == "not_deployed":
                    logger.info("Creating local account...")
                elif state == "deployed":
                    logger.info("Updating local account...")
                resp = deploy(mc_endpoint, token, verify=verify)
                if resp.status_code == requests.codes.ok:
                    logger.debug(json.dumps(resp.json(), indent=2))
                    return resp.json()["credentials"]["ssh_user"]
                else:
                    resp_dict = json.loads(resp.text)
                    try:
                        logger.error(f'Failed on deploy: [HTTP {resp.status_code}] [state={resp_dict["state"]}] {resp_dict["message"]}')
                    except Exception:
                        logger.error(f"Failed on deploy: [HTTP {resp.status_code}] {resp.text}")
            else:
                raise Exception(f"Weird, this should never have happened... Your account is in state: {state}. {infostring}")
        else:
            resp_dict = json.loads(resp.text)
            try:
                logger.error(f'Failed on get_status: [HTTP {resp.status_code}] [state={resp_dict["state"]}] {resp_dict["message"]}')
            except Exception:
                logger.error(f"Failed on get_status: [HTTP {resp.status_code}] {resp.text}")
    except Exception as e:
        logger.error(f"Something went wrong: {e}")
    raise Exception("Failed to get ssh username")


def is_valid_mc_url(mc_endpoint, verify=True):
    """make sure you always set the url schema when calling this method.
    This should be http or https
    """
    try:
        logger.info(f"Looking for motley_cue service at '{mc_endpoint}'...")
        parse_result = urlparse(mc_endpoint)
        fqdn_host = socket.getfqdn(parse_result.host)
        if fqdn_host and fqdn_host != parse_result.host:
            mc_endpoint = parse_result.copy_with(host=fqdn_host).unsplit()
            logger.info(f"Using FQDN for host: {mc_endpoint}")

        response = requests.get(mc_endpoint, verify=verify)
        if response.status_code == 200:
            if not verify:
                logger.warning(
                    "InsecureRequestWarning: Unverified HTTPS"
                    f"request is being made to '{mc_endpoint}'. "
                    "Adding certificate verification is strongly advised."
                )
            # check for motley_cue
            if response.json().get("description", None) == "This is the user API for mapping remote identities to local identities.":
                logger.info("...FOUND IT!")
                return mc_endpoint
    except requests.exceptions.SSLError:
        msg = "SSL certificate verification failed. "\
            "Use --insecure if you wish to ignore SSL certificate verification"
        logger.info(msg)
        raise Exception(msg)
    except Exception as e:
        pass
        # logger.debug(f"Something went wrong: {e}")
    logger.info("...NOTHING HERE")
    return None
