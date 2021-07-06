import requests
import json

from .logging import logger


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
        logger.info("Failed to get service info")
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
        logger.info("Failed to get authorisation info from service")
    return None


def local_username(mc_endpoint, token, verify=True):
    try:
        resp = get_status(mc_endpoint, token, verify=verify)
        if resp.status_code == requests.codes.ok:
            output = resp.json()
            if output["state"] == "not_deployed":
                resp = deploy(mc_endpoint, token, verify=verify)
                if resp.status_code == requests.codes.ok:
                    return resp.json()["credentials"]["ssh_user"]
                else:
                    resp_dict = json.loads(resp.text)
                    logger.error(f'[motley_cue] {resp_dict["state"]}: {resp_dict["message"]}')
                    resp.raise_for_status()
            else:
                return output["message"].split()[1]
        else:
            logger.error(f"[motley_cue] {json.loads(resp.text)}")
            resp.raise_for_status()
    except Exception as e:
        logger.error(f"[motley_cue] {e}")
    raise Exception("Failed to get ssh username")


def is_valid_mc_url(mc_endpoint, verify=True):
    try:
        logger.info(f"Looking for motley_cue service at '{mc_endpoint}'...")
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
                return True
    except requests.exceptions.SSLError:
        msg = "SSL certificate verification failed. "\
            "Use --insecure if you wish to ignore SSL certificate verification"
        logger.info(msg)
        raise Exception(msg)
    except Exception:
        pass
    logger.info("...NOTHING HERE")
    return False
