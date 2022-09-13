import requests
import json
from rfc3986 import urlparse
import socket

from .logging import logger

infostring = "Please contact an administrator for more information."
# From the docs:
# > It’s a good practice to set connect timeouts to slightly larger than a multiple of 3,
# > which is the default TCP packet retransmission window.
TIMEOUT = 3.05


def deploy(mc_endpoint, token, verify=True):
    endpoint = mc_endpoint + "/user/deploy"
    headers = {"Authorization": f"Bearer {token}"}

    resp = requests.get(endpoint, headers=headers, verify=verify)

    from_cache = getattr(resp, "from_cache", False)
    if from_cache:
        logger.debug(f"Using cached response for {endpoint}")

    return resp


def get_status(mc_endpoint, token, verify=True):
    endpoint = mc_endpoint + "/user/get_status"
    headers = {"Authorization": f"Bearer {token}"}

    resp = requests.get(endpoint, headers=headers, verify=verify)

    from_cache = getattr(resp, "from_cache", False)
    if from_cache:
        logger.debug(f"Using cached response for {endpoint}")

    return resp


def generate_otp(mc_endpoint, token, verify=True):
    endpoint = mc_endpoint + "/user/generate_otp"
    headers = {"Authorization": f"Bearer {token}"}

    resp = requests.get(endpoint, headers=headers, verify=verify)

    from_cache = getattr(resp, "from_cache", False)
    if from_cache:
        logger.debug(f"Using cached response for {endpoint}")

    return resp


def info(mc_endpoint, verify=True):
    endpoint = mc_endpoint + "/info"

    resp = requests.get(endpoint, verify=verify)

    from_cache = getattr(resp, "from_cache", False)
    if from_cache:
        logger.debug(f"Using cached response for {endpoint}")

    return resp


def info_authorisation(mc_endpoint, token, verify=True):
    endpoint = mc_endpoint + "/info/authorisation"
    headers = {"Authorization": f"Bearer {token}"}

    resp = requests.get(endpoint, headers=headers, verify=verify)

    from_cache = getattr(resp, "from_cache", False)
    if from_cache:
        logger.debug(f"Using cached response for {endpoint}")

    return resp


def get_info(mc_endpoint, verify=True):
    try:
        resp = info(mc_endpoint, verify=verify)
        if resp.status_code == requests.codes.ok:  # pylint: disable=no-member
            return resp.json()
        else:
            resp.raise_for_status()
    except Exception as e:
        logger.debug(f"Something went wrong: {e}")
        logger.error("Failed to get service info")
    return None


def get_supported_ops(mc_endpoint, verify=True):
    service_info = get_info(mc_endpoint, verify)
    if service_info is not None:
        supported_ops = service_info.get("supported_OPs", [])
        # backward compat with old motley_cue
        if supported_ops == []:
            supported_ops = service_info.get("supported OPs", [])
        return supported_ops
    return []


def get_authorisation_info(mc_endpoint, token, verify=True):
    try:
        resp = info_authorisation(mc_endpoint, token, verify=verify)
        return resp.json()
    except Exception as e:
        logger.debug(f"Something went wrong: {e}")
        logger.error("Failed to get authorisation info from service")
    return None


def get_audience(mc_endpoint, token, verify=True):
    try:
        resp = info_authorisation(mc_endpoint, token, verify=verify)
        return resp.json().get("audience", None)
    except Exception as e:
        logger.debug("Failed to get audience from service, assuming no specific audience needed.")
    return None


def get_local_status(mc_endpoint, token, verify=True):
    try:
        resp = get_status(mc_endpoint, token, verify=verify)
        if resp.status_code == requests.codes.ok:  # pylint: disable=no-member
            output = resp.json()
            state = output["state"]
            status_string = None
            if state == "suspended":
                status_string = f"Your account on service is suspended, you might not be able to login. {infostring}"
                status_string += f'\nLocal username: {output["message"].split()[1]}'
            elif state == "limited":
                status_string = f"Your account on service has limited capabilities, but you might still be able to login. {infostring}"
                status_string += f'\nLocal username: {output["message"].split()[1]}'
            elif state == "pending":
                status_string = (
                    f"Your account creation on service is still pending approval. {infostring}"
                )
            elif state == "unknown":
                status_string = f"Your account on service is in an undefined state. {infostring}"
            elif state == "not_deployed":
                status_string = f"Your account on service is not deployed, but it will be created on the first login if authorised."
            elif state == "deployed":
                status_string = f"Your account on service is deployed."
                status_string += f'\nLocal username: {output["message"].split()[1]}'
            if status_string:
                return status_string
            else:
                # should not happen
                return "Failed to get more information about your local account."
        else:
            return resp.text
    except Exception as e:
        logger.debug(f"Something went wrong: {e}")
        logger.error("Failed to get local account info from service")
    return None


def _get_username_from_message(message):
    try:
        return message.split()[1]
    except Exception as e:
        logger.debug(f"Something went wrong: {e}")
        logger.error("Failed to get SSH username from server")

def local_username(mc_endpoint, token, verify=True):
    resp = get_status(mc_endpoint, token, verify=verify)
    if resp.status_code == requests.codes.ok:  # pylint: disable=no-member
        output = resp.json()
        state = output["state"]
        logger.info(f"State of your local account: {state}")
        if state == "suspended":
            logger.warning(
                f"Your account on service is suspended, you might not be able to login. {infostring}"
            )
            return _get_username_from_message(output["message"])
        elif state == "limited":
            logger.warning(
                f"Your account on service has limited capabilities, but you might still be able to login. {infostring}"
            )
            return _get_username_from_message(output["message"])
        elif state in ["unknown", "not_deployed", "deployed", "pending"]:
            if state == "unknown":
                logger.warning(
                    "Your account on service is in an undefined state. Will try redeploying..."
                )
            elif state == "not_deployed":
                logger.info("Creating local account...")
            elif state == "deployed":
                logger.info("Updating local account...")
            elif state == "pending":
                logger.info("Your account creation on service is still pending approval. Sending another request for deployment...")
            resp = deploy(mc_endpoint, token, verify=verify)
            if resp.status_code == requests.codes.ok:  # pylint: disable=no-member
                new_state = resp.json()["state"]
                if new_state == "pending":
                    message = resp.json().get("message", "Your account creation on service is pending approval.")
                    raise Exception(
                        f"{message} {infostring}"
                    )
                elif new_state == "deployed":
                    logger.debug(json.dumps(resp.json(), indent=2))
                    return resp.json()["credentials"]["ssh_user"]
                return _get_username_from_message(resp.json()["message"])
            elif state == "deployed":
                logger.warning(
                    f"Failed on redeploy. Some of your user information might be outdated."
                )
                return _get_username_from_message(output["message"])
            else:
                resp_dict = json.loads(resp.text)
                try:
                    logger.error(
                        f'Failed on deploy: [HTTP {resp.status_code}] [state={resp_dict["state"]}] {resp_dict["message"]}'
                    )
                except Exception:
                    logger.error(f"Failed on deploy: [HTTP {resp.status_code}] {resp.text}")
        else:
            raise Exception(
                f"Weird, this should never have happened... Your account is in state: {state}. {infostring}"
            )
    else:
        resp_dict = json.loads(resp.text)
        try:
            logger.error(
                f'Failed on get_status: [HTTP {resp.status_code}] {resp_dict["error"]} - {resp_dict["error_description"]}'
            )
        except Exception:
            logger.error(f"Failed on get_status: [HTTP {resp.status_code}] {resp.text}")
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

        # a timeout is necessary here e.g. when the firewall drops packages
        resp = requests.get(mc_endpoint, verify=verify, timeout=TIMEOUT)

        from_cache = getattr(resp, "from_cache", False)
        if from_cache:
            logger.debug(f"Using cached response for {mc_endpoint}")

        if resp.status_code == 200:
            if not verify:
                logger.warning(
                    "InsecureRequestWarning: Unverified HTTPS"
                    f"request is being made to '{mc_endpoint}'. "
                    "Adding certificate verification is strongly advised."
                )
            # check for motley_cue
            if (
                resp.json().get("description", None)
                == "This is the user API for mapping remote identities to local identities."
            ):
                logger.info("...FOUND IT!")
                return mc_endpoint
    except requests.exceptions.SSLError:
        msg = (
            "SSL certificate verification failed. "
            "Use --insecure if you wish to ignore SSL certificate verification"
        )
        logger.info(msg)
        raise Exception(msg)
    except Exception as e:
        pass
        # logger.debug(f"Something went wrong: {e}")
    logger.info("...NOTHING HERE")
    return None
