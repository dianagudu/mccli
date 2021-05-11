import requests


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


def get_supported_ops(mc_endpoint, verify=True):
    try:
        resp = info(mc_endpoint, verify=verify)
        if resp.status_code == requests.codes.ok:
            return resp.json()["supported OPs"]
        else:
            resp.raise_for_status()
    except Exception as e:
        print(f"[motley_cue] {e}")
        print("Failed to get list of supported OPs")
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
                return output["message"].split()[1]
        else:
            print(f"[motley_cue] {resp.json()['detail']}")
            resp.raise_for_status()
    except Exception as e:
        print(f"[motley_cue] {e}")
    raise Exception("Failed to get ssh username")
