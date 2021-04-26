import requests


def deploy(mc_endpoint, token, verify=True):
    endpoint = mc_endpoint + "/user/deploy"
    headers = {"Authorization": f"Bearer {token}"}

    return requests.get(endpoint, headers=headers, verify=verify)


def get_status(mc_endpoint, token, verify=True):
    endpoint = mc_endpoint + "/user/get_status"
    headers = {"Authorization": f"Bearer {token}"}

    return requests.get(endpoint, headers=headers, verify=verify)


def info(mc_endpoint, token, verify=True):
    endpoint = mc_endpoint + "/info"
    headers = {"Authorization": f"Bearer {token}"}

    return requests.get(endpoint, headers=headers, verify=verify)


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
