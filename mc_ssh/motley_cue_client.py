import requests


def deploy(mc_endpoint, token):
    endpoint = mc_endpoint + "/user/deploy"
    headers = {"Authorization": f"Bearer {token}"}

    return requests.get(endpoint, headers=headers)


def get_status(mc_endpoint, token):
    endpoint = mc_endpoint + "/user/get_status"
    headers = {"Authorization": f"Bearer {token}"}

    return requests.get(endpoint, headers=headers)


def info(mc_endpoint, token):
    endpoint = mc_endpoint + "/info"
    headers = {"Authorization": f"Bearer {token}"}

    return requests.get(endpoint, headers=headers)


def local_username(mc_endpoint, token):
    resp = get_status(mc_endpoint, token)

    if resp.status_code == requests.codes.ok:
        output = resp.json()
        if output["state"] == "not_deployed":
            resp = deploy(mc_endpoint, token)
            if resp.status_code == requests.codes.ok:
                return resp.json()["credentials"]["ssh_user"]
        else:
            return output["message"].split()[1]
    print(f"[ERROR] {resp.json()['detail']}")
    resp.raise_for_status()
