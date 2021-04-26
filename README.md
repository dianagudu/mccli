# mc_ssh
SSH client wrapper for SSH with access token

## Installation

- Install mc_ssh from pypi: `pip install mc_ssh`
- Install mc_ssh from source:
    - Install prerequisites: `pip install -r requirements.txt`
    - Build package: `./setup.py sdist`
    - Install package: `pip install dist/mc_ssh-$version.tar.gz`
<!-- - Debian package:
    ```
    apt-get install python3 python3-venv
    dpkg -i motley-cue-client_$version.deb
    ``` -->

<!-- ## Configuration -->

## Usage

```sh
$ mccli --help

Usage: mccli [OPTIONS] COMMAND [ARGS]...

  ssh client wrapper for oidc-based authentication

Options:
  --help  Show this message and exit.

Commands:
  scp   secure file copy
  sftp  --- Not implemented ---
  ssh   open a login shell or execute a command via ssh

$ mccli ssh --help

Usage: mccli ssh [OPTIONS] HOSTNAME [COMMAND]

Options:
  --dry-run                       print sshpass command and exit
  --mc-endpoint TEXT              motley_cue API endpoint, default URLs:
                                  https://HOSTNAME, http://HOSTNAME:8080

  --insecure                      ignore verifying the SSL certificate for
                                  motley_cue endpoint, NOT RECOMMENDED

  Access Token sources: [mutually_exclusive]
    --oa-account TEXT             name of configured account in oidc-agent,
                                  has priority over --token  [env var:
                                  OIDC_AGENT_ACCOUNT]

    --token TEXT                  pass token directly, env variables are
                                  checked in given order  [env var:
                                  ACCESS_TOKEN, OIDC, OS_ACCESS_TOKEN,
                                  OIDC_ACCESS_TOKEN, WATTS_TOKEN,
                                  WATTSON_TOKEN]

  ssh options:                    supported options to be passed to SSH
    -p <int>                      port to connect to on remote host
  --help                          Show this message and exit.
```

First, you'll need an OIDC Access Token to authenticate.
You might want to check out the [oidc-agent](https://github.com/indigo-dc/oidc-agent) for that.

After you get the `oidc-agent` running, configure an account for your OP.
For example, if you generated an account named `egi` for the [EGI AAI](https://aai.egi.eu/oidc), you can set this in an environment variable:
```sh
export OIDC_AGENT_ACCOUNT=egi
```
Then, assuming that the ssh server has a [motley_cue](https://github.com/dianagudu/motley_cue) instance running at https://$SSH_SERVER, you can connect to the ssh server simply by:
```sh
mccli ssh $SSH_SERVER
```
Or get the sshpass command that you can run instead:
```sh
mccli ssh $SSH_SERVER --dry-run
```