# mc_ssh
SSH client wrapper for SSH with access token

## Installation

<!-- - Install mc_ssh from pypi: `pip install mc_ssh` -->
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
  sftp
  ssh   open a login shell or execute a command via ssh

$ mccli ssh --help

Usage: mccli ssh [OPTIONS] HOSTNAME [COMMAND]

Options:
  --mc-endpoint TEXT              motley_cue API endpoint, default:
                                  https://HOSTNAME

  Access Token sources: [mutually_exclusive]
    --oa-account TEXT             name of configured account in oidc-agent,
                                  has priority over --token  [env var:
                                  OIDC_AGENT_ACCOUNT]

    --token TEXT                  pass token directly, env variables are
                                  checked in given order  [env var:
                                  ACCESS_TOKEN, OIDC, OS_ACCESS_TOKEN,
                                  OIDC_ACCESS_TOKEN, WATTS_TOKEN,
                                  WATTSON_TOKEN]

  SSH options:                    supported options to be passed to SSH
    -p <int>                      port to connect to on remote host
  --help                          Show this message and exit.
```