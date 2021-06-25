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

  ssh client wrapper with OIDC-based authentication

Options:
  --mc-endpoint URL               motley_cue API endpoint, default URLs:
                                  https://HOSTNAME, http://HOSTNAME:8080

  --insecure                      ignore verifying the SSL certificate for
                                  motley_cue endpoint, NOT RECOMMENDED

  Access Token sources: [mutually_exclusive]
                                  the sources for retrieving the access token,
                                  odered by priority

    --token TOKEN                 pass token directly, env variables are
                                  checked in given order  [env var:
                                  ACCESS_TOKEN, OIDC, OS_ACCESS_TOKEN,
                                  OIDC_ACCESS_TOKEN, WATTS_TOKEN,
                                  WATTSON_TOKEN]

    --oa-account SHORTNAME        name of configured account in oidc-agent
                                  [env var: OIDC_AGENT_ACCOUNT]

    --iss, --issuer URL           url of token issuer; configured account in
                                  oidc-agent for this issuer will be used
                                  [env var: OIDC_ISS, OIDC_ISSUER]

  --log-level LEVEL               Either CRITICAL, ERROR, WARNING, INFO or
                                  DEBUG.

  --version                       Show the version and exit.
  --help                          Show this message and exit.

Commands:
  info  get info about service
  scp   secure file copy
  sftp  secure file transfer
  ssh   remote login client
```

You can also use the help option on each subcommand, eg:
```sh
mccli ssh --help
```

First, you'll need an OIDC Access Token to authenticate.
You might want to check out the [oidc-agent](https://github.com/indigo-dc/oidc-agent) for that.

After you get the `oidc-agent` running, configure an account for your OP.
For example, if you generated an account named `egi` for the [EGI AAI](https://aai.egi.eu/oidc), you can set this in an environment variable:
```sh
export OIDC_AGENT_ACCOUNT=egi
```
Then, assuming that the ssh server has a [motley_cue](https://github.com/dianagudu/motley_cue) instance running on the same host at https://$SSH_SERVER or http://$SSH_SERVER:8080, you can connect to the ssh server simply by:
```sh
mccli ssh $SSH_SERVER
```
Or get the sshpass command that you can run instead:
```sh
mccli ssh $SSH_SERVER --dry-run
```
