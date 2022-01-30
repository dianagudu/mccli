.. _at_sources:

Access Token source
=====================

You'll need an OIDC Access Token to authenticate to the SSH server.

You might want to check out the `oidc-agent <https://github.com/indigo-dc/oidc-agent>`_ for that. It is a daemon that can provide valid access tokens from any number of configured OIDC Providers (OPs).

Once you get the ``oidc-agent`` running, configure an account for your preferred OP. For example, you can generate an account configuration for the `EGI AAI <https://aai.egi.eu/oidc>`_  named ``egi`` as follows: 

.. code-block:: bash

  oidc-gen --pub --iss https://aai.egi.eu/oidc --scope "openid profile email offline_access eduperson_entitlement eduperson_scoped_affiliation eduperson_unique_id" egi

To use your EGI identity for SSH login, you can set the oidc-agent account in an environment variable:

.. code-block:: bash

  export OIDC_AGENT_ACCOUNT=egi

If you have another way to retrieve OIDC access tokens, don't worry. You can pass the token directly to the SSH command through an environment variable:

.. code-block:: bash

  export ACCESS_TOKEN=<paste your token here>


Configuration options
----------------------

``mccli`` supports multiple ways of retrieving an Access Token.

They are shown below, in the order they are checked. The first source that is found will be used. If no source is specified, it will try to retrieve the supported token issuer from the service.


.. rubric:: Options

.. option:: --token <TOKEN>

  Pass token directly.

.. option:: --oa-account, --oidc <SHORTNAME>
  
  Name of configured account in oidc-agent.

.. option:: --iss, --issuer <URL>

  URL of token issuer. Configured account in oidc-agent for this issuer will be used.


.. rubric:: Environment variables

Instead of the options above, environment variables can provide default values for the different sources.

.. envvar:: [ACCESS_TOKEN, OIDC, OS_ACCESS_TOKEN, OIDC_ACCESS_TOKEN, WATTS_TOKEN, WATTSON_TOKEN]

  provide a default for :option:`--token`

.. envvar:: [OIDC_AGENT_ACCOUNT]

  provide a default for :option:`--oa-account`

.. envvar:: [OIDC_ISS, OIDC_ISSUER]

  provide a default for :option:`--iss`

..
  .. code-block:: bash

    $ mccli --help
    
    Usage: mccli [OPTIONS] COMMAND [ARGS]...

      SSH client wrapper with OIDC-based authentication

    Options:
      Access Token sources: [mutually_exclusive]
                                      The sources for retrieving an Access Token,
                                      in the order they are checked. If no source
                                      is specified, it will try to retrieve the
                                      supported token issuer from the service.
        --token TOKEN                 Pass token directly. Environment variables
                                      are checked in given order.  [env var:
                                      ACCESS_TOKEN, OIDC, OS_ACCESS_TOKEN,
                                      OIDC_ACCESS_TOKEN, WATTS_TOKEN,
                                      WATTSON_TOKEN]
        --oa-account, --oidc SHORTNAME
                                      Name of configured account in oidc-agent.
                                      [env var: OIDC_AGENT_ACCOUNT]
        --iss, --issuer URL           URL of token issuer. Configured account in
                                      oidc-agent for this issuer will be used.
                                      Environment variables are checked in given
                                      order.  [env var: OIDC_ISS, OIDC_ISSUER]
      motley_cue options: 
        --mc-endpoint URL             motley_cue API endpoint. Default URLs are
                                      checked in given order: https://HOSTNAME,
                                      https://HOSTNAME:8443, http://HOSTNAME:8080
        --insecure                    Ignore verifying the SSL certificate for
                                      motley_cue endpoint, NOT RECOMMENDED.
        --no-cache                    Do not cache HTTP requests.
      Verbosity: 
        --debug                       Sets the log level to DEBUG.
        --log-level LEVEL             Either CRITICAL, ERROR, WARNING, INFO or
                                      DEBUG. Default value: ERROR.  [env var: LOG]
      Help: 
        -h, --help                    Show this message and exit.
        -V, --version                 Show the version and exit.

    Commands:
      info  get info about service
      scp   secure file copy
      sftp  secure file transfer
      ssh   remote login client


..
  $ mccli --help

  Usage: mccli [OPTIONS] COMMAND [ARGS]...
  
    SSH client wrapper with OIDC-based authentication
  
  Options:
    Access Token sources: [mutually_exclusive]
                              The sources for retrieving an Access Token,
                              in the order they are checked. If no source
                              is specified, it will try to retrieve the
                              supported token issuer from the service.
      --token TOKEN           Pass token directly. Environment variables
                              are checked in given order.  [env var:
                              ACCESS_TOKEN, OIDC, OS_ACCESS_TOKEN,
                              OIDC_ACCESS_TOKEN, WATTS_TOKEN,
                              WATTSON_TOKEN]
      --oa-account, --oidc SHORTNAME
                              Name of configured account in oidc-agent.
                              [env var: OIDC_AGENT_ACCOUNT]
      --iss, --issuer URL     URL of token issuer. Configured account in
                              oidc-agent for this issuer will be used.
                              Environment variables are checked in given
                              order.  [env var: OIDC_ISS, OIDC_ISSUER]
    motley_cue options:
      --mc-endpoint URL       motley_cue API endpoint. Default URLs are
                              checked in given order: https://HOSTNAME,
                              https://HOSTNAME:8443, http://HOSTNAME:8080
      --insecure              Ignore verifying the SSL certificate for
                              motley_cue endpoint, NOT RECOMMENDED.
      --no-cache              Do not cache HTTP requests.
    Verbosity:
      --debug                 Sets the log level to DEBUG.
      --log-level LEVEL       Either CRITICAL, ERROR, WARNING, INFO or
                              DEBUG. Default value: ERROR.  [env var: LOG]
    Help:
      -h, --help              Show this message and exit.
      -V, --version           Show the version and exit.
  
  Commands:
    info  get info about service
    scp   secure file copy
    sftp  secure file transfer
    ssh   remote login client