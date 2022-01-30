.. _misc:

Additional configurations
=========================

For a full description of the options, use the help option --- also on each subcommand, as they might have additional options available:

.. code-block:: bash

  mccli --help
  mccli ssh --help
  mccli info --help


.. rubric:: motley_cue endpoint

`motley_cue <https://github.com/dianagudu/motley_cue>`_ is the server-side software that handles the mapping of OIDC identities to local accounts. 
``mccli`` queries motley_cue's REST API to trigger local account provisioning or retrieve the local username to be by SSH.

Ideally, as a user you do not need to know anything about it. However, you might encounter the following error message: ``No motley_cue service found on host``.

This means that the motley_cue API is not running on one of the standard ports: 443, 8443, 8080. In that case, please contact an administrator of the SSH server for more information, and then pass the API URL via ``--mc-endpoint`` to every ``mccli`` command.


.. rubric:: dry-run

With this option, ``mccli`` does not run the given SSH command, but prints the corresponding ``sshpass`` command that can be used to SSH into the server. In addition, it will trigger the deployment of your local account on the remote machine if the account doesn't exist.

For example,

.. code-block:: bash

  mccli ssh --oidc egi --dry-run ssh $SSH_SERVER


will output something like:

.. code-block:: bash

  SSHPASS=`oidc-token egi` sshpass -P 'Access Token' -e ssh -l user001 $SSH_SERVER

This means your local account on the remote host is ``user001``.

This could be useful if you want to run this command on a different machine that doesn't have ``mccli`` or Python installed.

.. rubric:: Logging

Access more logging information with the following options:

.. option:: --log-level <LEVEL>
        
  Either CRITICAL, ERROR, WARNING, INFO or DEBUG. Default value: ERROR.

.. option:: --debug

  Sets the log level to DEBUG.

Or simply set the environment variable **LOG** to the desired level.
