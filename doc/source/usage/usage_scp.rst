.. _usage_scp:

Secure copy
===========

Copying files over SSH is possible by simply prepending your usual ``scp`` command with ``mccli``.

For example, to copy the local file *file.txt* to the *remotedir* folder on a remote host, try:

.. code-block:: bash

  mccli scp file.txt $REMOTE_HOST:remotedir/


Of course, you will first need to :doc:`configure the Access Token source <at_sources>`.

.. warning::
    Do not specify the remote user if you want mccli to handle the OIDC-based authentication to the remote host for you!

If you specify a username for a host, then it will be used and it will be assumed that this specific host does not use OIDC-based authentication. This is useful, for example, when one of the remote hosts in the copy operation does not support OIDC-based authentication. You will have to handle authentication to that host on your own, e.g. via SSH keys.


General usage
-------------

Consult the :doc:`help page <../api/cli/scp>` for a full account of the options for ``mccli scp``.
