.. _ssh_options:

SSH/SCP-specific options
=========================

Since ``mccli`` is a wrapper around the SSH/SCP clients, all SSH/SCP-specific options are supported. The options are passed through to the SSH/SCP command unmodified.

This is enabled by the `pexpect <https://pexpect.readthedocs.io/>`_ library (via `pexpect.spawn <https://pexpect.readthedocs.io/en/stable/api/pexpect.html#spawn-class>`_).

Examples
--------

For example, you can pass a non-standart port to connect to the remote host or increase output verbosity like so:

.. code-block:: bash

  mccli ssh -vv -p 1022 $SSH_SERVER


It is also possible to execute a command on the remote host instead of an interactive login shell, by specifying a command after the ssh host, as usual:

.. code-block:: bash

    mccli ssh $SSH_SERVER ls -a


Passing options to the ``scp`` command works in a similar way.


.. code-block:: bash

  mccli ssh <SSH options go here> $SSH_SERVER <command on remote host>
  mccli scp <SCP options go here> $SCP_SOURCE ... $SCP_TARGET
