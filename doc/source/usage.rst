.. _usage:

Usage
=====

Connecting to an OIDC-capable SSH server is as simple as:

.. code-block:: bash

  mccli ssh $SSH_SERVER


But first, you'll need an OIDC Access Token from your federated identity provider to authenticate.
:doc:`See how to configure the Access Token source here <usage/at_sources>`.


More advanced usage below:

.. toctree::
  :maxdepth: 1

  usage/at_sources
  usage/usage_scp
  usage/ssh-options
  usage/usage_info
  usage/misc  


Or check out the :ref:`CLI reference manual <cli>` for a full list of options.