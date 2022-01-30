.. _usage_info:

Retrieve information about user and server
==========================================

The ``mccli info`` command helps you retrieve various information that you might find useful:

* about your federated identity
* about an OIDC-enabled SSH server
* about your local account on an OIDC-enabled SSH server 


OIDC user information
----------------------

You can find out more information about your OIDC identity by passing the corresponding OIDC Access Token (or oidc-agent account) to mccli: 

.. code-block:: bash

  mccli info --oidc egi


This command prints the information in the token, as well as information retrieved from the userinfo endpoint of the token issuer, such as:

* full name
* email address
* group memberships
* assurance information
* unique identifier
* ...

Powered by the `flaat-userinfo <https://github.com/indigo-dc/flaat>`_ tool.


Server information
-------------------

Before trying to connect to an OIDC-enabled SSH server, you can check which OIDC providers (OPs) are supported, as well as other login information, with:

.. code-block:: bash

  mccli info $SSH_SERVER


Even if your OP is supported, it is possible that you are not authorised to use login (you might not be in the authorised groups). To find out more, try:

.. code-block:: bash

  mccli info --oidc egi $SSH_SERVER


If the OP is supported on the server, this command will show the authorisation information for this OP, as well as the status of your local account on the server (whether it is deployed or not, what is your local username, etc.). 
