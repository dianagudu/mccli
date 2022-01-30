mccli
=====

This is an SSH client wrapper that enables SSH with OIDC access tokens.

For server-side software, see `motley_cue 
<https://github.com/dianagudu/motley_cue>`_.

Compatibility
-------------

mccli works with Python 3.

mccli only works on Linux. Windows support is planned as plugins for popular SSH clients, such as PuTTY.


Documentation
-------------

.. toctree::
  :maxdepth: 2

  installation
  usage


Test server
------------

You can test this tool against our `test SSH server <https://ssh-oidc-demo.data.kit.edu>`_ that supports OIDC-based authentication:

.. code-block:: rst
  
  ssh-oidc-demo.data.kit.edu


The server accepts tokens from the following OIDC providers:

* `EGI Check-in <https://aai.egi.eu/oidc>`_
* `WLCG <https://wlcg.cloud.cnaf.infn.it>`_
* `HELMHOLTZ AAI (production) <https://login.helmholtz.de/oauth2>`_
* `HELMHOLTZ AAI (development) <https://login-dev.helmholtz.de/oauth2>`_
* `KIT <https://oidc.scc.kit.edu/auth/realms/kit>`_
* `DEEP Hybrid DataCloud <https://iam.deep-hybrid-datacloud.eu>`_
* `Google <https://accounts.google.com>`_


API reference
-------------
If you are looking for information on a specific function, class or
method, this part of the documentation is for you.

.. toctree::
   :maxdepth: 4

   api


mccli is developed on `Github <https://github.com/dianagudu/mccli>`_. Please report `issues <https://github.com/dianagudu/mccli/issues>`_ there as well.


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

