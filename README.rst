mccli
=====

This is an SSH client wrapper that enables SSH with OIDC access tokens.

For server-side software, see `motley_cue <https://motley-cue.readthedocs.io>`_.

Compatibility
-------------

mccli works with Python 3 (>=3.7), and only Linux. Windows support is planned as plugins for popular SSH clients, such as PuTTY.


Documentation
-------------

The documentation is available at `readthedocs <https://mccli.readthedocs.io/>`_.

..
  or `GitHub Pages <https://dianagudu.github.io/mccli/>`_.

.. end-of-intro
.. beginning-of-test-server

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

.. end-of-test-server

License
-------

The source code is licensed under the `MIT license <https://opensource.org/licenses/MIT>`_. 

The logo is licensed under the `Creative Commons Attribution 4.0 International License <http://creativecommons.org/licenses/by/4.0/>`_ .

..
    .. image:: https://i.creativecommons.org/l/by/4.0/88x31.png
        :target: http://creativecommons.org/licenses/by/4.0/
        :alt: CC BY 4.0
