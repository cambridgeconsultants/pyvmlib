.. image:: https://app.travis-ci.com/cambridgeconsultants/pyvmlib.svg?branch=master
    :target: https://app.travis-ci.com/cambridgeconsultants/pyvmlib
    :alt: Build Status

.. image:: https://img.shields.io/pypi/dm/pyvmlib.svg
    :target: https://pypi.python.org/pypi/pyvmlib/
    :alt: Downloads

pyvmlib
=======

A simple library for controlling VMware vCenter / ESXi servers.

This library wraps up pyvmomi into something a little more friendly.

To use, create a ``Connection`` object and call methods on it. e.g.

.. code-block:: python

    with Connection(HOST, USER, PASS) as conn:
        for dev in conn.list_usb_devices_on_guest(VM_NAME):
            print("Got dev: {}".format(dev))

If your host has a self-signed certificate, set the ``ignore_ssl_error`` argument to ``True``

.. code-block:: python

    with Connection(INSECURE_HOST, USER, PASS, ignore_ssl_error=True) as conn:
        for dev in conn.list_usb_devices_on_guest(VM_NAME):
            print("Got dev: {}".format(dev))

