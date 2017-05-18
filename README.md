# pyvmlib
A simple library for controlling VMware vCenter / ESXi servers.

This library wraps up pyvmomi into something a little more friendly.

To use, create a `Connection` object and call methods on it. e.g.

```
with Connection(HOST, USER, PASS) as conn:
    for dev in conn.list_usb_devices_on_guest(VM_NAME):
        print("Got dev: {}".format(dev))
```

If your host has a self-signed certificate, set the `ignore_ssl_error` argument to `True`.

```
with Connection(INSECURE_HOST, USER, PASS, ignore_ssl_error=True) as conn:
    for dev in conn.list_usb_devices_on_guest(VM_NAME):
        print("Got dev: {}".format(dev))
```
