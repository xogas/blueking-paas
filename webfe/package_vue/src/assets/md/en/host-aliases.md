This configuration item can be defined in two ways: through an online form or the application description file. It is recommended to use the application description file for definition.

#### Online Form

For applications deployed via the image repository, you can directly add domain resolution rules on the page, which will take effect after saving and redeploying.

#### Application Description File

For applications deployed from source code, please define `spec.domainResolution.hostAliases` in the `app_desc.yaml` file located in the build directory to add additional domain resolution rules, which is equivalent to appending entries to the /etc/hosts file.

Below is an example file:
```yaml
specVersion: 3
appVersion: "1.0.0"
module:
  spec:
    processes:
      # ... omitted
    domainResolution:
      hostAliases:
        - ip: "127.0.0.1"
          hostnames:
            - "foo.local"
            - "bar.local"
```

Field Descriptions:
- `ip`: (string) The target IP address to resolve.
- `hostnames`: (array[string]) The list of domain names to be resolved.

In the example configuration, when the application accesses the domains `foo.local` and `bar.local`, they will be resolved to the target IP `127.0.0.1`.

> Note: The configuration in the example follows the latest specification of the cloud-native application description file (specVersion: 3). If your description file version is `spec_version: 2`, please convert it to the latest version first.

#### Notes

1. **Scope of Effect**: After definition, all modules under the application will take effect.
2. **Priority**: If this item is defined in the application description file `app_desc.yaml`, it will refresh this configuration item during each deployment.