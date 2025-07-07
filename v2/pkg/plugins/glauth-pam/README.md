# GLAuth Plugin

This is a GLAuth plugin; that is, a backend that are not compiled in GLAuth by default.

To quote 'Butonic' (Jörn Friedrich Dreyer):

> Just keep the 'lightweight' in mind.

To build either back-end, type
```
make plugin_name
```
where 'name' is the plugin's name; so, for instance: `make plugin_sqlite`

To build back-ends for specific architectures, specify `PLUGIN_OS` and `PLUGIN_ARCH` --
 For instance, to build the sqlite plugin for the new Mac M1s:
 ```
make plugin_sqlite PLUGIN_OS=darwin PLUGIN_ARCH=arm64
 ```

## PAM Plugin

To authenticate against local users, edit the configuration file (see pkg/plugins/sample-pam.cfg) so that:

```
...
[backend]
  datastore = "plugin"
  plugin = "bin/pam.so"
...
```

When building this plugin, one must first ensure that the proper development headers are installed. For instance, on Ubuntu:
```
sudo apt-get install libpam0g-dev
```

You will likely also wish to tweak the `groupWithSearchCapability` setting, to assign an appropriate secondary group.

Then, to perform a search:
```
ldapsearch -LLL -H ldap://localhost:3893 -D cn=<unix user name>,ou=<a group the user belongs to>,dc=glauth,dc=com -w <unix user password> -x -bdc=glauth,dc=com  cn=<unix user name>
```
