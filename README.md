# GLAuth
Go-lang LDAP Authentication (GLAuth) is a secure, easy-to-use, LDAP server w/ configurable backends.

* Centrally manage accounts across your infrastructure
* Centrally manage SSH keys, Linux accounts, and passwords for cloud servers.
* Lightweight alternative to OpenLDAP and Active Directory for development, or a homelab.
* Store your user directory in a file, local or in S3; SQL database; or proxy to existing LDAP servers.
* Two Factor Authentication (transparent to applications)
* Multiple backends can be chained to inject features

Use it to centralize account management across your Linux servers, your OSX machines, and your support applications (Jenkins, Apache/Nginx, Graylog2, and many more!).

### What changed?

- [x] Improved performance for SQL backends.
- [x] Embed plugins in single binary.
- [x] Store plugins in single repository.
- [x] Moved from [docopt](https://github.com/docopt/docopt-go) to [kong](https://github.com/alecthomas/kong) in CLI.
- [x] Bumped Go and dependencies versions.
- [x] Added binary distribution for various architectures of Linux, MacOS and Windows.

### Quickstart
This quickstart is a great way to try out GLAuth in a non-production environment.  *Be warned that you should take the extra steps to setup SSL (TLS) for production use!*

1. Download a precompiled binary from the [releases](https://github.com/nnstd/glauth/releases) page.
2. Download the [example config file](https://github.com/nnstd/glauth/blob/master/examples/sample-simple.cfg).
3. Start the GLAuth server, referencing the path to the desired config file with `-c`.
   - `./glauth64 -c sample-simple.cfg`
4. Test with traditional LDAP tools
   - For example: `ldapsearch -LLL -H ldap://localhost:3893 -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com -w mysecret -x -bdc=glauth,dc=com cn=hackers`

### Kubernetes and Helm
You can use [Helm chart](https://github.com/nnstd/helm-glauth). It has:

- [x] Support of [PostgresOperator](https://github.com/movetokube/postgres-operator) for database creation and secret management.

and more.

### Make Commands

Note - makefile uses git data to inject build-time variables. For best results, run in the context of the git repo.

### Documentation

The original version of GLauth's documentation is available at https://glauth.github.io/

<hr>

### Quickstart

Get started in three short [steps](https://glauth.github.io/docs/quickstart.html)

### Usage:
```
glauth: securely expose your LDAP for external auth

Usage:
  glauth [options] -c <file|s3url>
  glauth -h --help
  glauth --version

Options:
  -c, --config <file>       Config file.
  -K <aws_key_id>           AWS Key ID.
  -S <aws_secret_key>       AWS Secret Key.
  -r <aws_region>           AWS Region [default: us-east-1].
  --ldap <address>          Listen address for the LDAP server.
  --ldaps <address>         Listen address for the LDAPS server.
  --ldaps-cert <cert-file>  Path to cert file for the LDAPS server.
  --ldaps-key <key-file>    Path to key file for the LDAPS server.
  -h, --help                Show this screen.
  --version                 Show version.
```

### Configuration:
GLAuth can be deployed as a single server using only a local configuration file.  This is great for testing, or for production if you use a tool like Puppet/Chef/Ansible:
```unix
glauth -c glauth.cfg
```
Here's a sample config wth hardcoded users and groups:
```toml
[backend]
  datastore = "config"
  baseDN = "dc=glauth,dc=com"
[[users]]
  name = "hackers"
  uidnumber = 5001
  primarygroup = 5501
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a"   # dogood
  sshkeys = [ "ssh-dss AAAAB3..." ]
[[users]]
  name = "uberhackers"
  uidnumber = 5006
  primarygroup = 5501
  passbcrypt = "243261243130244B62463462656F7265504F762E794F324957746D656541326B4B46596275674A79336A476845764B616D65446169784E41384F4432"   # dogood
[[groups]]
  name = "superheros"
  gidnumber = 5501
```

More configuration options are documented [here](https://glauth.github.io/docs/file.html) and in this [sample file](https://github.com/glauth/glauth/blob/master/v2/sample-simple.cfg)

### Backends:

GLAuth can use a local file, S3 or an existing LDAP infrastructure and also supports SQL databases.

- [x] Config file
- [x] S3
- [x] Postgres
- [x] MySQL
- [x] SQLite
- [x] LDAP
- [x] PAM

```toml
[backend]
  datastore = "ldap"
  servers = [ "ldaps://server1:636", "ldaps://server2:636" ]
```

### Contributing
For more information, see [CONTRIBUTING.md](CONTRIBUTING.md).

### License

GLAuth is licensed under the [GNU Affero General Public License v3.0](https://github.com/nnstd/glauth/blob/master/LICENSE) and as commercial software. For commercial licensing, please contact us at sales@nnstd.dev.
