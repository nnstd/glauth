# Note: to make a plugin compatible with a binary built in debug mode, add `-gcflags='all=-N -l'`

PLUGIN_OS ?= linux
PLUGIN_ARCH ?= amd64

plugin_mysql: bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/mysql.so

bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/mysql.so: pkg/plugins/glauth-mysql/mysql.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^

plugin_mysql_linux_amd64:
	PLUGIN_OS=linux PLUGIN_ARCH=amd64 make plugin_mysql

plugin_mysql_linux_arm64:
	PLUGIN_OS=linux PLUGIN_ARCH=arm64 make plugin_mysql

plugin_mysql_darwin_amd64:
	PLUGIN_OS=darwin PLUGIN_ARCH=amd64 make plugin_mysql

plugin_mysql_darwin_arm64:
	PLUGIN_OS=darwin PLUGIN_ARCH=arm64 make plugin_mysql

release-glauth-mysql:
	@P=mysql M=pkg/plugins/glauth-mysql make releaseplugin
