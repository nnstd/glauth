package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/arl/statsviz"
	"github.com/fsnotify/fsnotify"
	"github.com/jinzhu/copier"
	"github.com/nnstd/glauth/v2/internal/monitoring"
	_tls "github.com/nnstd/glauth/v2/internal/tls"
	"github.com/nnstd/glauth/v2/internal/toml"
	"github.com/nnstd/glauth/v2/internal/tracing"
	"github.com/nnstd/glauth/v2/internal/version"
	"github.com/nnstd/glauth/v2/pkg/config"
	"github.com/nnstd/glauth/v2/pkg/frontend"
	"github.com/nnstd/glauth/v2/pkg/logging"
	"github.com/nnstd/glauth/v2/pkg/server"
	"github.com/nnstd/glauth/v2/pkg/stats"

	"github.com/alecthomas/kong"
	"github.com/rs/zerolog"
)

// CLI represents the command-line interface structure
type CLI struct {
	// Global flags
	Config       string `short:"c" type:"path" help:"Config file or S3 URL."`
	AWSKeyID     string `short:"K" help:"AWS Key ID for S3 config access."`
	AWSSecretKey string `short:"S" help:"AWS Secret Key for S3 config access."`
	AWSRegion    string `short:"r" default:"us-east-1" help:"AWS Region."`
	AWSEndpoint  string `help:"Custom S3 endpoint URL." name:"aws_endpoint_url"`

	// Server addresses
	LDAP      string `help:"Listen address for the LDAP server." name:"ldap"`
	LDAPS     string `help:"Listen address for the LDAPS server." name:"ldaps"`
	LDAPSCert string `help:"Path to cert file for the LDAPS server." name:"ldaps-cert" type:"path"`
	LDAPSKey  string `help:"Path to key file for the LDAPS server." name:"ldaps-key" type:"path"`

	// Commands
	Run         RunCmd         `cmd:"" help:"Start the LDAP server (default)." default:"1"`
	CheckConfig CheckConfigCmd `cmd:"" help:"Check configuration file and exit."`
	Version     VersionCmd     `cmd:"" help:"Show version information."`
}

// RunCmd represents the main server run command
type RunCmd struct{}

// Run executes the main server command
func (c *RunCmd) Run(cliCtx *CLI) error {
	if cliCtx.Config == "" {
		return fmt.Errorf("config file is required to run the server (use -c/--config)")
	}

	cfg, err := toml.NewConfig(false, cliCtx.Config, convertCLIToArgs(cliCtx))
	if err != nil {
		return fmt.Errorf("configuration file error: %w", err)
	}

	if err := copier.Copy(activeConfig, cfg); err != nil {
		log.Info().Err(err).Msg("Could not save reloaded config. Holding on to old config")
	}

	log = logging.InitLogging(activeConfig.Debug, activeConfig.Syslog, activeConfig.StructuredLog)

	if cfg.Debug {
		log.Info().Msg("Debugging enabled")
	}
	if cfg.Syslog {
		log.Info().Msg("Syslog enabled")
	}

	log.Info().Msg("AP start")

	startService()
	return nil
}

// CheckConfigCmd represents the check-config command
type CheckConfigCmd struct{}

// Run executes the check-config command
func (c *CheckConfigCmd) Run(cliCtx *CLI) error {
	if cliCtx.Config == "" {
		return fmt.Errorf("config file is required for check-config command")
	}
	cfg, err := toml.NewConfig(true, cliCtx.Config, convertCLIToArgs(cliCtx))
	if err != nil {
		return fmt.Errorf("configuration file error: %w", err)
	}
	_ = cfg // cfg is validated during creation
	fmt.Println("Config file seems ok (but I am not checking much at this time)")
	return nil
}

// VersionCmd represents the version command
type VersionCmd struct{}

// Run executes the version command
func (c *VersionCmd) Run() error {
	fmt.Println(version.GetVersion())
	return nil
}

// convertCLIToArgs converts the Kong CLI struct to the args map format expected by toml.NewConfig
func convertCLIToArgs(cli *CLI) map[string]interface{} {
	args := make(map[string]interface{})

	args["--config"] = cli.Config
	if cli.AWSKeyID != "" {
		args["-K"] = cli.AWSKeyID
	}
	if cli.AWSSecretKey != "" {
		args["-S"] = cli.AWSSecretKey
	}
	if cli.AWSRegion != "" {
		args["-r"] = cli.AWSRegion
	}
	if cli.AWSEndpoint != "" {
		args["--aws_endpoint_url"] = cli.AWSEndpoint
	}
	if cli.LDAP != "" {
		args["--ldap"] = cli.LDAP
	}
	if cli.LDAPS != "" {
		args["--ldaps"] = cli.LDAPS
	}
	if cli.LDAPSCert != "" {
		args["--ldaps-cert"] = cli.LDAPSCert
	}
	if cli.LDAPSKey != "" {
		args["--ldaps-key"] = cli.LDAPSKey
	}

	return args
}

var (
	log zerolog.Logger
	cli CLI

	activeConfig = &config.Config{}
)

func main() {
	ctx := kong.Parse(&cli,
		kong.Name("glauth"),
		kong.Description("securely expose your LDAP for external auth"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
	)

	// Execute the parsed command
	err := ctx.Run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func startService() {
	// stats
	stats.General.Set("version", stats.Stringer(version.Version))

	// web API
	if activeConfig.API.Enabled {
		log.Info().Msg("Web API enabled")

		if activeConfig.API.Internals {
			statsviz.Register(
				http.DefaultServeMux,
				statsviz.Root("/internals"),
				statsviz.SendFrequency(1000*time.Millisecond),
			)
		}

		go frontend.RunAPI(
			frontend.Logger(log),
			frontend.Config(&activeConfig.API),
		)
	}

	monitor := monitoring.NewMonitor(&log)
	tracer := tracing.NewTracer(
		tracing.NewConfig(
			activeConfig.Tracing.Enabled,
			activeConfig.Tracing.GRPCEndpoint,
			activeConfig.Tracing.HTTPEndpoint,
			&log,
		),
	)

	startConfigWatcher()

	var err error
	var tlsConfig *tls.Config
	if c := activeConfig.LDAP; c.Enabled && c.TLS {
		// TODO check if tls params are string or bytes and change config accordingly
		tlsConfig, err = _tls.MakeTLS([]byte(c.TLSCert), []byte(c.TLSKey))

		if err != nil {
			log.Warn().Err(err).Msg("unable to configure TLS, proceeding without....StartTLS won't be supported")
		}
	}

	s, err := server.NewServer(
		server.Logger(log),
		server.Config(activeConfig),
		server.TLSConfig(tlsConfig),
		server.Monitor(monitor),
		server.Tracer(tracer),
	)

	if err != nil {
		log.Error().Err(err).Msg("could not create server")
		os.Exit(1)
	}

	if activeConfig.LDAP.Enabled {
		go func() {
			if err := s.ListenAndServe(); err != nil {
				log.Error().Err(err).Msg("could not start LDAP server")
				os.Exit(1)
			}
		}()
	}

	if activeConfig.LDAPS.Enabled {
		go func() {
			if err := s.ListenAndServeTLS(); err != nil {
				log.Error().Err(err).Msg("could not start LDAPS server")
				os.Exit(1)
			}
		}()
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Block until we receive our signal.
	<-c

	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	s.Shutdown()

	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	log.Info().Msg("AP exit")
	os.Exit(0)
}

func startConfigWatcher() {
	configFileLocation := cli.Config
	if !activeConfig.WatchConfig || strings.HasPrefix(configFileLocation, "s3://") {
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error().Err(err).Msg("could not start config-watcher")
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	go func() {
		isChanged, isRemoved := false, false
		for {
			select {
			case event := <-watcher.Events:
				log.Info().Str("e", event.Op.String()).Msg("watcher got event")

				if event.Op&fsnotify.Write == fsnotify.Write {
					isChanged = true
				} else if event.Op&fsnotify.Remove == fsnotify.Remove { // vim edit file with rename/remove
					isChanged, isRemoved = true, true
				} else if event.Op&fsnotify.Create == fsnotify.Create { // only when watching a directory
					isChanged = true
				}
			case err := <-watcher.Errors:
				log.Error().Err(err).Msg("watcher error")
			case <-ticker.C:
				// wakeup, try finding removed config
			}

			if _, err := os.Stat(configFileLocation); !os.IsNotExist(err) && (isRemoved || isChanged) {
				if isRemoved {
					log.Info().Str("file", configFileLocation).Msg("rewatching config")
					watcher.Add(configFileLocation) // overwrite
					isChanged, isRemoved = true, false
				}
				
				if isChanged {
					cfg, err := toml.NewConfig(false, configFileLocation, convertCLIToArgs(&cli))
					if err != nil {
						log.Info().Err(err).Msg("Could not reload config. Holding on to old config")
					} else {
						log.Info().Msg("Config was reloaded")

						if err := copier.Copy(activeConfig, cfg); err != nil {
							log.Info().Err(err).Msg("Could not save reloaded config. Holding on to old config")
						}
					}
					isChanged = false
				}
			}
		}
	}()

	watcher.Add(configFileLocation)
}
