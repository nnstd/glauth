package server

import (
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/ldap"
	"github.com/nnstd/glauth/v2/internal/monitoring"
	"github.com/nnstd/glauth/v2/pkg/config"
	"github.com/nnstd/glauth/v2/pkg/database"
	"github.com/nnstd/glauth/v2/pkg/handler"
)

type LdapSvc struct {
	c        *config.Config
	yubiAuth *yubigo.YubiAuth
	l        *ldap.Server

	monitor monitoring.MonitorInterface
	tracer  trace.Tracer
	log     zerolog.Logger
}

func NewServer(opts ...Option) (*LdapSvc, error) {
	options := newOptions(opts...)

	s := LdapSvc{
		log:     options.Logger,
		c:       options.Config,
		monitor: options.Monitor,
		tracer:  options.Tracer,
	}

	var err error

	if len(s.c.YubikeyClientID) > 0 && len(s.c.YubikeySecret) > 0 {
		s.yubiAuth, err = yubigo.NewYubiAuth(s.c.YubikeyClientID, s.c.YubikeySecret)

		if err != nil {
			return nil, errors.New("yubikey auth failed")
		}
	}

	var helper handler.Handler

	loh := handler.NewLDAPOpsHelper(s.tracer)

	// instantiate the helper, if any
	if s.c.Helper.Enabled {
		switch s.c.Helper.Datastore {
		case "config":
			helper = handler.NewConfigHandler(
				handler.Logger(&s.log),
				handler.Config(s.c),
				handler.YubiAuth(s.yubiAuth),
				handler.LDAPHelper(loh),
				handler.Tracer(s.tracer),
			)
		default:
			return nil, fmt.Errorf("unsupported helper '%s' - must be 'config'", s.c.Helper.Datastore)
		}

		s.log.Info().Str("datastore", s.c.Helper.Datastore).Msg("Using helper")
	}

	backendCounter := -1
	allHandlers := handler.HandlerWrapper{Handlers: make([]handler.Handler, 10), Count: &backendCounter}

	// configure the backends
	s.l = ldap.NewServer()
	s.l.EnforceLDAP = true

	if tlsConfig := options.TLSConfig; tlsConfig != nil {
		s.l.TLSConfig = tlsConfig
		s.log.Debug().Interface("tls.certificates", tlsConfig.Certificates).Msg("enabling LDAP over TLS")
	}

	for i, backend := range s.c.Backends {
		var h handler.Handler
		switch backend.Datastore {
		case "ldap":
			h = handler.NewLdapHandler(
				handler.Backend(backend),
				handler.Handlers(allHandlers),
				handler.Logger(&s.log),
				handler.Helper(helper),
				handler.Monitor(s.monitor),
				handler.Tracer(s.tracer),
			)
		case "owncloud":
			h = handler.NewOwnCloudHandler(
				handler.Backend(backend),
				handler.Logger(&s.log),
				handler.Monitor(s.monitor),
				handler.Tracer(s.tracer),
			)
		case "config":
			h = handler.NewConfigHandler(
				handler.Backend(backend),
				handler.Logger(&s.log),
				handler.Config(s.c), // TODO only used to access Users and Groups, move that to dedicated options
				handler.YubiAuth(s.yubiAuth),
				handler.LDAPHelper(loh),
				handler.Monitor(s.monitor),
				handler.Tracer(s.tracer),
			)
		case "database":
			var dbType database.DatabaseType
			if backend.DatabaseType != "" {
				dbType = database.DatabaseType(backend.DatabaseType)
			} else {
				// Auto-detect database type from connection string
				var err error
				dbType, err = database.DetectDatabaseType(backend.Database)
				if err != nil {
					return nil, fmt.Errorf("unable to detect database type from connection string: %s", err)
				}
			}
			h, err = database.NewHandler(dbType,
				handler.Backend(backend),
				handler.Logger(&s.log),
				handler.Config(s.c),
				handler.YubiAuth(s.yubiAuth),
				handler.LDAPHelper(loh),
				handler.Monitor(s.monitor),
				handler.Tracer(s.tracer),
			)
			if err != nil {
				return nil, fmt.Errorf("unable to create database handler: %s", err)
			}
		case "embed":
			h, err = NewEmbed(
				handler.Backend(backend),
				handler.Logger(&s.log),
				handler.Config(s.c),
				handler.YubiAuth(s.yubiAuth),
				handler.LDAPHelper(loh),
				handler.Monitor(s.monitor),
				handler.Tracer(s.tracer),
			)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported backend '%s' - must be one of 'config', 'ldap', 'owncloud', 'database'", backend.Datastore)
		}
		s.log.Info().Str("datastore", backend.Datastore).Int("position", i).Msg("Loading backend")

		// Only our first backend will answer proper LDAP queries.
		// Note that this could evolve towars something nicer where we would maintain
		// multiple binders in addition to the existing multiple LDAP backends
		if i == 0 {
			s.l.BindFunc("", h)
			s.l.SearchFunc("", h)
			s.l.CloseFunc("", h)
		}
		allHandlers.Handlers[i] = h
		backendCounter++
	}

	monitoring.NewLDAPMonitorWatcher(s.l, s.monitor, &s.log)

	return &s, nil
}

// ListenAndServe listens on the TCP network address s.c.LDAP.Listen
func (s *LdapSvc) ListenAndServe() error {
	s.log.Info().Str("address", s.c.LDAP.Listen).Msg("LDAP server listening")
	return s.l.ListenAndServe(s.c.LDAP.Listen)
}

// ListenAndServeTLS listens on the TCP network address s.c.LDAPS.Listen
func (s *LdapSvc) ListenAndServeTLS() error {
	s.log.Info().Str("address", s.c.LDAPS.Listen).Msg("LDAPS server listening")
	return s.l.ListenAndServeTLS(
		s.c.LDAPS.Listen,
		s.c.LDAPS.Cert,
		s.c.LDAPS.Key,
	)
}

// Shutdown ends listeners by sending true to the ldap serves quit channel
func (s *LdapSvc) Shutdown() {
	s.l.Quit <- true
}
