package monitoring

import (
	"time"

	"github.com/nnstd/glauth/v2/pkg/stats"
	"github.com/rs/zerolog"
)

type LDAPMonitorWatcher struct {
	syncTicker *time.Ticker

	ldap LDAPServerInterface

	monitor MonitorInterface
	logger  *zerolog.Logger
}

func (m *LDAPMonitorWatcher) sync() {
	for range m.syncTicker.C {
		m.storeMetrics()
	}
}

func (m *LDAPMonitorWatcher) storeMetrics() {
	// Collect LDAP library stats
	ldapStats := m.ldap.GetStats()

	if err := m.monitor.SetLDAPMetric(map[string]string{"type": "conns"}, float64(ldapStats.Conns)); err != nil {
		m.logger.Error().Err(err).Msg("failed to set metric")
	}

	if err := m.monitor.SetLDAPMetric(map[string]string{"type": "binds"}, float64(ldapStats.Binds)); err != nil {
		m.logger.Error().Err(err).Msg("failed to set metric")
	}

	if err := m.monitor.SetLDAPMetric(map[string]string{"type": "unbinds"}, float64(ldapStats.Unbinds)); err != nil {
		m.logger.Error().Err(err).Msg("failed to set metric")
	}

	if err := m.monitor.SetLDAPMetric(map[string]string{"type": "searches"}, float64(ldapStats.Searches)); err != nil {
		m.logger.Error().Err(err).Msg("failed to set metric")
	}

	keys := []string{
		"bind_reqs", "bind_successes", "bind_failures", "bind_errors",
		"search_reqs", "search_successes", "search_failures", "search_errors",
		"closes",
	}

	// Collect custom authentication and search metrics
	frontendValues := make(map[string]int64)
	for _, key := range keys {
		frontendValues[key] = stats.Frontend.Get(key)
	}

	// Set authentication metrics
	if bindReqs, exists := frontendValues["bind_reqs"]; exists {
		if err := m.monitor.SetLDAPMetric(map[string]string{"type": "bind_requests"}, float64(bindReqs)); err != nil {
			m.logger.Error().Err(err).Msg("failed to set bind_requests metric")
		}
	}

	if bindSuccesses, exists := frontendValues["bind_successes"]; exists {
		if err := m.monitor.SetLDAPMetric(map[string]string{"type": "bind_successes"}, float64(bindSuccesses)); err != nil {
			m.logger.Error().Err(err).Msg("failed to set bind_successes metric")
		}
	}

	if bindFailures, exists := frontendValues["bind_failures"]; exists {
		if err := m.monitor.SetLDAPMetric(map[string]string{"type": "bind_failures"}, float64(bindFailures)); err != nil {
			m.logger.Error().Err(err).Msg("failed to set bind_failures metric")
		}
	}

	if bindErrors, exists := frontendValues["bind_errors"]; exists {
		if err := m.monitor.SetLDAPMetric(map[string]string{"type": "bind_errors"}, float64(bindErrors)); err != nil {
			m.logger.Error().Err(err).Msg("failed to set bind_errors metric")
		}
	}

	// Set search metrics
	if searchReqs, exists := frontendValues["search_reqs"]; exists {
		if err := m.monitor.SetLDAPMetric(map[string]string{"type": "search_requests"}, float64(searchReqs)); err != nil {
			m.logger.Error().Err(err).Msg("failed to set search_requests metric")
		}
	}

	if searchSuccesses, exists := frontendValues["search_successes"]; exists {
		if err := m.monitor.SetLDAPMetric(map[string]string{"type": "search_successes"}, float64(searchSuccesses)); err != nil {
			m.logger.Error().Err(err).Msg("failed to set search_successes metric")
		}
	}

	if searchFailures, exists := frontendValues["search_failures"]; exists {
		if err := m.monitor.SetLDAPMetric(map[string]string{"type": "search_failures"}, float64(searchFailures)); err != nil {
			m.logger.Error().Err(err).Msg("failed to set search_failures metric")
		}
	}

	if searchErrors, exists := frontendValues["search_errors"]; exists {
		if err := m.monitor.SetLDAPMetric(map[string]string{"type": "search_errors"}, float64(searchErrors)); err != nil {
			m.logger.Error().Err(err).Msg("failed to set search_errors metric")
		}
	}

	// Set other metrics
	if closes, exists := frontendValues["closes"]; exists {
		if err := m.monitor.SetLDAPMetric(map[string]string{"type": "closes"}, float64(closes)); err != nil {
			m.logger.Error().Err(err).Msg("failed to set closes metric")
		}
	}

	// Collect backend metrics
	backendValues := make(map[string]int64)
	backendValues["closes"] = stats.Backend.Get("closes")
	// Add other backend metrics as needed

	for key, value := range backendValues {
		if err := m.monitor.SetLDAPMetric(map[string]string{"type": "backend_" + key}, float64(value)); err != nil {
			m.logger.Error().Err(err).Str("metric", "backend_"+key).Msg("failed to set backend metric")
		}
	}
}

func NewLDAPMonitorWatcher(ldap LDAPServerInterface, monitor MonitorInterface, logger *zerolog.Logger) *LDAPMonitorWatcher {
	m := new(LDAPMonitorWatcher)

	m.syncTicker = time.NewTicker(15 * time.Second)
	m.ldap = ldap
	m.monitor = monitor
	m.logger = logger

	m.ldap.SetStats(true)

	go m.sync()

	return m
}
