package monitoring

import (
	"github.com/glauth/ldap"
)

// LDAPServerAdapter wraps ldap.Server to implement LDAPServerInterface
// without copying mutexes in the Stats struct
type LDAPServerAdapter struct {
	server *ldap.Server
}

// NewLDAPServerAdapter creates a new adapter for ldap.Server
func NewLDAPServerAdapter(server *ldap.Server) *LDAPServerAdapter {
	return &LDAPServerAdapter{server: server}
}

// SetStats implements LDAPServerInterface.SetStats
func (a *LDAPServerAdapter) SetStats(enabled bool) {
	a.server.SetStats(enabled)
}

// GetStats implements LDAPServerInterface.GetStats
// Returns stats data without the mutex to avoid copying issues
func (a *LDAPServerAdapter) GetStats() StatsData {
	stats := a.server.GetStats()
	// Create a new stats struct with the same values but without the mutex
	return StatsData{
		Conns:    stats.Conns,
		Binds:    stats.Binds,
		Unbinds:  stats.Unbinds,
		Searches: stats.Searches,
	}
}
