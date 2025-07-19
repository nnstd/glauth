package monitoring

type MonitorInterface interface {
	SetResponseTimeMetric(map[string]string, float64) error
	SetLDAPMetric(map[string]string, float64) error
}

// StatsData represents the stats data without mutex
type StatsData struct {
	Conns    int
	Binds    int
	Unbinds  int
	Searches int
}

type LDAPServerInterface interface {
	SetStats(bool)
	GetStats() StatsData
}
