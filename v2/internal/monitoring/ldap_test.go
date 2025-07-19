package monitoring

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.uber.org/mock/gomock"
)

//go:generate mockgen -build_flags=--mod=mod -package monitoring -destination ./mock_interfaces.go -source=./interfaces.go

func TestNewLDAPMonitorWatcherRunsOnASchedule(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockMonitor := NewMockMonitorInterface(ctrl)
	mockLDAPServer := NewMockLDAPServerInterface(ctrl)

	// Create a stats struct without the mutex to avoid copying issues
	stats := StatsData{
		Conns:    0,
		Binds:    0,
		Unbinds:  0,
		Searches: 0,
	}

	mockLDAPServer.EXPECT().SetStats(true).Times(1)
	mockLDAPServer.EXPECT().GetStats().MinTimes(1).Return(stats)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "conns"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "binds"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "unbinds"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "searches"}, float64(0)).MinTimes(1)

	// Expect custom metrics (these will be 0 initially since counters start at 0)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "bind_requests"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "bind_successes"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "bind_failures"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "bind_errors"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "search_requests"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "search_successes"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "search_failures"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "search_errors"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "closes"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "backend_closes"}, float64(0)).MinTimes(1)

	logger := zerolog.Nop()
	m := NewLDAPMonitorWatcher(mockLDAPServer, mockMonitor, &logger)

	m.syncTicker = time.NewTicker(5 * time.Microsecond)

	// allow goroutine to start and ticker to tick
	time.Sleep(10 * time.Millisecond)
}
