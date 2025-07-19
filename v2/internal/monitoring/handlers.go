package monitoring

import (
	"encoding/json"
	"net/http"

	"github.com/nnstd/glauth/v2/pkg/stats"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

type API struct {
	logger zerolog.Logger
}

func (a *API) RegisterEndpoints(router *http.ServeMux) {
	router.HandleFunc("/metrics", a.prometheusHTTP)
	router.HandleFunc("/api/v1/reset-counters", a.resetCountersHTTP)
	router.HandleFunc("/api/v1/collect-metrics", a.collectMetricsHTTP)
}

func (a *API) prometheusHTTP(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}

func (a *API) resetCountersHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Reset all counters and get their previous values
	frontendValues, backendValues := stats.ResetAllCounters()

	// Prepare response
	response := map[string]interface{}{
		"status":          "success",
		"message":         "Counters reset successfully",
		"frontend_values": frontendValues,
		"backend_values":  backendValues,
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Encode and send response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		a.logger.Error().Err(err).Msg("Failed to encode reset counters response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	a.logger.Info().Interface("frontend_values", frontendValues).Interface("backend_values", backendValues).Msg("Counters reset via API")
}

func (a *API) collectMetricsHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get current values without resetting
	frontendValues := make(map[string]int64)
	backendValues := make(map[string]int64)

	// Get frontend values
	for key := range map[string]bool{
		"bind_reqs": true, "bind_successes": true, "bind_failures": true, "bind_errors": true,
		"search_reqs": true, "search_successes": true, "search_failures": true, "search_errors": true,
		"closes": true,
	} {
		frontendValues[key] = stats.Frontend.Get(key)
	}

	// Get backend values (we don't know all keys in advance, so we'll just return what we have)
	// This is a simplified approach - in a real implementation you might want to track all keys
	backendValues["closes"] = stats.Backend.Get("closes")

	// Prepare response
	response := map[string]interface{}{
		"status":          "success",
		"message":         "Metrics collected successfully",
		"frontend_values": frontendValues,
		"backend_values":  backendValues,
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Encode and send response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		a.logger.Error().Err(err).Msg("Failed to encode collect metrics response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	a.logger.Debug().Interface("frontend_values", frontendValues).Interface("backend_values", backendValues).Msg("Metrics collected via API")
}

func NewAPI(logger zerolog.Logger) *API {
	a := new(API)

	a.logger = logger

	return a
}
