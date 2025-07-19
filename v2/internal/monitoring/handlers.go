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
}

func (a *API) prometheusHTTP(w http.ResponseWriter, r *http.Request) {
	// Serve Prometheus metrics
	promhttp.Handler().ServeHTTP(w, r)

	// Reset counters after serving metrics
	frontendValues, backendValues := stats.ResetAllCounters()
	a.logger.Debug().Interface("frontend_values", frontendValues).Interface("backend_values", backendValues).Msg("Counters reset after Prometheus scrape")
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

func NewAPI(logger zerolog.Logger) *API {
	a := new(API)

	a.logger = logger

	return a
}
