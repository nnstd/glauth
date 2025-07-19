package stats

import (
	"expvar"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// Counter represents a thread-safe counter that can be reset
type Counter struct {
	value int64
	mu    sync.RWMutex
}

// Add increments the counter by the given value
func (c *Counter) Add(delta int64) {
	atomic.AddInt64(&c.value, delta)
}

// Get returns the current value of the counter
func (c *Counter) Get() int64 {
	return atomic.LoadInt64(&c.value)
}

// Reset sets the counter to 0 and returns the previous value
func (c *Counter) Reset() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	oldValue := atomic.LoadInt64(&c.value)
	atomic.StoreInt64(&c.value, 0)
	return oldValue
}

// String implements the expvar.Var interface
func (c *Counter) String() string {
	return fmt.Sprintf("%d", c.Get())
}

// ResettableMap is a thread-safe map of counters that can be reset
type ResettableMap struct {
	counters     map[string]*Counter
	stringValues map[string]string
	mu           sync.RWMutex
}

// NewResettableMap creates a new ResettableMap
func NewResettableMap() *ResettableMap {
	return &ResettableMap{
		counters:     make(map[string]*Counter),
		stringValues: make(map[string]string),
	}
}

// Add increments a counter by the given value, creating it if it doesn't exist
func (rm *ResettableMap) Add(key string, delta int64) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if counter, exists := rm.counters[key]; exists {
		counter.Add(delta)
	} else {
		counter = &Counter{}
		counter.Add(delta)
		rm.counters[key] = counter
	}
}

// Set sets a counter to a specific value, creating it if it doesn't exist
func (rm *ResettableMap) Set(key string, value interface{}) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// For string values, we'll store them as a special counter type
	// This maintains compatibility with the existing expvar.Set usage
	if strValue, ok := value.(string); ok {
		// Store string values separately
		rm.stringValues[key] = strValue
		return
	}

	// For numeric values, use the counter
	if intValue, ok := value.(int64); ok {
		if counter, exists := rm.counters[key]; exists {
			// Reset and set to new value
			counter.Reset()
			counter.Add(intValue)
		} else {
			counter = &Counter{}
			counter.Add(intValue)
			rm.counters[key] = counter
		}
	}
}

// Get returns the current value of a counter
func (rm *ResettableMap) Get(key string) int64 {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if counter, exists := rm.counters[key]; exists {
		return counter.Get()
	}
	return 0
}

// ResetAll resets all counters and returns a map of their previous values
func (rm *ResettableMap) ResetAll() map[string]int64 {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	previousValues := make(map[string]int64)
	for key, counter := range rm.counters {
		previousValues[key] = counter.Reset()
	}
	// Clear string values as well
	rm.stringValues = make(map[string]string)
	return previousValues
}

// Reset resets a specific counter and returns its previous value
func (rm *ResettableMap) Reset(key string) int64 {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if counter, exists := rm.counters[key]; exists {
		return counter.Reset()
	}
	return 0
}

// String implements the expvar.Var interface
func (rm *ResettableMap) String() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Pre-allocate buffer with estimated size to avoid multiple allocations
	var buf strings.Builder
	buf.WriteString("{")

	first := true

	// Add counter values
	for key, counter := range rm.counters {
		if !first {
			buf.WriteString(",")
		}

		buf.WriteString(`"`)
		buf.WriteString(key)
		buf.WriteString(`":`)
		buf.WriteString(counter.String())
		first = false
	}

	// Add string values
	for key, strValue := range rm.stringValues {
		if !first {
			buf.WriteString(",")
		}

		buf.WriteString(`"`)
		buf.WriteString(key)
		buf.WriteString(`":"`)
		buf.WriteString(strValue)
		buf.WriteString(`"`)
		first = false
	}

	buf.WriteString("}")
	return buf.String()
}

// exposed expvar variables
var (
	Frontend = NewResettableMap()
	Backend  = NewResettableMap()
	General  = expvar.NewMap("proxy")
)

func init() {
	// Register the resettable maps with expvar
	expvar.Publish("proxy_frontend", Frontend)
	expvar.Publish("proxy_backend", Backend)
}

// ResetAllCounters resets all frontend and backend counters and returns their previous values
func ResetAllCounters() (map[string]int64, map[string]int64) {
	frontendValues := Frontend.ResetAll()
	backendValues := Backend.ResetAll()
	return frontendValues, backendValues
}

// ResetFrontendCounters resets all frontend counters and returns their previous values
func ResetFrontendCounters() map[string]int64 {
	return Frontend.ResetAll()
}

// ResetBackendCounters resets all backend counters and returns their previous values
func ResetBackendCounters() map[string]int64 {
	return Backend.ResetAll()
}
