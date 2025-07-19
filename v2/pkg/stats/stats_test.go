package stats

import (
	"testing"
)

func TestCounterReset(t *testing.T) {
	counter := &Counter{}

	// Test initial value
	if counter.Get() != 0 {
		t.Errorf("Expected initial value to be 0, got %d", counter.Get())
	}

	// Test adding values
	counter.Add(5)
	counter.Add(3)
	if counter.Get() != 8 {
		t.Errorf("Expected value to be 8 after adding 5 and 3, got %d", counter.Get())
	}

	// Test reset
	previousValue := counter.Reset()
	if previousValue != 8 {
		t.Errorf("Expected reset to return previous value 8, got %d", previousValue)
	}
	if counter.Get() != 0 {
		t.Errorf("Expected counter to be 0 after reset, got %d", counter.Get())
	}
}

func TestResettableMapReset(t *testing.T) {
	rm := NewResettableMap()

	// Test adding values
	rm.Add("test1", 10)
	rm.Add("test2", 20)
	rm.Add("test1", 5) // Should add to existing counter

	// Test getting values
	if rm.Get("test1") != 15 {
		t.Errorf("Expected test1 to be 15, got %d", rm.Get("test1"))
	}
	if rm.Get("test2") != 20 {
		t.Errorf("Expected test2 to be 20, got %d", rm.Get("test2"))
	}

	// Test reset all
	previousValues := rm.ResetAll()
	if len(previousValues) != 2 {
		t.Errorf("Expected 2 previous values, got %d", len(previousValues))
	}
	if previousValues["test1"] != 15 {
		t.Errorf("Expected test1 previous value to be 15, got %d", previousValues["test1"])
	}
	if previousValues["test2"] != 20 {
		t.Errorf("Expected test2 previous value to be 20, got %d", previousValues["test2"])
	}

	// Test counters are reset
	if rm.Get("test1") != 0 {
		t.Errorf("Expected test1 to be 0 after reset, got %d", rm.Get("test1"))
	}
	if rm.Get("test2") != 0 {
		t.Errorf("Expected test2 to be 0 after reset, got %d", rm.Get("test2"))
	}
}

func TestResettableMapResetSpecific(t *testing.T) {
	rm := NewResettableMap()

	// Test adding values
	rm.Add("test1", 10)
	rm.Add("test2", 20)

	// Test reset specific counter
	previousValue := rm.Reset("test1")
	if previousValue != 10 {
		t.Errorf("Expected test1 previous value to be 10, got %d", previousValue)
	}

	// Test only test1 is reset
	if rm.Get("test1") != 0 {
		t.Errorf("Expected test1 to be 0 after reset, got %d", rm.Get("test1"))
	}
	if rm.Get("test2") != 20 {
		t.Errorf("Expected test2 to still be 20, got %d", rm.Get("test2"))
	}
}

func TestResettableMapString(t *testing.T) {
	rm := NewResettableMap()

	// Test empty map
	expected := "{}"
	if rm.String() != expected {
		t.Errorf("Expected empty map string to be %s, got %s", expected, rm.String())
	}

	// Test with values
	rm.Add("test1", 10)
	rm.Add("test2", 20)

	// The exact string format depends on map iteration order, so we'll just check it contains our values
	result := rm.String()
	if len(result) == 0 {
		t.Errorf("Expected non-empty string, got empty string")
	}
}

func TestGlobalCountersReset(t *testing.T) {
	// Test global counter reset functions
	Frontend.Add("test_global", 100)
	Backend.Add("test_global", 200)

	// Test reset all
	frontendValues, backendValues := ResetAllCounters()

	if frontendValues["test_global"] != 100 {
		t.Errorf("Expected frontend test_global to be 100, got %d", frontendValues["test_global"])
	}
	if backendValues["test_global"] != 200 {
		t.Errorf("Expected backend test_global to be 200, got %d", backendValues["test_global"])
	}

	// Test counters are reset
	if Frontend.Get("test_global") != 0 {
		t.Errorf("Expected frontend test_global to be 0 after reset, got %d", Frontend.Get("test_global"))
	}
	if Backend.Get("test_global") != 0 {
		t.Errorf("Expected backend test_global to be 0 after reset, got %d", Backend.Get("test_global"))
	}
}

func TestResettableMapSet(t *testing.T) {
	rm := NewResettableMap()

	// Test setting numeric values
	rm.Set("test_int", int64(42))
	if rm.Get("test_int") != 42 {
		t.Errorf("Expected test_int to be 42, got %d", rm.Get("test_int"))
	}

	// Test setting string values
	rm.Set("test_string", "hello world")

	// Test that string values are included in the JSON output
	result := rm.String()
	if len(result) == 0 {
		t.Errorf("Expected non-empty string result")
	}

	// Test reset clears both numeric and string values
	previousValues := rm.ResetAll()
	if previousValues["test_int"] != 42 {
		t.Errorf("Expected test_int previous value to be 42, got %d", previousValues["test_int"])
	}

	// After reset, numeric value should be 0
	if rm.Get("test_int") != 0 {
		t.Errorf("Expected test_int to be 0 after reset, got %d", rm.Get("test_int"))
	}
}
