package handler

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cespare/xxhash"
	"github.com/glauth/ldap"
)

// bytesPool for reusing buffer allocations
var bytesPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// Benchmark data setup
func createTestServers(count int) []ldapBackend {
	servers := make([]ldapBackend, count)
	for i := 0; i < count; i++ {
		servers[i] = ldapBackend{
			Scheme:   "ldaps",
			Hostname: fmt.Sprintf("server-%d.example.com", i),
			Port:     636 + i,
			Status:   Up,
			Ping:     time.Duration(i*10) * time.Millisecond,
		}
	}
	return servers
}

// Current implementation using FNV
func computeServerHashFNV(servers []ldapBackend) uint64 {
	hash := fnv.New64a()
	for _, server := range servers {
		fmt.Fprintf(hash, "%s:%d:%d:%d", server.Hostname, server.Port, server.Status, server.Ping)
	}
	return hash.Sum64()
}

// Alternative implementation using xxhash
func computeServerHashXXHash(servers []ldapBackend) uint64 {
	hash := xxhash.New()
	for _, server := range servers {
		fmt.Fprintf(hash, "%s:%d:%d:%d", server.Hostname, server.Port, server.Status, server.Ping)
	}
	return hash.Sum64()
}

// Optimized xxhash implementation with bytes pool
func computeServerHashXXHashOptimized(servers []ldapBackend) uint64 {
	buf := bytesPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bytesPool.Put(buf)
	}()

	for _, server := range servers {
		fmt.Fprintf(buf, "%s:%d:%d:%d", server.Hostname, server.Port, server.Status, server.Ping)
	}
	return xxhash.Sum64String(buf.String())
}

// Benchmark FNV hash with different server counts
func BenchmarkComputeServerHashFNV_1Server(b *testing.B) {
	servers := createTestServers(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeServerHashFNV(servers)
	}
}

func BenchmarkComputeServerHashFNV_5Servers(b *testing.B) {
	servers := createTestServers(5)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeServerHashFNV(servers)
	}
}

func BenchmarkComputeServerHashFNV_10Servers(b *testing.B) {
	servers := createTestServers(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeServerHashFNV(servers)
	}
}

func BenchmarkComputeServerHashFNV_50Servers(b *testing.B) {
	servers := createTestServers(50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeServerHashFNV(servers)
	}
}

// Benchmark xxhash with different server counts
func BenchmarkComputeServerHashXXHash_1Server(b *testing.B) {
	servers := createTestServers(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeServerHashXXHash(servers)
	}
}

func BenchmarkComputeServerHashXXHash_5Servers(b *testing.B) {
	servers := createTestServers(5)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeServerHashXXHash(servers)
	}
}

func BenchmarkComputeServerHashXXHash_10Servers(b *testing.B) {
	servers := createTestServers(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeServerHashXXHash(servers)
	}
}

func BenchmarkComputeServerHashXXHash_50Servers(b *testing.B) {
	servers := createTestServers(50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeServerHashXXHash(servers)
	}
}

// Benchmark optimized xxhash with different server counts
func BenchmarkComputeServerHashXXHashOptimized_1Server(b *testing.B) {
	servers := createTestServers(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeServerHashXXHashOptimized(servers)
	}
}

func BenchmarkComputeServerHashXXHashOptimized_5Servers(b *testing.B) {
	servers := createTestServers(5)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeServerHashXXHashOptimized(servers)
	}
}

func BenchmarkComputeServerHashXXHashOptimized_10Servers(b *testing.B) {
	servers := createTestServers(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeServerHashXXHashOptimized(servers)
	}
}

func BenchmarkComputeServerHashXXHashOptimized_50Servers(b *testing.B) {
	servers := createTestServers(50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeServerHashXXHashOptimized(servers)
	}
}

// Benchmark comparison with mixed server states
func BenchmarkComputeServerHashMixedStates(b *testing.B) {
	servers := []ldapBackend{
		{Scheme: "ldaps", Hostname: "server1.example.com", Port: 636, Status: Up, Ping: 10 * time.Millisecond},
		{Scheme: "ldap", Hostname: "server2.example.com", Port: 389, Status: Down, Ping: 0},
		{Scheme: "ldaps", Hostname: "server3.example.com", Port: 636, Status: Up, Ping: 25 * time.Millisecond},
		{Scheme: "ldap", Hostname: "server4.example.com", Port: 389, Status: Down, Ping: 0},
		{Scheme: "ldaps", Hostname: "server5.example.com", Port: 636, Status: Up, Ping: 15 * time.Millisecond},
	}

	b.Run("FNV", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			computeServerHashFNV(servers)
		}
	})

	b.Run("XXHash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			computeServerHashXXHash(servers)
		}
	})

	b.Run("XXHashOptimized", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			computeServerHashXXHashOptimized(servers)
		}
	})
}

// Test to ensure all implementations produce the same hash for identical input
func TestHashConsistency(t *testing.T) {
	servers := createTestServers(3)

	fnvHash := computeServerHashFNV(servers)
	xxHash := computeServerHashXXHash(servers)
	xxHashOpt := computeServerHashXXHashOptimized(servers)

	// Note: FNV and xxhash will produce different hash values for the same input
	// This is expected as they are different hash algorithms
	t.Logf("FNV hash: %d", fnvHash)
	t.Logf("XXHash: %d", xxHash)
	t.Logf("XXHash Optimized: %d", xxHashOpt)

	// Test that each algorithm produces consistent results
	fnvHash2 := computeServerHashFNV(servers)
	xxHash2 := computeServerHashXXHash(servers)
	xxHashOpt2 := computeServerHashXXHashOptimized(servers)

	if fnvHash != fnvHash2 {
		t.Errorf("FNV hash not consistent: %d != %d", fnvHash, fnvHash2)
	}
	if xxHash != xxHash2 {
		t.Errorf("XXHash not consistent: %d != %d", xxHash, xxHash2)
	}
	if xxHashOpt != xxHashOpt2 {
		t.Errorf("XXHash Optimized not consistent: %d != %d", xxHashOpt, xxHashOpt2)
	}
}

// Benchmark memory allocation
func BenchmarkHashMemoryAllocation(b *testing.B) {
	servers := createTestServers(10)

	b.Run("FNV", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			computeServerHashFNV(servers)
		}
	})

	b.Run("XXHash", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			computeServerHashXXHash(servers)
		}
	})

	b.Run("XXHashOptimized", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			computeServerHashXXHashOptimized(servers)
		}
	})
}

// Benchmark server key construction methods
func BenchmarkServerKeyConstruction(b *testing.B) {
	server := ldapBackend{
		Scheme:   "ldaps",
		Hostname: "example-server.com",
		Port:     636,
		Status:   Up,
		Ping:     time.Duration(10) * time.Millisecond,
	}

	b.Run("fmt.Sprintf", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			serverKey := fmt.Sprintf("%s:%d", server.Hostname, server.Port)
			_ = serverKey
		}
	})

	b.Run("strings.Builder", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var sb strings.Builder
			sb.WriteString(server.Hostname)
			sb.WriteString(":")
			sb.WriteString(strconv.Itoa(server.Port))
			serverKey := sb.String()
			_ = serverKey
		}
	})

	b.Run("strings.Builder_Preallocated", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var sb strings.Builder
			// Pre-allocate capacity for hostname + ":" + port (max 5 digits)
			sb.Grow(len(server.Hostname) + 1 + 5)
			sb.WriteString(server.Hostname)
			sb.WriteString(":")
			sb.WriteString(strconv.Itoa(server.Port))
			serverKey := sb.String()
			_ = serverKey
		}
	})

	b.Run("strings.Join", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			serverKey := strings.Join([]string{server.Hostname, strconv.Itoa(server.Port)}, ":")
			_ = serverKey
		}
	})
}

// Benchmark with different hostname lengths
func BenchmarkServerKeyConstruction_VariableLength(b *testing.B) {
	testCases := []struct {
		name     string
		hostname string
		port     int
	}{
		{"short", "srv", 389},
		{"medium", "example-server.com", 636},
		{"long", "very-long-server-name-in-production-environment.example.com", 1636},
	}

	for _, tc := range testCases {
		server := ldapBackend{
			Scheme:   "ldaps",
			Hostname: tc.hostname,
			Port:     tc.port,
			Status:   Up,
			Ping:     time.Duration(10) * time.Millisecond,
		}

		b.Run(fmt.Sprintf("fmt.Sprintf_%s", tc.name), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				serverKey := fmt.Sprintf("%s:%d", server.Hostname, server.Port)
				_ = serverKey
			}
		})

		b.Run(fmt.Sprintf("strings.Builder_%s", tc.name), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var sb strings.Builder
				sb.Grow(len(server.Hostname) + 1 + 5)
				sb.WriteString(server.Hostname)
				sb.WriteString(":")
				sb.WriteString(strconv.Itoa(server.Port))
				serverKey := sb.String()
				_ = serverKey
			}
		})
	}
}

// Benchmark slice allocation methods
func BenchmarkSliceAllocation(b *testing.B) {
	b.Run("Unoptimized_EmptySlice", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			entries := []*ldap.Entry{}
			attrs := []*ldap.EntryAttribute{}
			_ = entries
			_ = attrs
		}
	})

	b.Run("Optimized_Preallocated", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			entries := make([]*ldap.Entry, 0, 100)
			attrs := make([]*ldap.EntryAttribute, 0, 20)
			_ = entries
			_ = attrs
		}
	})

	b.Run("Optimized_ExactSize", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			entries := make([]*ldap.Entry, 0, 50)
			attrs := make([]*ldap.EntryAttribute, 0, 10)
			_ = entries
			_ = attrs
		}
	})
}

// Benchmark slice operations with different sizes
func BenchmarkSliceOperations(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Unoptimized_Size%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				entries := []*ldap.Entry{}
				for j := 0; j < size; j++ {
					entries = append(entries, &ldap.Entry{})
				}
				_ = entries
			}
		})

		b.Run(fmt.Sprintf("Optimized_Size%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				entries := make([]*ldap.Entry, 0, size)
				for j := 0; j < size; j++ {
					entries = append(entries, &ldap.Entry{})
				}
				_ = entries
			}
		})
	}
}
