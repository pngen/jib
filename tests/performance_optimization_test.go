package tests

import (
	"fmt"
	"testing"

	"github.com/pngen/jib/core"
)

func TestLRUCache(t *testing.T) {
	cache := core.NewLRUCache(3)

	// Add items
	cache.Put("key1", "value1")
	cache.Put("key2", "value2")
	cache.Put("key3", "value3")

	// Check retrieval
	if cache.Get("key1") != "value1" {
		t.Error("Should retrieve key1")
	}
	if cache.Get("key2") != "value2" {
		t.Error("Should retrieve key2")
	}
	if cache.Get("key3") != "value3" {
		t.Error("Should retrieve key3")
	}

	// Add one more - should evict oldest (key1)
	cache.Put("key4", "value4")

	// key1 should be gone
	if cache.Get("key1") != nil {
		t.Error("key1 should have been evicted")
	}
	if cache.Get("key2") != "value2" {
		t.Error("Should retrieve key2")
	}
	if cache.Get("key3") != "value3" {
		t.Error("Should retrieve key3")
	}
	if cache.Get("key4") != "value4" {
		t.Error("Should retrieve key4")
	}

	// Check size
	if cache.Size() != 3 {
		t.Error("Cache size should be 3")
	}
}

func TestOptimizedEnforcer(t *testing.T) {
	enforcer := core.NewOptimizedBoundaryEnforcer()

	// Test binding caching
	binding1 := enforcer.BindArtifactToJurisdiction("model-x", "us-ca")
	binding2 := enforcer.BindArtifactToJurisdiction("model-x", "us-ca")

	// Should be same object due to caching
	_ = binding1
	_ = binding2

	// Test cache stats
	stats := enforcer.GetCacheStats()
	if stats["binding_cache_size"] != 1 {
		t.Error("Binding cache size should be 1")
	}
	if stats["proof_cache_size"] != 0 {
		t.Error("Proof cache size should be 0")
	}
}

func TestPerformanceMonitor(t *testing.T) {
	monitor := core.NewPerformanceMonitor()

	// Record operations
	monitor.RecordOperation("check_boundary", 0.005)
	monitor.RecordOperation("check_boundary", 0.003)
	monitor.RecordOperation("bind_artifact", 0.01)

	// Check metrics
	avgBoundary := monitor.GetAverageDuration("check_boundary")
	if avgBoundary < 0.0039 || avgBoundary > 0.0041 {
		t.Error("Average boundary duration should be around 0.004")
	}

	avgBind := monitor.GetAverageDuration("bind_artifact")
	if avgBind < 0.0099 || avgBind > 0.0101 {
		t.Error("Average bind duration should be around 0.01")
	}

	countBoundary := monitor.GetOperationCount("check_boundary")
	if countBoundary != 2 {
		t.Error("Should have 2 check boundary operations")
	}
}

func TestBatchOperations(t *testing.T) {
	enforcer := core.NewOptimizedBoundaryEnforcer()

	// Register some test data
	jurisdiction := map[string]interface{}{
		"id":   "us-ca",
		"name": "California",
	}
	domain := map[string]interface{}{
		"id":             "prod-us-west",
		"jurisdiction_id": "us-ca",
	}

	enforcer.RegisterJurisdiction(jurisdiction)
	enforcer.RegisterExecutionDomain(domain)

	// Create some checks
	checks := [][3]string{
		{"model-x", "prod-us-west", "dev-us-east"},
		{"model-y", "prod-us-west", "dev-us-east"},
		{"model-z", "prod-us-west", "dev-us-east"},
	}

	// Batch check
	results := enforcer.BatchCheckBoundaries(checks)

	if len(results) != 3 {
		t.Error("Should have 3 results")
	}
	for _, result := range results {
		if _, ok := result["artifact_id"]; !ok {
			t.Error("Result should have artifact_id")
		}
		if _, ok := result["source_domain_id"]; !ok {
			t.Error("Result should have source_domain_id")
		}
		if _, ok := result["target_domain_id"]; !ok {
			t.Error("Result should have target_domain_id")
		}
	}
}

func TestCacheEfficiency(t *testing.T) {
	enforcer := core.NewOptimizedBoundaryEnforcer()

	// Add some bindings
	for i := 0; i < 10; i++ {
		enforcer.BindArtifactToJurisdiction(fmt.Sprintf("model-%d", i), "us-ca")
	}

	// Check cache stats
	stats := enforcer.GetCacheStats()
	if stats["binding_cache_size"] > 10 {
		t.Error("Binding cache size should not exceed number of bindings")
	}
}