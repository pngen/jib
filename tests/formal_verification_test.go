package tests

import (
	"testing"
	"time"

	"github.com/pngen/jib/core"
)

func TestBoundaryAlgebraComposition(t *testing.T) {
	// Create two boundaries
	b1 := &core.Boundary{
		ID:                   "b1",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-tx",
		Allowed:              true,
		Reason:               "Allowed by policy",
	}

	b2 := &core.Boundary{
		ID:                   "b2",
		SourceJurisdictionID: "us-tx",
		TargetJurisdictionID: "us-nv",
		Allowed:              false,
		Reason:               "Denied by policy",
	}

	// Test composition (simplified)
	ba := &core.BoundaryAlgebra{}
	composed := ba.Compose(b1, b2)

	if composed.ID != "b1:b2" {
		t.Error("Composed ID mismatch")
	}
	if composed.SourceJurisdictionID != "us-ca" {
		t.Error("Source jurisdiction ID mismatch")
	}
	if composed.TargetJurisdictionID != "us-nv" {
		t.Error("Target jurisdiction ID mismatch")
	}
	if composed.Allowed {
		t.Error("Expected allowed to be false (AND of true and false)")
	}
}

func TestTemporalBoundaryValidityFormal(t *testing.T) {
	// Create a boundary with time constraints
	boundary := &core.TemporalBoundary{
		ID:                   "temp-boundary",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-tx",
		Allowed:              true,
		Reason:               "Time-limited access",
		ValidFrom:            int64Ptr(time.Now().Unix() - 3600), // 1 hour ago
		ValidUntil:           int64Ptr(time.Now().Unix() + 3600), // 1 hour from now
	}

	currentTime := time.Now().Unix()

	// Should be valid now
	if !boundary.IsValidAt(currentTime) {
		t.Error("Boundary should be valid now")
	}

	// Test before valid_from
	pastTime := currentTime - 7200 // 2 hours ago
	if boundary.IsValidAt(pastTime) {
		t.Error("Boundary should not be valid before valid_from")
	}

	// Test after valid_until
	futureTime := currentTime + 7200 // 2 hours from now
	if boundary.IsValidAt(futureTime) {
		t.Error("Boundary should not be valid after valid_until")
	}
}

func TestInvariantChecker(t *testing.T) {
	// Create a real enforcer for testing
	enforcer := core.NewBoundaryEnforcer()
	// Note: CheckNoUnboundExecution expects *BoundaryEnforcer, not mock

	// Test I1: artifact without binding should fail
	ic := &core.InvariantChecker{}
	err := ic.CheckNoUnboundExecution(enforcer, "model-x")
	if err == nil {
		t.Error("Invariant I1 should fail for unbound artifact")
	}

	// Test I4: Fail-closed on ambiguity
	err = ic.CheckFailClosedAmbiguity(true, "ambiguous")
	if err == nil {
		t.Error("Should have raised assertion error for ambiguous case")
	}
}

func TestSMTEncoder(t *testing.T) {
	encoder := core.NewSMTEncoder()
	encoder.AddConstraint("forall x: allowed(x) -> jurisdiction(x) == source_jurisdiction")

	// Should not raise
	result := encoder.Solve()
	if !result {
		t.Error("SMT solver should return true")
	}
}

func TestModelChecker(t *testing.T) {
	checker := core.NewModelChecker()
	checker.AddProperty("safety", "No unauthorized boundary crossing")
	checker.AddProperty("liveness", "Eventually decides on all proposals")

	results := checker.VerifyAll()

	// Should return dict with verification results
	if len(results) != 2 {
		t.Error("Should have two properties verified")
	}
	if !results["safety"] {
		t.Error("Safety property should be verified")
	}
	if !results["liveness"] {
		t.Error("Liveness property should be verified")
	}
}

// Helper function to create pointer to int64
func int64Ptr(i int64) *int64 {
	return &i
}