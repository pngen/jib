package tests

import (
	"testing"
	"time"

	"github.com/pngen/jib/core"
)

func TestTemporalBoundaryValidity(t *testing.T) {
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

func TestTemporalBoundaryManager(t *testing.T) {
	manager := core.NewTemporalBoundaryManager()

	// Create boundaries with different time constraints
	boundary1 := &core.TemporalBoundary{
		ID:                   "boundary-1",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-tx",
		Allowed:              true,
		Reason:               "Valid now",
		ValidFrom:            int64Ptr(time.Now().Unix() - 3600),
		ValidUntil:           int64Ptr(time.Now().Unix() + 3600),
	}

	boundary2 := &core.TemporalBoundary{
		ID:                   "boundary-2",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-nv",
		Allowed:              false,
		Reason:               "Expired",
		ValidFrom:            int64Ptr(time.Now().Unix() - 7200),
		ValidUntil:           int64Ptr(time.Now().Unix() - 3600), // Already expired
	}

	// Register boundaries
	manager.RegisterBoundary(boundary1)
	manager.RegisterBoundary(boundary2)

	// Check validity
	if !manager.CheckValidity("boundary-1", nil) {
		t.Error("Boundary-1 should be valid")
	}
	if manager.CheckValidity("boundary-2", nil) {
		t.Error("Boundary-2 should not be valid")
	}

	// Get valid boundaries
	valid := manager.GetValidBoundaries()
	if len(valid) != 1 {
		t.Error("Should have 1 valid boundary")
	}
	if valid[0].ID != "boundary-1" {
		t.Error("Should return boundary-1")
	}

	// Get expired boundaries
	expired := manager.GetExpiredBoundaries()
	if len(expired) != 1 {
		t.Error("Should have 1 expired boundary")
	}
	if expired[0].ID != "boundary-2" {
		t.Error("Should return boundary-2")
	}
}

func TestGracePeriodManager(t *testing.T) {
	gpm := core.NewGracePeriodManager(3600) // 1 hour

	// Create a boundary with expiration
	boundary := &core.TemporalBoundary{
		ID:                   "test-boundary",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-tx",
		Allowed:              true,
		Reason:               "Test",
		ValidUntil:           int64Ptr(time.Now().Unix() + 1800), // Expires in 30 minutes
	}

	currentTime := time.Now().Unix()

	// Within grace window (expiry in 30m, grace window is 1h)
	if !gpm.IsInGracePeriod(boundary, int64Ptr(currentTime)) {
		t.Error("Should be in grace period")
	}

	// Outside grace window: pick a time strictly before graceStart
	tooEarly := *boundary.ValidUntil - gpm.DefaultGracePeriod - 1
	if gpm.IsInGracePeriod(boundary, int64Ptr(tooEarly)) {
		t.Error("Should not be in grace period yet")
	}

	// Get remaining time
	remaining := gpm.GetRemainingTime(boundary, int64Ptr(currentTime))
	if remaining <= 0 || remaining > 1800 {
		t.Error("Remaining time should be between 0 and 1800 seconds")
	}
}

func TestBoundaryExpiry(t *testing.T) {
	manager := core.NewTemporalBoundaryManager()

	// Create an expired boundary
	expiredBoundary := &core.TemporalBoundary{
		ID:                   "expired-boundary",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-tx",
		Allowed:              true,
		Reason:               "Expired",
		ValidUntil:           int64Ptr(time.Now().Unix() - 3600), // Already expired
	}

	manager.RegisterBoundary(expiredBoundary)

	// Check if expired
	if manager.CheckValidity("expired-boundary", nil) {
		t.Error("Boundary should be invalid")
	}

	// Get expired boundaries
	expired := manager.GetExpiredBoundaries()
	if len(expired) != 1 {
		t.Error("Should have 1 expired boundary")
	}
	if expired[0].ID != "expired-boundary" {
		t.Error("Should return expired-boundary")
	}
}