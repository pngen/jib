package tests

import (
	"testing"

	"github.com/pngen/jib/core"
)

func TestRegisterJurisdiction(t *testing.T) {
	enforcer := core.NewBoundaryEnforcer()

	j := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California, USA",
		Type: core.SOVEREIGN,
	}

	enforcer.RegisterJurisdiction(j)

	if _, exists := enforcer.Jurisdictions["us-ca"]; !exists {
		t.Error("Jurisdiction not registered")
	}
}

func TestRegisterExecutionDomain(t *testing.T) {
	enforcer := core.NewBoundaryEnforcer()

	d := &core.ExecutionDomain{
		ID:             "prod-us-west",
		Name:           "Production US West",
		JurisdictionID: "us-ca",
	}

	enforcer.RegisterExecutionDomain(d)

	if _, exists := enforcer.ExecutionDomains["prod-us-west"]; !exists {
		t.Error("Execution domain not registered")
	}
}

func TestBindArtifact(t *testing.T) {
	enforcer := core.NewBoundaryEnforcer()

	// Register jurisdiction
	j := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California, USA",
		Type: core.SOVEREIGN,
	}
	enforcer.RegisterJurisdiction(j)

	// Generate key pair for binding
	privateKey := SamplePrivateKey()

	// Bind artifact
	binding, err := enforcer.BindArtifactToJurisdiction(
		"model-x",
		"us-ca",
		privateKey,
		"abc123def456",
		"static",
	)
	if err != nil {
		t.Fatalf("Failed to bind artifact: %v", err)
	}

	if binding.ArtifactID != "model-x" {
		t.Error("Artifact ID mismatch")
	}
	if binding.JurisdictionID != "us-ca" {
		t.Error("Jurisdiction ID mismatch")
	}
	if len(enforcer.BoundArtifacts["model-x"]) != 1 {
		t.Error("Binding not stored in bound artifacts")
	}
}

func TestBindInvalidJurisdiction(t *testing.T) {
	enforcer := core.NewBoundaryEnforcer()

	// Generate key pair for binding
	privateKey := SamplePrivateKey()

	_, err := enforcer.BindArtifactToJurisdiction(
		"model-x",
		"nonexistent",
		privateKey,
		"abc123def456",
		"static",
	)

	if err == nil {
		t.Error("Expected InvalidJurisdictionBinding error")
	}
}

func TestCheckBoundaryAllowed(t *testing.T) {
	enforcer := core.NewBoundaryEnforcer()

	// Register jurisdictions
	j1 := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California, USA",
		Type: core.SOVEREIGN,
	}
	j2 := &core.Jurisdiction{
		ID:   "us-tx",
		Name: "Texas, USA",
		Type: core.SOVEREIGN,
	}

	enforcer.RegisterJurisdiction(j1)
	enforcer.RegisterJurisdiction(j2)

	// Register domains
	d1 := &core.ExecutionDomain{
		ID:             "prod-us-west",
		Name:           "Production US West",
		JurisdictionID: "us-ca",
	}
	d2 := &core.ExecutionDomain{
		ID:             "prod-us-east",
		Name:           "Production US East",
		JurisdictionID: "us-tx",
	}

	enforcer.RegisterExecutionDomain(d1)
	enforcer.RegisterExecutionDomain(d2)

	// Generate key pair for binding
	privateKey := SamplePrivateKey()

	// Bind artifact
	_, err := enforcer.BindArtifactToJurisdiction(
		"model-x",
		"us-ca",
		privateKey,
		"abc123def456",
		"static",
	)
	if err != nil {
		t.Fatalf("Failed to bind artifact: %v", err)
	}

	// Create boundary (allowing cross-domain)
	boundary := &core.Boundary{
		ID:                   "ca-to-tx",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-tx",
		Allowed:              true,
		Reason:               "Explicitly allowed by policy",
	}
	enforcer.Boundaries["us-ca:us-tx"] = boundary

	// Check boundary
	proof, err := enforcer.CheckBoundary("model-x", "prod-us-west", "prod-us-east")
	if err != nil {
		t.Fatalf("Failed to check boundary: %v", err)
	}

	if !proof.Allowed {
		t.Error("Expected boundary to be allowed")
	}
	if proof.Reason != "Explicitly allowed by policy" {
		t.Error("Reason mismatch")
	}
}

func TestCheckBoundaryDenied(t *testing.T) {
	enforcer := core.NewBoundaryEnforcer()

	// Register jurisdictions
	j1 := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California, USA",
		Type: core.SOVEREIGN,
	}
	j2 := &core.Jurisdiction{
		ID:   "us-tx",
		Name: "Texas, USA",
		Type: core.SOVEREIGN,
	}

	enforcer.RegisterJurisdiction(j1)
	enforcer.RegisterJurisdiction(j2)

	// Register domains
	d1 := &core.ExecutionDomain{
		ID:             "prod-us-west",
		Name:           "Production US West",
		JurisdictionID: "us-ca",
	}
	d2 := &core.ExecutionDomain{
		ID:             "prod-us-east",
		Name:           "Production US East",
		JurisdictionID: "us-tx",
	}

	enforcer.RegisterExecutionDomain(d1)
	enforcer.RegisterExecutionDomain(d2)

	// Generate key pair for binding
	privateKey := SamplePrivateKey()

	// Bind artifact
	_, err := enforcer.BindArtifactToJurisdiction(
		"model-x",
		"us-ca",
		privateKey,
		"abc123def456",
		"static",
	)
	if err != nil {
		t.Fatalf("Failed to bind artifact: %v", err)
	}

	// No boundary defined - should default to deny
	proof, err := enforcer.CheckBoundary("model-x", "prod-us-west", "prod-us-east")
	if err != nil {
		t.Fatalf("Failed to check boundary: %v", err)
	}

	if proof.Allowed {
		t.Error("Expected boundary to be denied")
	}
	if proof.Reason != "No explicit boundary rule defined" {
		t.Error("Reason mismatch")
	}
}

func TestEnforceBoundaryAllowed(t *testing.T) {
	enforcer := core.NewBoundaryEnforcer()

	// Register jurisdictions
	j1 := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California, USA",
		Type: core.SOVEREIGN,
	}
	j2 := &core.Jurisdiction{
		ID:   "us-tx",
		Name: "Texas, USA",
		Type: core.SOVEREIGN,
	}

	enforcer.RegisterJurisdiction(j1)
	enforcer.RegisterJurisdiction(j2)

	// Register domains
	d1 := &core.ExecutionDomain{
		ID:             "prod-us-west",
		Name:           "Production US West",
		JurisdictionID: "us-ca",
	}
	d2 := &core.ExecutionDomain{
		ID:             "prod-us-east",
		Name:           "Production US East",
		JurisdictionID: "us-tx",
	}

	enforcer.RegisterExecutionDomain(d1)
	enforcer.RegisterExecutionDomain(d2)

	// Generate key pair for binding
	privateKey := SamplePrivateKey()

	// Bind artifact
	_, err := enforcer.BindArtifactToJurisdiction(
		"model-x",
		"us-ca",
		privateKey,
		"abc123def456",
		"static",
	)
	if err != nil {
		t.Fatalf("Failed to bind artifact: %v", err)
	}

	// Create boundary (allowing cross-domain)
	boundary := &core.Boundary{
		ID:                   "ca-to-tx",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-tx",
		Allowed:              true,
		Reason:               "Explicitly allowed by policy",
	}
	enforcer.Boundaries["us-ca:us-tx"] = boundary

	// Should not raise
	err = enforcer.EnforceBoundary("model-x", "prod-us-west", "prod-us-east")
	if err != nil {
		t.Fatalf("Enforce boundary should not have raised error: %v", err)
	}
}

func TestEnforceBoundaryDenied(t *testing.T) {
	enforcer := core.NewBoundaryEnforcer()

	// Register jurisdictions
	j1 := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California, USA",
		Type: core.SOVEREIGN,
	}
	j2 := &core.Jurisdiction{
		ID:   "us-tx",
		Name: "Texas, USA",
		Type: core.SOVEREIGN,
	}

	enforcer.RegisterJurisdiction(j1)
	enforcer.RegisterJurisdiction(j2)

	// Register domains
	d1 := &core.ExecutionDomain{
		ID:             "prod-us-west",
		Name:           "Production US West",
		JurisdictionID: "us-ca",
	}
	d2 := &core.ExecutionDomain{
		ID:             "prod-us-east",
		Name:           "Production US East",
		JurisdictionID: "us-tx",
	}

	enforcer.RegisterExecutionDomain(d1)
	enforcer.RegisterExecutionDomain(d2)

	// Generate key pair for binding
	privateKey := SamplePrivateKey()

	// Bind artifact
	_, err := enforcer.BindArtifactToJurisdiction(
		"model-x",
		"us-ca",
		privateKey,
		"abc123def456",
		"static",
	)
	if err != nil {
		t.Fatalf("Failed to bind artifact: %v", err)
	}

	// No boundary defined - should default to deny
	err = enforcer.EnforceBoundary("model-x", "prod-us-west", "prod-us-east")
	if err == nil {
		t.Error("Expected JurisdictionalViolation error")
	}
}