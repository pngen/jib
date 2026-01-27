package tests

import (
	"testing"

	"github.com/pngen/jib/core"
)

func TestResearchGradeEnforcerInitialization(t *testing.T) {
	peers := []string{"node-1", "node-2"}
	enforcer := core.NewResearchGradeBoundaryEnforcer("node-1", peers)

	if enforcer.BaseEnforcer == nil {
		t.Error("Base enforcer should not be nil")
	}
	if enforcer.KeyManager == nil {
		t.Error("Key manager should not be nil")
	}
	if enforcer.MerkleTree == nil {
		t.Error("Merkle tree should not be nil")
	}
	if enforcer.TemporalManager == nil {
		t.Error("Temporal manager should not be nil")
	}
	if enforcer.DistributedEnforcer == nil {
		t.Error("Distributed enforcer should not be nil")
	}
	if enforcer.ProvenanceTracker == nil {
		t.Error("Provenance tracker should not be nil")
	}
	if enforcer.InvariantChecker == nil {
		t.Error("Invariant checker should not be nil")
	}
	if enforcer.PolicyManager == nil {
		t.Error("Policy manager should not be nil")
	}
}

func TestBindArtifactWithCrypto(t *testing.T) {
	peers := []string{"node-1", "node-2"}
	enforcer := core.NewResearchGradeBoundaryEnforcer("node-1", peers)

	// Generate key pair
	privateKey := SamplePrivateKey()

	// Create jurisdiction and domain for testing
	jurisdiction := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California",
		Type: core.SOVEREIGN,
	}
	enforcer.BaseEnforcer.RegisterJurisdiction(jurisdiction)

	// Bind artifact
	binding, err := enforcer.BindArtifactWithCrypto(
		"model-x",
		"us-ca",
		privateKey,
		"abc123def456",
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
	if !binding.Verify() {
		t.Error("Binding should be cryptographically valid")
	}
}

func TestDecisionLog(t *testing.T) {
	peers := []string{"node-1", "node-2"}
	enforcer := core.NewResearchGradeBoundaryEnforcer("node-1", peers)

	// Should have empty log initially
	log := enforcer.GetDecisionLog()
	if log == nil {
		t.Error("Decision log should not be nil")
	}
}

func TestFlowSummary(t *testing.T) {
	peers := []string{"node-1", "node-2"}
	enforcer := core.NewResearchGradeBoundaryEnforcer("node-1", peers)

	// Should have initial summary
	summary := enforcer.GetFlowSummary()
	if summary == nil {
		t.Error("Flow summary should not be nil")
	}
}