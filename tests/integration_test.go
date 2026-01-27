package tests

import (
	"crypto/ed25519"

	"testing"

	"github.com/pngen/jib/core"
)

func TestPrepareExecutionContext(t *testing.T) {
	adapter := core.NewIntegrationAdapter()

	// Register binding
	b := &core.CryptographicBinding{
		ID:                 "binding-123",
		ArtifactID:         "model-x",
		JurisdictionID:     "us-ca",
		BindingType:        "static",
		SignatureAlgorithm: "Ed25519",
		PublicKey:          ed25519.PublicKey(make([]byte, 32)),
		Signature:          []byte("signature_bytes"),
		ArtifactHash:       "hash123",
		Timestamp:          1234567890,
	}
	adapter.Bindings["binding-123"] = b

	// Prepare context
	context := adapter.PrepareExecutionContext("model-x", "prod-us-west")

	if context["artifact_id"].(string) != "model-x" {
		t.Error("Artifact ID mismatch")
	}
	if context["domain_id"].(string) != "prod-us-west" {
		t.Error("Domain ID mismatch")
	}
	if len(context["jurisdiction_bindings"].([]map[string]interface{})) != 1 {
		t.Error("Should have one jurisdiction binding")
	}
}

func TestEmitAndGetProof(t *testing.T) {
	adapter := core.NewIntegrationAdapter()

	// Create proof
	proof := &core.BoundaryProof{
		ID:             "proof-123",
		ArtifactID:     "model-x",
		SourceDomainID: "prod-us-west",
		TargetDomainID: "dev-us-east",
		JurisdictionID: "us-ca",
		Allowed:        true,
		Reason:         "Allowed by policy",
		Timestamp:      1234567890,
		Evidence:       []string{},
	}

	// Emit proof
	adapter.EmitProof(proof)

	// Retrieve proof
	retrieved := adapter.GetProof("proof-123")

	if retrieved == nil {
		t.Error("Should retrieve proof")
	}
	if retrieved.ID != "proof-123" {
		t.Error("Proof ID mismatch")
	}
	if retrieved.ArtifactID != "model-x" {
		t.Error("Artifact ID mismatch")
	}
}

func TestValidateExecutionDomain(t *testing.T) {
	adapter := core.NewIntegrationAdapter()

	// Should return true for valid domain (simplified)
	result := adapter.ValidateExecutionDomain(&core.ExecutionDomain{
		ID:             "prod-us-west",
		Name:           "Production US West",
		JurisdictionID: "us-ca",
	})

	if !result {
		t.Error("Should validate execution domain")
	}
}

func TestGetJurisdictionInfo(t *testing.T) {
	adapter := core.NewIntegrationAdapter()

	// Should return basic info
	info := adapter.GetJurisdictionInfo("us-ca")

	if info["id"].(string) != "us-ca" {
		t.Error("ID mismatch")
	}
	if info["name"].(string) != "Unknown Jurisdiction" {
		t.Error("Name mismatch")
	}
	if info["type"].(string) != "unknown" {
		t.Error("Type mismatch")
	}
}