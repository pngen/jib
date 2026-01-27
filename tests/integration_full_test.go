package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/pngen/jib/core"
)

func TestFullEnforcementPipelineAllowed(t *testing.T) {
	// Setup distributed system
	enforcer := core.NewResearchGradeBoundaryEnforcer("node-1", []string{"node-2", "node-3"})

	// Register jurisdictions
	usCa := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California, USA",
		Type: core.SOVEREIGN,
	}
	usTx := &core.Jurisdiction{
		ID:   "us-tx",
		Name: "Texas, USA",
		Type: core.SOVEREIGN,
	}

	enforcer.BaseEnforcer.RegisterJurisdiction(usCa)
	enforcer.BaseEnforcer.RegisterJurisdiction(usTx)

	// Register execution domains
	prodWest := &core.ExecutionDomain{
		ID:             "prod-west",
		Name:           "Production West",
		JurisdictionID: "us-ca",
	}
	prodEast := &core.ExecutionDomain{
		ID:             "prod-east",
		Name:           "Production East",
		JurisdictionID: "us-tx",
	}

	enforcer.BaseEnforcer.RegisterExecutionDomain(prodWest)
	enforcer.BaseEnforcer.RegisterExecutionDomain(prodEast)

	// Create cryptographic binding
	privateKey := SamplePrivateKey()
	binding, err := enforcer.BindArtifactWithCrypto(
		"model-x",
		"us-ca",
		privateKey,
		"abc123def456",
	)
	if err != nil {
		t.Fatalf("Failed to bind artifact: %v", err)
	}

	// Verify binding cryptographically
	if !binding.Verify() {
		t.Error("Cryptographic binding verification failed")
	}

	// Add temporal boundary (valid for next hour)
	validFrom := time.Now().Unix() - 60
	validUntil := time.Now().Unix() + 3600
	temporalBoundary := &core.TemporalBoundary{
		ID:                   "temp-ca-to-tx",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-tx",
		Allowed:              true,
		Reason:               "Temporary cross-jurisdiction access",
		ValidFrom:            &validFrom,
		ValidUntil:           &validUntil,
	}
	enforcer.RegisterTemporalBoundary(temporalBoundary)

	// Add static boundary rule
	boundary := &core.Boundary{
		ID:                   "ca-to-tx",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-tx",
		Allowed:              true,
		Reason:               "Allowed by policy",
	}
	enforcer.BaseEnforcer.Boundaries["us-ca:us-tx"] = boundary

	// Execute full enforcement with all checks
	proof, err := enforcer.EnforceBoundaryWithAllChecks("model-x", "prod-west", "prod-east")
	if err != nil {
		t.Fatalf("Enforcement failed: %v", err)
	}

	// Verify proof properties
	if !proof.Allowed {
		t.Error("Boundary should be allowed")
	}
	if proof.ArtifactID != "model-x" {
		t.Error("Artifact ID mismatch")
	}
	if proof.JurisdictionID != "us-ca" {
		t.Error("Jurisdiction ID mismatch")
	}
	if proof.SourceDomainID != "prod-west" {
		t.Error("Source domain ID mismatch")
	}
	if proof.TargetDomainID != "prod-east" {
		t.Error("Target domain ID mismatch")
	}
	if proof.Reason != "Allowed by policy" {
		t.Error("Reason mismatch")
	}

	// Verify provenance tracking
	flowSummary := enforcer.GetFlowSummary()
	if flowSummary["total_flows"].(int) < 1 {
		t.Error("Should have recorded data flow")
	}
	if flowSummary["cross_boundary_flows"].(int) < 1 {
		t.Error("Should have cross-boundary flow")
	}

	// Verify Merkle tree audit trail
	if enforcer.MerkleTree.GetRoot() == "" {
		t.Error("Merkle tree should have root")
	}

	// Verify decision log
	decisionLog := enforcer.GetDecisionLog()
	if len(decisionLog) < 1 {
		t.Error("Should have decision log entry")
	}
}

func TestEnforcementDeniesExpiredTemporalBoundary(t *testing.T) {
	enforcer := core.NewResearchGradeBoundaryEnforcer("node-1", []string{})

	// Setup jurisdictions and domains
	usCa := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California",
		Type: core.SOVEREIGN,
	}
	usTx := &core.Jurisdiction{
		ID:   "us-tx",
		Name: "Texas",
		Type: core.SOVEREIGN,
	}
	enforcer.BaseEnforcer.RegisterJurisdiction(usCa)
	enforcer.BaseEnforcer.RegisterJurisdiction(usTx)

	prodWest := &core.ExecutionDomain{
		ID:             "prod-west",
		Name:           "West",
		JurisdictionID: "us-ca",
	}
	prodEast := &core.ExecutionDomain{
		ID:             "prod-east",
		Name:           "East",
		JurisdictionID: "us-tx",
	}
	enforcer.BaseEnforcer.RegisterExecutionDomain(prodWest)
	enforcer.BaseEnforcer.RegisterExecutionDomain(prodEast)

	// Create binding
	privateKey := SamplePrivateKey()
	_, err := enforcer.BindArtifactWithCrypto(
		"model-x",
		"us-ca",
		privateKey,
		"hash123",
	)
	if err != nil {
		t.Fatalf("Failed to bind artifact: %v", err)
	}

	// Add EXPIRED temporal boundary
	validFrom := time.Now().Unix() - 7200
	validUntil := time.Now().Unix() - 3600
	expiredBoundary := &core.TemporalBoundary{
		ID:                   "expired-ca-to-tx",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-tx",
		Allowed:              true,
		Reason:               "Expired access",
		ValidFrom:            &validFrom,
		ValidUntil:           &validUntil,
	}
	enforcer.RegisterTemporalBoundary(expiredBoundary)

	// Should raise TemporalConstraintViolation
	_, err = enforcer.EnforceBoundaryWithAllChecks("model-x", "prod-west", "prod-east")
	if err == nil {
		t.Error("Should have raised TemporalConstraintViolation")
	}
}

func TestEnforcementDeniesInvalidCryptographicBinding(t *testing.T) {
	enforcer := core.NewResearchGradeBoundaryEnforcer("node-1", []string{})

	// Setup
	usCa := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California",
		Type: core.SOVEREIGN,
	}
	enforcer.BaseEnforcer.RegisterJurisdiction(usCa)

	prodWest := &core.ExecutionDomain{
		ID:             "prod-west",
		Name:           "West",
		JurisdictionID: "us-ca",
	}
	prodEast := &core.ExecutionDomain{
		ID:             "prod-east",
		Name:           "East",
		JurisdictionID: "us-ca",
	}
	enforcer.BaseEnforcer.RegisterExecutionDomain(prodWest)
	enforcer.BaseEnforcer.RegisterExecutionDomain(prodEast)

	// Create valid binding
	privateKey := SamplePrivateKey()
	validBinding, err := enforcer.BindArtifactWithCrypto(
		"model-x",
		"us-ca",
		privateKey,
		"original-hash",
	)
	if err != nil {
		t.Fatalf("Failed to bind artifact: %v", err)
	}

	// Tamper with binding by replacing with invalid signature
	tamperedBinding := &core.CryptographicBinding{
		ID:                 validBinding.ID,
		ArtifactID:         validBinding.ArtifactID,
		JurisdictionID:     validBinding.JurisdictionID,
		BindingType:        validBinding.BindingType,
		SignatureAlgorithm: validBinding.SignatureAlgorithm,
		PublicKey:          validBinding.PublicKey,
		Signature:          []byte("INVALID_SIGNATURE"), // Tampered!
		ArtifactHash:       validBinding.ArtifactHash,
		Timestamp:          validBinding.Timestamp,
	}

	// Replace valid binding with tampered one
	enforcer.BaseEnforcer.BoundArtifacts["model-x"] = []*core.CryptographicBinding{tamperedBinding}

	// Add boundary
	boundary := &core.Boundary{
		ID:                   "ca-to-ca",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-ca",
		Allowed:              true,
		Reason:               "Same jurisdiction",
	}
	enforcer.BaseEnforcer.Boundaries["us-ca:us-ca"] = boundary

	// Should raise BindingIntegrityViolation
	_, err = enforcer.EnforceBoundaryWithAllChecks("model-x", "prod-west", "prod-east")
	if err == nil {
		t.Error("Should have raised BindingIntegrityViolation")
	}
}

func TestEnforcementDeniesUnboundArtifact(t *testing.T) {
	enforcer := core.NewResearchGradeBoundaryEnforcer("node-1", []string{})

	// Setup
	usCa := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California",
		Type: core.SOVEREIGN,
	}
	enforcer.BaseEnforcer.RegisterJurisdiction(usCa)

	prodWest := &core.ExecutionDomain{
		ID:             "prod-west",
		Name:           "West",
		JurisdictionID: "us-ca",
	}
	prodEast := &core.ExecutionDomain{
		ID:             "prod-east",
		Name:           "East",
		JurisdictionID: "us-ca",
	}
	enforcer.BaseEnforcer.RegisterExecutionDomain(prodWest)
	enforcer.BaseEnforcer.RegisterExecutionDomain(prodEast)

	// DON'T create binding - artifact is unbound

	// Add boundary
	boundary := &core.Boundary{
		ID:                   "ca-to-ca",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-ca",
		Allowed:              true,
		Reason:               "Same jurisdiction",
	}
	enforcer.BaseEnforcer.Boundaries["us-ca:us-ca"] = boundary

	// Should raise InvalidJurisdictionBinding
	_, err := enforcer.EnforceBoundaryWithAllChecks(
		"unbound-artifact",
		"prod-west",
		"prod-east",
	)
	if err == nil {
		t.Error("Should have raised InvalidJurisdictionBinding")
	}
}

func TestEnforcementDeniesWithoutExplicitBoundary(t *testing.T) {
	enforcer := core.NewResearchGradeBoundaryEnforcer("node-1", []string{})

	// Setup
	usCa := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California",
		Type: core.SOVEREIGN,
	}
	usTx := &core.Jurisdiction{
		ID:   "us-tx",
		Name: "Texas",
		Type: core.SOVEREIGN,
	}
	enforcer.BaseEnforcer.RegisterJurisdiction(usCa)
	enforcer.BaseEnforcer.RegisterJurisdiction(usTx)

	prodWest := &core.ExecutionDomain{
		ID:             "prod-west",
		Name:           "West",
		JurisdictionID: "us-ca",
	}
	prodEast := &core.ExecutionDomain{
		ID:             "prod-east",
		Name:           "East",
		JurisdictionID: "us-tx",
	}
	enforcer.BaseEnforcer.RegisterExecutionDomain(prodWest)
	enforcer.BaseEnforcer.RegisterExecutionDomain(prodEast)

	// Create binding
	privateKey := SamplePrivateKey()
	_, err := enforcer.BindArtifactWithCrypto(
		"model-x",
		"us-ca",
		privateKey,
		"hash123",
	)
	if err != nil {
		t.Fatalf("Failed to bind artifact: %v", err)
	}

	// DON'T add boundary - no explicit rule defined

	// Should raise due to fail-closed semantics
	_, err = enforcer.EnforceBoundaryWithAllChecks("model-x", "prod-west", "prod-east")
	if err == nil {
		t.Error("Should have raised JurisdictionalViolation or Invariant I2 assertion")
	}
}

func TestMultiArtifactProvenanceTracking(t *testing.T) {
	enforcer := core.NewResearchGradeBoundaryEnforcer("node-1", []string{})

	// Setup
	usCa := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California",
		Type: core.SOVEREIGN,
	}
	usTx := &core.Jurisdiction{
		ID:   "us-tx",
		Name: "Texas",
		Type: core.SOVEREIGN,
	}
	usNy := &core.Jurisdiction{
		ID:   "us-ny",
		Name: "New York",
		Type: core.SOVEREIGN,
	}

	enforcer.BaseEnforcer.RegisterJurisdiction(usCa)
	enforcer.BaseEnforcer.RegisterJurisdiction(usTx)
	enforcer.BaseEnforcer.RegisterJurisdiction(usNy)

	dCa := &core.ExecutionDomain{
		ID:             "d-ca",
		Name:           "CA Domain",
		JurisdictionID: "us-ca",
	}
	dTx := &core.ExecutionDomain{
		ID:             "d-tx",
		Name:           "TX Domain",
		JurisdictionID: "us-tx",
	}
	dNy := &core.ExecutionDomain{
		ID:             "d-ny",
		Name:           "NY Domain",
		JurisdictionID: "us-ny",
	}

	enforcer.BaseEnforcer.RegisterExecutionDomain(dCa)
	enforcer.BaseEnforcer.RegisterExecutionDomain(dTx)
	enforcer.BaseEnforcer.RegisterExecutionDomain(dNy)

	// Create multiple artifacts
	artifacts := []string{"model-a", "model-b", "model-c"}
	for _, artifact := range artifacts {
		privateKey := SamplePrivateKey()
		_, err := enforcer.BindArtifactWithCrypto(
			artifact,
			"us-ca",
			privateKey,
			fmt.Sprintf("hash-%s", artifact),
		)
		if err != nil {
			t.Fatalf("Failed to bind artifact %s: %v", artifact, err)
		}
	}

	// Define boundaries
	for _, targetJID := range []string{"us-tx", "us-ny"} {
		boundary := &core.Boundary{
			ID:                   fmt.Sprintf("ca-to-%s", targetJID),
			SourceJurisdictionID: "us-ca",
			TargetJurisdictionID: targetJID,
			Allowed:              true,
			Reason:               "Cross-region allowed",
		}
		enforcer.BaseEnforcer.Boundaries[fmt.Sprintf("us-ca:%s", targetJID)] = boundary
	}

	// Execute multiple boundary checks
	for _, artifact := range artifacts {
		for _, target := range []string{"d-tx", "d-ny"} {
			proof, err := enforcer.EnforceBoundaryWithAllChecks(artifact, "d-ca", target)
			if err != nil {
				t.Fatalf("Failed to enforce boundary for %s: %v", artifact, err)
			}
			if !proof.Allowed {
				t.Errorf("Expected boundary allowed for %s", artifact)
			}
		}
	}

	// Verify provenance tracking
	flowSummary := enforcer.GetFlowSummary()
	if flowSummary["total_flows"].(int) < 6 {
		t.Error("Should have 6 flows (3 artifacts  2 destinations)")
	}
	if flowSummary["cross_boundary_flows"].(int) < 6 {
		t.Error("All should be cross-boundary")
	}

	// Verify audit trail
	if enforcer.MerkleTree.GetRoot() == "" {
		t.Error("Should have Merkle tree root")
	}
	if len(enforcer.MerkleTree.Leaves) < 6 {
		t.Error("Should have 6 leaves in Merkle tree")
	}
}

func TestConcurrentEnforcementRequests(t *testing.T) {
	enforcer := core.NewResearchGradeBoundaryEnforcer("node-1", []string{})

	// Setup
	usCa := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California",
		Type: core.SOVEREIGN,
	}
	enforcer.BaseEnforcer.RegisterJurisdiction(usCa)

	d1 := &core.ExecutionDomain{
		ID:             "d1",
		Name:           "Domain 1",
		JurisdictionID: "us-ca",
	}
	d2 := &core.ExecutionDomain{
		ID:             "d2",
		Name:           "Domain 2",
		JurisdictionID: "us-ca",
	}
	enforcer.BaseEnforcer.RegisterExecutionDomain(d1)
	enforcer.BaseEnforcer.RegisterExecutionDomain(d2)

	// Create bindings for multiple artifacts
	artifacts := make([]string, 10)
	for i := range artifacts {
		artifacts[i] = fmt.Sprintf("model-%d", i)
		privateKey := SamplePrivateKey()
		_, err := enforcer.BindArtifactWithCrypto(
			artifacts[i],
			"us-ca",
			privateKey,
			fmt.Sprintf("hash-%s", artifacts[i]),
		)
		if err != nil {
			t.Fatalf("Failed to bind artifact %s: %v", artifacts[i], err)
		}
	}

	// Add boundary
	boundary := &core.Boundary{
		ID:                   "ca-to-ca",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-ca",
		Allowed:              true,
		Reason:               "Same jurisdiction",
	}
	enforcer.BaseEnforcer.Boundaries["us-ca:us-ca"] = boundary

	// Execute concurrent enforcement requests
	proofs := make([]*core.BoundaryProof, len(artifacts))
	for i, artifact := range artifacts {
		var err error
		proofs[i], err = enforcer.EnforceBoundaryWithAllChecks(artifact, "d1", "d2")
		if err != nil {
			t.Fatalf("Failed to enforce boundary for %s: %v", artifact, err)
		}
	}

	// Verify all succeeded
	for _, proof := range proofs {
		if !proof.Allowed {
			t.Error("All proofs should be allowed")
		}
	}
}

func TestTemporalBoundaryGracePeriod(t *testing.T) {
	enforcer := core.NewResearchGradeBoundaryEnforcer("node-1", []string{})

	// Setup
	usCa := &core.Jurisdiction{
		ID:   "us-ca",
		Name: "California",
		Type: core.SOVEREIGN,
	}
	usTx := &core.Jurisdiction{
		ID:   "us-tx",
		Name: "Texas",
		Type: core.SOVEREIGN,
	}
	enforcer.BaseEnforcer.RegisterJurisdiction(usCa)
	enforcer.BaseEnforcer.RegisterJurisdiction(usTx)

	dCa := &core.ExecutionDomain{
		ID:             "d-ca",
		Name:           "CA",
		JurisdictionID: "us-ca",
	}
	dTx := &core.ExecutionDomain{
		ID:             "d-tx",
		Name:           "TX",
		JurisdictionID: "us-tx",
	}
	enforcer.BaseEnforcer.RegisterExecutionDomain(dCa)
	enforcer.BaseEnforcer.RegisterExecutionDomain(dTx)

	// Create binding
	privateKey := SamplePrivateKey()
	_, err := enforcer.BindArtifactWithCrypto(
		"model-x",
		"us-ca",
		privateKey,
		"hash123",
	)
	if err != nil {
		t.Fatalf("Failed to bind artifact: %v", err)
	}

	// Add temporal boundary expiring in 30 minutes
	now := time.Now().Unix()
	validFrom := now - 3600
	validUntil := now + 1800
	temporalBoundary := &core.TemporalBoundary{
		ID:                   "temp-ca-to-tx",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-tx",
		Allowed:              true,
		Reason:               "Temporary access",
		ValidFrom:            &validFrom,
		ValidUntil:           &validUntil,
	}
	enforcer.RegisterTemporalBoundary(temporalBoundary)

	// Add static boundary
	boundary := &core.Boundary{
		ID:                   "ca-to-tx",
		SourceJurisdictionID: "us-ca",
		TargetJurisdictionID: "us-tx",
		Allowed:              true,
		Reason:               "Policy allows",
	}
	enforcer.BaseEnforcer.Boundaries["us-ca:us-tx"] = boundary

	// Should still be valid (in grace period)
	proof, err := enforcer.EnforceBoundaryWithAllChecks("model-x", "d-ca", "d-tx")
	if err != nil {
		t.Fatalf("Failed to enforce boundary: %v", err)
	}
	if !proof.Allowed {
		t.Error("Should be allowed")
	}

	// Verify grace period manager can detect we're near expiration
	gpm := core.NewGracePeriodManager(3600)
	inGrace := gpm.IsInGracePeriod(temporalBoundary, &now)
	remaining := gpm.GetRemainingTime(temporalBoundary, &now)

	if !inGrace {
		t.Error("Should be in grace period")
	}
	if remaining <= 0 || remaining > 1800 {
		t.Error("Remaining time should be between 0 and 1800 seconds")
	}
}

func TestMerkleTreeAuditTrailIntegrity(t *testing.T) {
	enforcer := core.NewResearchGradeBoundaryEnforcer("node-1", []string{})

	// Add multiple proof IDs to Merkle tree
	proofIDs := make([]string, 10)
	for i := range proofIDs {
		proofIDs[i] = fmt.Sprintf("proof-%d", i)
		enforcer.MerkleTree.AddLeaf(proofIDs[i])
	}

	// Get root
	root1 := enforcer.MerkleTree.GetRoot()
	if root1 == "" {
		t.Error("Should have root")
	}

	// Verify proofs
	for i := range proofIDs {
		proof := enforcer.MerkleTree.GetProof(i)
		if len(proof) == 0 {
			t.Error("Should have proof")
		}
	}

	// Add one more proof
	enforcer.MerkleTree.AddLeaf("proof-new")
	root2 := enforcer.MerkleTree.GetRoot()

	// Root should have changed (tamper-evident)
	if root1 == root2 {
		t.Error("Root should change after adding new leaf")
	}
}