package tests

import (
	"crypto/ed25519"
	"reflect"
	"testing"
	"time"

	"github.com/pngen/jib/core"
)

func configuredBaseEnforcer(t *testing.T, allowed bool) (*core.BoundaryEnforcer, *core.CryptographicBinding) {
	t.Helper()
	enforcer := core.NewBoundaryEnforcer()
	enforcer.RegisterJurisdiction(&core.Jurisdiction{ID: "source-j", Name: "Source", Type: core.SOVEREIGN})
	enforcer.RegisterJurisdiction(&core.Jurisdiction{ID: "target-j", Name: "Target", Type: core.SOVEREIGN})
	enforcer.RegisterExecutionDomain(&core.ExecutionDomain{ID: "source-d", Name: "Source Domain", JurisdictionID: "source-j"})
	enforcer.RegisterExecutionDomain(&core.ExecutionDomain{ID: "target-d", Name: "Target Domain", JurisdictionID: "target-j"})
	enforcer.RegisterBoundary(&core.Boundary{
		ID: "boundary", SourceJurisdictionID: "source-j", TargetJurisdictionID: "target-j",
		Allowed: allowed, Reason: "test policy",
	})
	privateKey := SamplePrivateKey()
	binding, err := enforcer.BindArtifactToJurisdiction("artifact", "source-j", privateKey, "artifact-hash", core.DefaultBindingType)
	if err != nil {
		t.Fatalf("bind artifact: %v", err)
	}
	return enforcer, binding
}

func configuredResearchEnforcer(t *testing.T, allowed bool) (*core.ResearchGradeBoundaryEnforcer, *core.CryptographicBinding) {
	t.Helper()
	rge := core.NewResearchGradeBoundaryEnforcer("node", nil)
	rge.BaseEnforcer.RegisterJurisdiction(&core.Jurisdiction{ID: "source-j", Name: "Source", Type: core.SOVEREIGN})
	rge.BaseEnforcer.RegisterJurisdiction(&core.Jurisdiction{ID: "target-j", Name: "Target", Type: core.SOVEREIGN})
	rge.BaseEnforcer.RegisterExecutionDomain(&core.ExecutionDomain{ID: "source-d", Name: "Source Domain", JurisdictionID: "source-j"})
	rge.BaseEnforcer.RegisterExecutionDomain(&core.ExecutionDomain{ID: "target-d", Name: "Target Domain", JurisdictionID: "target-j"})
	rge.BaseEnforcer.RegisterBoundary(&core.Boundary{
		ID: "boundary", SourceJurisdictionID: "source-j", TargetJurisdictionID: "target-j",
		Allowed: allowed, Reason: "test policy",
	})
	binding, err := rge.BindArtifactWithCrypto("artifact", "source-j", SamplePrivateKey(), "artifact-hash")
	if err != nil {
		t.Fatalf("bind artifact: %v", err)
	}
	return rge, binding
}

func TestResearchEnforcerRejectsStaticDeny(t *testing.T) {
	rge, _ := configuredResearchEnforcer(t, false)
	proof, err := rge.EnforceBoundaryWithAllChecks("artifact", "source-d", "target-d")
	if err == nil {
		t.Fatalf("static deny must return an enforcement error, proof=%#v", proof)
	}
	if proof != nil && proof.Allowed {
		t.Fatal("denied enforcement must never return an allowed proof")
	}
}

func TestTemporalDenyOverridesStaticAllow(t *testing.T) {
	rge, _ := configuredResearchEnforcer(t, true)
	now := time.Now().Unix()
	start, end := now-60, now+60
	rge.RegisterTemporalBoundary(&core.TemporalBoundary{
		ID: "temporal-deny", SourceJurisdictionID: "source-j", TargetJurisdictionID: "target-j",
		Allowed: false, Reason: "temporary denial", ValidFrom: &start, ValidUntil: &end,
	})

	if proof, err := rge.EnforceBoundaryWithAllChecks("artifact", "source-d", "target-d"); err == nil {
		t.Fatalf("active temporal deny must override static allow, proof=%#v", proof)
	}
}

func TestRevocationCannotBeBypassedByChangingBindingID(t *testing.T) {
	rge, binding := configuredResearchEnforcer(t, true)
	originalID := binding.ID
	rge.RevokeBinding(originalID)
	binding.ID = "attacker-selected-id"

	if binding.Verify() {
		t.Fatal("binding ID is part of the signed envelope and mutation must invalidate it")
	}
	if proof, err := rge.EnforceBoundaryWithAllChecks("artifact", "source-d", "target-d"); err == nil {
		t.Fatalf("revoked binding must not regain authority after ID mutation, proof=%#v", proof)
	}
}

func TestBindingBucketCannotSubstituteArtifactIdentity(t *testing.T) {
	enforcer, binding := configuredBaseEnforcer(t, true)
	enforcer.BoundArtifacts["other-artifact"] = []*core.CryptographicBinding{binding}
	if proof, err := enforcer.CheckBoundary("other-artifact", "source-d", "target-d"); err == nil {
		t.Fatalf("binding for a different artifact must fail closed, proof=%#v", proof)
	}
}

func TestBoundaryConflictsAreOrderIndependentAndReturnedBindingIsDetached(t *testing.T) {
	allowFirst, returned := configuredBaseEnforcer(t, true)
	returned.Signature[0] ^= 0xff
	proof, err := allowFirst.CheckBoundary("artifact", "source-d", "target-d")
	if err != nil || !proof.Allowed {
		t.Fatalf("mutating returned binding must not alter stored authority: proof=%#v err=%v", proof, err)
	}
	allowFirst.RegisterBoundary(&core.Boundary{
		ID: "deny", SourceJurisdictionID: "source-j", TargetJurisdictionID: "target-j",
		Allowed: false, Reason: "deny wins",
	})
	proof, err = allowFirst.CheckBoundary("artifact", "source-d", "target-d")
	if err != nil || proof.Allowed {
		t.Fatalf("deny registered after allow must win: proof=%#v err=%v", proof, err)
	}

	denyFirst, _ := configuredBaseEnforcer(t, false)
	denyFirst.RegisterBoundary(&core.Boundary{
		ID: "allow", SourceJurisdictionID: "source-j", TargetJurisdictionID: "target-j",
		Allowed: true, Reason: "late allow",
	})
	proof, err = denyFirst.CheckBoundary("artifact", "source-d", "target-d")
	if err != nil || proof.Allowed {
		t.Fatalf("allow registered after deny must not escalate: proof=%#v err=%v", proof, err)
	}
}

func TestMalformedPublicKeyFailsClosedWithoutPanic(t *testing.T) {
	binding := &core.CryptographicBinding{
		ID: "binding", ArtifactID: "artifact", JurisdictionID: "jurisdiction",
		BindingType: core.DefaultBindingType, SignatureAlgorithm: "Ed25519",
		PublicKey: []byte{1}, Signature: make([]byte, ed25519.SignatureSize),
		ArtifactHash: "hash", Timestamp: 1,
	}
	if binding.Verify() {
		t.Fatal("malformed public key must fail verification")
	}
}

func TestProofIDCommitsDecisionAndAuditHistoryIsImmutable(t *testing.T) {
	enforcer, _ := configuredBaseEnforcer(t, true)
	allowed, err := enforcer.CheckBoundary("artifact", "source-d", "target-d")
	if err != nil || !allowed.Allowed {
		t.Fatalf("expected allow proof, proof=%#v err=%v", allowed, err)
	}
	if allowed.ID != allowed.Hash() {
		t.Fatal("proof ID must be its semantic content hash")
	}

	enforcer.RegisterBoundary(&core.Boundary{
		ID: "boundary-v2", SourceJurisdictionID: "source-j", TargetJurisdictionID: "target-j",
		Allowed: false, Reason: "revoked by policy",
	})
	denied, err := enforcer.CheckBoundary("artifact", "source-d", "target-d")
	if err != nil || denied.Allowed {
		t.Fatalf("expected deny proof, proof=%#v err=%v", denied, err)
	}
	if allowed.ID == denied.ID {
		t.Fatal("allow and deny decisions must have distinct content IDs")
	}

	adapter := core.NewIntegrationAdapter()
	adapter.EmitProof(allowed)
	adapter.EmitProof(denied)
	allowed.Allowed = false
	retrieved := adapter.GetProof(allowed.ID)
	if retrieved == nil || !retrieved.Allowed {
		t.Fatal("external proof mutation must not change stored audit history")
	}
	if len(adapter.GetAllProofs()) != 2 {
		t.Fatal("distinct decisions must both remain in audit history")
	}
	tampered := *denied
	tampered.Reason = "tampered without updating ID"
	if err := adapter.EmitProof(&tampered); err == nil {
		t.Fatal("adapter must reject a proof whose ID no longer matches its content")
	}
}

func TestThresholdSigningRejectsInvalidOrUntrustedSigners(t *testing.T) {
	_, privateA, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	publicA := privateA.Public().(ed25519.PublicKey)
	_, privateB, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	publicB := privateB.Public().(ed25519.PublicKey)
	binding := &core.CryptographicBinding{
		ID: "binding", ArtifactID: "artifact", JurisdictionID: "jurisdiction",
		BindingType: core.DefaultBindingType, SignatureAlgorithm: "Ed25519",
		PublicKey: publicA, ArtifactHash: "hash", Timestamp: 1,
	}

	if _, err := core.NewThresholdSignature(0, 3).SignWithThreshold(binding, nil); err == nil {
		t.Fatal("zero threshold must fail")
	}
	untrusted := core.NewThresholdSignature(1, 1)
	untrusted.AddSigner("a", publicA)
	if _, err := untrusted.SignWithThreshold(binding, []ed25519.PrivateKey{privateB}); err == nil {
		t.Fatal("unregistered signer must fail")
	}
	duplicate := core.NewThresholdSignature(2, 2)
	duplicate.AddSigner("a", publicA)
	duplicate.AddSigner("b", publicB)
	if _, err := duplicate.SignWithThreshold(binding, []ed25519.PrivateKey{privateA, privateA}); err == nil {
		t.Fatal("duplicate signer must not satisfy threshold")
	}
}

func TestOptimizedEnforcerRequiresBindingAndInvalidatesCachedAllow(t *testing.T) {
	optimized := core.NewOptimizedBoundaryEnforcer()
	optimized.RegisterJurisdiction(map[string]interface{}{"id": "source-j"})
	optimized.RegisterJurisdiction(map[string]interface{}{"id": "target-j"})
	optimized.RegisterExecutionDomain(map[string]interface{}{"id": "source-d", "jurisdiction_id": "source-j"})
	optimized.RegisterExecutionDomain(map[string]interface{}{"id": "target-d", "jurisdiction_id": "target-j"})
	optimized.RegisterBoundary(map[string]interface{}{
		"id": "boundary", "source_jurisdiction_id": "source-j", "target_jurisdiction_id": "target-j",
		"allowed": true, "reason": "allowed",
	})

	if optimized.CheckBoundary("artifact", "source-d", "target-d")["allowed"].(bool) {
		t.Fatal("optimized path must deny an unbound artifact")
	}
	if optimized.BindArtifactToJurisdiction("artifact", "source-j") == nil {
		t.Fatal("valid optimized binding should be created")
	}
	first := optimized.CheckBoundary("artifact", "source-d", "target-d")
	if !first["allowed"].(bool) {
		t.Fatal("bound artifact with explicit allow should pass")
	}
	first["allowed"] = false
	if !optimized.CheckBoundary("artifact", "source-d", "target-d")["allowed"].(bool) {
		t.Fatal("caller mutation must not poison cached proof")
	}

	optimized.RegisterBoundary(map[string]interface{}{
		"id": "boundary-v2", "source_jurisdiction_id": "source-j", "target_jurisdiction_id": "target-j",
		"allowed": false, "reason": "denied",
	})
	if optimized.CheckBoundary("artifact", "source-d", "target-d")["allowed"].(bool) {
		t.Fatal("cached allow must be invalidated by deny update")
	}
}

func TestDistributedEnforcerDoesNotFabricatePeerVotes(t *testing.T) {
	enforcer := core.NewDistributedBoundaryEnforcer("node-1", []string{"node-2", "node-3"})
	decision, err := enforcer.ProposeBoundaryDecisionWithDecision("artifact", "source", "target", true)
	if err != nil {
		t.Fatalf("proposal failed: %v", err)
	}
	if decision {
		t.Fatal("configured peers that did not vote must not be counted as approvals")
	}
}

func TestProvenanceKeepsSameSecondEventsAndRealBranchEdges(t *testing.T) {
	tracker := core.NewDataFlowTracker()
	timestamp := int64(123)
	tracker.RecordDataFlow("artifact", "read", "A", "B", &timestamp)
	tracker.RecordDataFlow("artifact", "read", "A", "B", &timestamp)
	if got := tracker.GetFlowSummary()["total_flows"].(int); got != 2 {
		t.Fatalf("expected two flow events, got %d", got)
	}
	if got := len(tracker.Graph.Nodes); got != 2 {
		t.Fatalf("same-second events must have distinct graph nodes, got %d", got)
	}

	graph := core.NewProvenanceGraph()
	graph.AddNode(core.NewProvenanceNode("p1", "a", "read", "J1", 1, nil, nil))
	graph.AddNode(core.NewProvenanceNode("p2", "a", "read", "J2", 1, nil, nil))
	graph.AddNode(core.NewProvenanceNode("child", "a", "merge", "J3", 2, []string{"p1", "p2"}, nil))
	crossings := graph.FindBoundaryCrossings("child")
	if len(crossings) != 2 || crossings[0] != (core.BoundaryCrossing{"J1", "J3"}) || crossings[1] != (core.BoundaryCrossing{"J2", "J3"}) {
		t.Fatalf("expected real parent-to-child crossings only, got %#v", crossings)
	}
}

func TestPolicyHierarchyEnforcesChildDenyAndReportsConflict(t *testing.T) {
	parent := core.NewPolicyNode("parent", "Parent", core.NewAtomicBoundary("route", true))
	parent.AddChild(core.NewPolicyNode("child", "Child", core.NewAtomicBoundary("child-route", false)))
	if parent.Evaluate(nil) {
		t.Fatal("child deny must constrain its parent regardless of parent expression type")
	}
	cyclic := core.NewPolicyNode("cyclic", "Cyclic", core.NewAtomicBoundary("route", true))
	cyclic.AddChild(cyclic)
	if cyclic.Evaluate(nil) {
		t.Fatal("cyclic policy hierarchy must fail closed")
	}

	manager := core.NewPolicyManager()
	manager.AddPolicy(core.NewPolicyNode("allow", "Allow", core.NewAtomicBoundary("route", true)))
	manager.AddPolicy(core.NewPolicyNode("deny", "Deny", core.NewAtomicBoundary("route", false)))
	if conflicts := manager.FindConflicts(); len(conflicts) != 1 {
		t.Fatalf("expected one explicit atomic policy conflict, got %#v", conflicts)
	}
}

func TestCRDTBoundaryConflictConvergesFailClosed(t *testing.T) {
	allow := core.NewCRDTManager()
	deny := core.NewCRDTManager()
	allow.UpdateBoundary("route", map[string]interface{}{"id": "route", "allowed": true, "reason": "allow"})
	deny.UpdateBoundary("route", map[string]interface{}{"id": "route", "allowed": false, "reason": "deny"})

	allow.MergeState(deny)
	deny.MergeState(allow)
	allowState := allow.GetBoundary("route").(map[string]interface{})
	denyState := deny.GetBoundary("route").(map[string]interface{})
	if !reflect.DeepEqual(allowState, denyState) || allowState["allowed"].(bool) {
		t.Fatalf("conflicting replicas must converge on deny, allow=%#v deny=%#v", allowState, denyState)
	}
	allowState["allowed"] = true
	if allow.GetBoundary("route").(map[string]interface{})["allowed"].(bool) {
		t.Fatal("returned CRDT state must not alias stored governance state")
	}
	allow.MergeState(allow) // self-merge must not deadlock
}
