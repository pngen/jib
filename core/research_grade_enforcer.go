package core

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"
)

// ResearchGradeBoundaryEnforcer integrates all research-grade features.
type ResearchGradeBoundaryEnforcer struct {
	BaseEnforcer        *BoundaryEnforcer
	KeyManager          *KeyManager
	MerkleTree          *MerkleTree
	BindingRevocation   *BindingRevocation
	TemporalManager     *TemporalBoundaryManager
	DistributedEnforcer *DistributedBoundaryEnforcer
	ProvenanceTracker   *DataFlowTracker
	InvariantChecker    *InvariantChecker
	PolicyManager       *PolicyManager
	mutex               sync.RWMutex
}

// NewResearchGradeBoundaryEnforcer creates a new instance of ResearchGradeBoundaryEnforcer.
func NewResearchGradeBoundaryEnforcer(nodeID string, peers []string) *ResearchGradeBoundaryEnforcer {
	return &ResearchGradeBoundaryEnforcer{
		BaseEnforcer:        NewBoundaryEnforcer(),
		KeyManager:          NewKeyManager(),
		MerkleTree:          NewMerkleTree(),
		BindingRevocation:   NewBindingRevocation(),
		TemporalManager:     NewTemporalBoundaryManager(),
		DistributedEnforcer: NewDistributedBoundaryEnforcer(nodeID, peers),
		ProvenanceTracker:   NewDataFlowTracker(),
		InvariantChecker:    &InvariantChecker{},
		PolicyManager:       NewPolicyManager(),
	}
}

// EnforceBoundaryWithAllChecks performs full enforcement with all research-grade checks.
func (rge *ResearchGradeBoundaryEnforcer) EnforceBoundaryWithAllChecks(
	artifactID string,
	sourceDomainID string,
	targetDomainID string,
) (*BoundaryProof, error) {
	rge.mutex.Lock()
	defer rge.mutex.Unlock()

	// The base enforcer is the authoritative local policy decision. No
	// consensus, provenance, or audit side effects may precede this check.
	proof, err := rge.BaseEnforcer.CheckBoundary(artifactID, sourceDomainID, targetDomainID)
	if err != nil {
		return nil, err
	}
	if proof == nil {
		return nil, &JurisdictionalViolation{
			JIBError: JIBError{Message: "boundary check did not produce a proof"},
		}
	}
	if !proof.Allowed {
		return proof, &JurisdictionalViolation{
			JIBError: JIBError{Message: fmt.Sprintf("cross-domain execution denied: %s", proof.Reason)},
		}
	}

	targetJurisdictionID := rge.targetJurisdictionID(targetDomainID)
	if targetJurisdictionID == "" {
		return nil, &JurisdictionalViolation{
			JIBError: JIBError{Message: "target execution domain has no registered jurisdiction"},
		}
	}
	boundaryKey := fmt.Sprintf("%s:%s", proof.JurisdictionID, targetJurisdictionID)

	currentTime := time.Now().Unix()
	if !rge.checkTemporalValidity(boundaryKey, currentTime) {
		return nil, NewTemporalConstraintViolation(boundaryKey, currentTime)
	}
	for _, bindingID := range proof.Evidence {
		if rge.BindingRevocation.IsRevoked(bindingID, currentTime) {
			return nil, NewBindingIntegrityViolation(bindingID, artifactID)
		}
	}

	err = rge.InvariantChecker.CheckNoUnboundExecution(rge.BaseEnforcer, artifactID)
	if err != nil {
		return nil, NewInvariantViolation("I1", map[string]interface{}{"artifact_id": artifactID, "error": err.Error()})
	}

	err = rge.InvariantChecker.CheckExplicitBoundaries(rge.BaseEnforcer, proof.JurisdictionID, targetJurisdictionID)
	if err != nil {
		return nil, NewInvariantViolation("I2", map[string]interface{}{"source": proof.JurisdictionID, "target": targetJurisdictionID, "error": err.Error()})
	}

	decision, err := rge.DistributedEnforcer.ProposeBoundaryDecisionWithDecision(artifactID, sourceDomainID, targetDomainID, proof.Allowed)
	if err != nil {
		return nil, NewConsensusFailure(err.Error(), map[string]interface{}{"artifact_id": artifactID, "source": sourceDomainID, "target": targetDomainID})
	}

	if !decision {
		return nil, NewConsensusFailure("distributed consensus denied boundary crossing", map[string]interface{}{"artifact_id": artifactID, "source": sourceDomainID, "target": targetDomainID})
	}

	if auditErr := rge.InvariantChecker.CheckAuditability(proof); auditErr != nil {
		return nil, NewInvariantViolation("I5", map[string]interface{}{"proof_id": proof.ID, "error": auditErr.Error()})
	}

	rge.ProvenanceTracker.RecordDataFlow(
		artifactID, "boundary_check",
		proof.JurisdictionID,
		targetJurisdictionID,
		nil,
	)
	rge.MerkleTree.AddLeaf(proof.Hash())

	return proof, nil
}

// checkTemporalValidity checks if temporal boundaries are valid for the given key.
func (rge *ResearchGradeBoundaryEnforcer) checkTemporalValidity(boundaryKey string, timestamp int64) bool {
	rge.TemporalManager.mutex.RLock()
	defer rge.TemporalManager.mutex.RUnlock()

	matched := false
	hasActiveAllow := false
	for _, tb := range rge.TemporalManager.TemporalBoundaries {
		if tb == nil || !validTemporalBoundaryIdentity(tb) {
			return false
		}
		key := fmt.Sprintf("%s:%s", tb.SourceJurisdictionID, tb.TargetJurisdictionID)
		if key != boundaryKey {
			continue
		}
		matched = true
		if !supportedTemporalBoundary(tb) {
			return false
		}
		if !tb.IsValidAt(timestamp) {
			continue
		}
		if !tb.Allowed {
			return false
		}
		hasActiveAllow = true
	}

	if !matched {
		return true
	}
	return hasActiveAllow
}

func (rge *ResearchGradeBoundaryEnforcer) targetJurisdictionID(targetDomainID string) string {
	rge.BaseEnforcer.mu.RLock()
	defer rge.BaseEnforcer.mu.RUnlock()
	domain := rge.BaseEnforcer.ExecutionDomains[targetDomainID]
	if !validExecutionDomainRegistration(domain) || domain.ID != targetDomainID {
		return ""
	}
	jurisdiction := rge.BaseEnforcer.Jurisdictions[domain.JurisdictionID]
	if !validJurisdictionRegistration(jurisdiction) || jurisdiction.ID != domain.JurisdictionID {
		return ""
	}
	return domain.JurisdictionID
}

// BindArtifactWithCrypto binds an artifact with cryptographic signature.
func (rge *ResearchGradeBoundaryEnforcer) BindArtifactWithCrypto(
	artifactID string,
	jurisdictionID string,
	privateKey ed25519.PrivateKey,
	artifactHash string,
) (*CryptographicBinding, error) {
	binding, err := rge.BaseEnforcer.BindArtifactToJurisdiction(artifactID, jurisdictionID, privateKey, artifactHash, DefaultBindingType)
	if err != nil {
		return nil, err
	}

	rge.MerkleTree.AddLeaf(binding.Hash())
	return binding, nil
}

// RegisterTemporalBoundary registers a time-bounded boundary.
func (rge *ResearchGradeBoundaryEnforcer) RegisterTemporalBoundary(boundary *TemporalBoundary) {
	rge.TemporalManager.RegisterBoundary(boundary)
}

// GetDecisionLog gets distributed decision log.
func (rge *ResearchGradeBoundaryEnforcer) GetDecisionLog() []map[string]interface{} {
	return rge.DistributedEnforcer.GetDecisionLog()
}

// GetFlowSummary gets data flow summary.
func (rge *ResearchGradeBoundaryEnforcer) GetFlowSummary() map[string]interface{} {
	return rge.ProvenanceTracker.GetFlowSummary()
}

// GetMerkleRoot returns the current Merkle root for audit verification.
func (rge *ResearchGradeBoundaryEnforcer) GetMerkleRoot() string {
	return rge.MerkleTree.GetRoot()
}

// RevokeBinding revokes an artifact binding.
func (rge *ResearchGradeBoundaryEnforcer) RevokeBinding(bindingID string) {
	rge.BindingRevocation.RevokeBinding(bindingID, time.Now().Unix())
}
