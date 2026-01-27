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

	bindings, exists := rge.BaseEnforcer.BoundArtifacts[artifactID]
	if !exists || len(bindings) == 0 {
		return nil, &InvalidJurisdictionBinding{
			JIBError: JIBError{Message: fmt.Sprintf("no bindings found for %s", artifactID)},
		}
	}

	for _, binding := range bindings {
		if !binding.Verify() {
			return nil, NewBindingIntegrityViolation(binding.ID, artifactID)
		}
		
		if rge.BindingRevocation.IsRevoked(binding.ID, time.Now().Unix()) {
			return nil, NewBindingIntegrityViolation(binding.ID, artifactID)
		}
	}

	sourceDomain, exists1 := rge.BaseEnforcer.ExecutionDomains[sourceDomainID]
	targetDomain, exists2 := rge.BaseEnforcer.ExecutionDomains[targetDomainID]

	if !exists1 || !exists2 {
		return nil, &JurisdictionalViolation{
			JIBError: JIBError{Message: fmt.Sprintf(
				"artifact %s not bound to source jurisdiction %s",
				artifactID,
				sourceDomainID,
			)},
		}
	}

	boundaryKey := fmt.Sprintf("%s:%s", sourceDomain.JurisdictionID, targetDomain.JurisdictionID)

	currentTime := time.Now().Unix()
	if !rge.checkTemporalValidity(boundaryKey, currentTime) {
		return nil, NewTemporalConstraintViolation(boundaryKey, currentTime)
	}

	err := rge.InvariantChecker.CheckNoUnboundExecution(rge.BaseEnforcer, artifactID)
	if err != nil {
		return nil, NewInvariantViolation("I1", map[string]interface{}{"artifact_id": artifactID, "error": err.Error()})
	}

	err = rge.InvariantChecker.CheckExplicitBoundaries(rge.BaseEnforcer, sourceDomain.JurisdictionID, targetDomain.JurisdictionID)
	if err != nil {
		return nil, NewInvariantViolation("I2", map[string]interface{}{"source": sourceDomain.JurisdictionID, "target": targetDomain.JurisdictionID, "error": err.Error()})
	}

	decision, err := rge.DistributedEnforcer.ProposeBoundaryDecision(artifactID, sourceDomainID, targetDomainID)
	if err != nil {
		return nil, NewConsensusFailure(err.Error(), map[string]interface{}{"artifact_id": artifactID, "source": sourceDomainID, "target": targetDomainID})
	}

	if !decision {
		return nil, NewConsensusFailure("distributed consensus denied boundary crossing", map[string]interface{}{"artifact_id": artifactID, "source": sourceDomainID, "target": targetDomainID})
	}

	rge.ProvenanceTracker.RecordDataFlow(
		artifactID, "boundary_check",
		sourceDomain.JurisdictionID,
		targetDomain.JurisdictionID,
		nil,
	)

	proof, err := rge.BaseEnforcer.CheckBoundary(artifactID, sourceDomainID, targetDomainID)
	if err != nil {
		return nil, err
	}

	if auditErr := rge.InvariantChecker.CheckAuditability(proof); auditErr != nil {
		return nil, NewInvariantViolation("I5", map[string]interface{}{"proof_id": proof.ID, "error": auditErr.Error()})
	}

	rge.MerkleTree.AddLeaf(proof.Hash())

	return proof, nil
}

// checkTemporalValidity checks if temporal boundaries are valid for the given key.
func (rge *ResearchGradeBoundaryEnforcer) checkTemporalValidity(boundaryKey string, timestamp int64) bool {
	temporalBoundaries := make([]*TemporalBoundary, 0)
	for _, tb := range rge.TemporalManager.TemporalBoundaries {
		key := fmt.Sprintf("%s:%s", tb.SourceJurisdictionID, tb.TargetJurisdictionID)
		if key == boundaryKey {
			temporalBoundaries = append(temporalBoundaries, tb)
		}
	}
	
	if len(temporalBoundaries) == 0 {
		return true
	}
	
	for _, tb := range temporalBoundaries {
		if tb.IsValidAt(timestamp) {
			return true
		}
	}
	return false
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