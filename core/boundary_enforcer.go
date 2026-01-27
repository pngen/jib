package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// BoundaryEnforcer enforces jurisdictional boundaries on intelligence execution.
type BoundaryEnforcer struct {
	Jurisdictions       map[string]*Jurisdiction
	ExecutionDomains    map[string]*ExecutionDomain
	BoundArtifacts      map[string][]*CryptographicBinding
	Boundaries          map[string]*Boundary
	mu               	sync.RWMutex
}

// NewBoundaryEnforcer creates a new instance of BoundaryEnforcer.
func NewBoundaryEnforcer() *BoundaryEnforcer {
	return &BoundaryEnforcer{
		Jurisdictions:    make(map[string]*Jurisdiction),
		ExecutionDomains: make(map[string]*ExecutionDomain),
		BoundArtifacts:   make(map[string][]*CryptographicBinding),
		Boundaries:       make(map[string]*Boundary),
	}
}

// RegisterJurisdiction registers a jurisdiction.
func (be *BoundaryEnforcer) RegisterJurisdiction(jurisdiction *Jurisdiction) {
	be.mu.Lock()
	defer be.mu.Unlock()
	be.Jurisdictions[jurisdiction.ID] = jurisdiction
}

// RegisterExecutionDomain registers an execution domain.
func (be *BoundaryEnforcer) RegisterExecutionDomain(domain *ExecutionDomain) {
	be.mu.Lock()
	defer be.mu.Unlock()
	be.ExecutionDomains[domain.ID] = domain
}

// RegisterBoundary registers a boundary rule.
func (be *BoundaryEnforcer) RegisterBoundary(boundary *Boundary) {
	be.mu.Lock()
	defer be.mu.Unlock()
	key := fmt.Sprintf("%s:%s", boundary.SourceJurisdictionID, boundary.TargetJurisdictionID)
	be.Boundaries[key] = boundary
}

// BindArtifactToJurisdiction binds an artifact to a jurisdiction with cryptographic signature.
func (be *BoundaryEnforcer) BindArtifactToJurisdiction(
	artifactID string,
	jurisdictionID string,
	privateKey ed25519.PrivateKey,
	artifactHash string,
	bindingType string,
) (*CryptographicBinding, error) {
	be.mu.Lock()
	defer be.mu.Unlock()

	if _, exists := be.Jurisdictions[jurisdictionID]; !exists {
		return nil, &InvalidJurisdictionBinding{
			JIBError: JIBError{Message: fmt.Sprintf("jurisdiction %s not registered", jurisdictionID)},
		}
	}

	timestamp := time.Now().Unix()
	bindingID := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", artifactID, jurisdictionID, timestamp))))

	binding := &CryptographicBinding{
		ID:                 bindingID,
		ArtifactID:            artifactID,
		JurisdictionID:        jurisdictionID,
		BindingType:           bindingType,
		SignatureAlgorithm:    "Ed25519",
		PublicKey:             privateKey.Public().(ed25519.PublicKey),
		Signature:             []byte{},
		ArtifactHash:          artifactHash,
		Timestamp:             timestamp,
	}

	canonical := binding.CanonicalForm()
	signature := ed25519.Sign(privateKey, []byte(canonical))
	binding.Signature = signature

	if _, exists := be.BoundArtifacts[artifactID]; !exists {
		be.BoundArtifacts[artifactID] = make([]*CryptographicBinding, 0)
	}
	be.BoundArtifacts[artifactID] = append(be.BoundArtifacts[artifactID], binding)

	return binding, nil
}

// ResolveJurisdictionForArtifact resolves the jurisdiction(s) bound to an artifact.
func (be *BoundaryEnforcer) ResolveJurisdictionForArtifact(artifactID string) []string {
	be.mu.RLock()
	defer be.mu.RUnlock()

	bindings, exists := be.BoundArtifacts[artifactID]
	if !exists {
		return []string{}
	}
	jurisdictions := make([]string, len(bindings))
	for i, binding := range bindings {
		jurisdictions[i] = binding.JurisdictionID
	}
	return jurisdictions
}

// CheckBoundary checks if execution across domains is allowed.
func (be *BoundaryEnforcer) CheckBoundary(
	artifactID string,
	sourceDomainID string,
	targetDomainID string,
) (*BoundaryProof, error) {
	be.mu.RLock()
	defer be.mu.RUnlock()

	sourceDomain, exists1 := be.ExecutionDomains[sourceDomainID]
	targetDomain, exists2 := be.ExecutionDomains[targetDomainID]

	if !exists1 || !exists2 {
		return nil, &JurisdictionalViolation{
			JIBError: JIBError{Message: fmt.Sprintf(
				"artifact %s not bound to source jurisdiction %s",
				artifactID,
				sourceDomainID,
			)},
		}
	}

	artifactJurisdictions := be.ResolveJurisdictionForArtifact(artifactID)
	found := false
	for _, jurisdictionID := range artifactJurisdictions {
		if jurisdictionID == sourceDomain.JurisdictionID {
			found = true
			break
		}
	}
	if !found {
		return nil, &JurisdictionalViolation{
			JIBError: JIBError{Message: fmt.Sprintf(
				"artifact %s not bound to source jurisdiction %s",
				artifactID,
				sourceDomain.JurisdictionID,
			)},
		}
	}

	// Check if target domain is allowed by jurisdiction
	boundaryKey := fmt.Sprintf("%s:%s", sourceDomain.JurisdictionID, targetDomain.JurisdictionID)
	boundary, exists := be.Boundaries[boundaryKey]

	var allowed bool
	var reason string

	if exists {
		allowed = boundary.Allowed
		reason = boundary.Reason
	} else {
		// Default to deny if no explicit boundary defined
		allowed = false
		reason = "No explicit boundary rule defined"
	}

	return &BoundaryProof{
		ID:                 fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", artifactID, sourceDomainID, targetDomainID)))),
		ArtifactID:         artifactID,
		SourceDomainID:     sourceDomainID,
		TargetDomainID:     targetDomainID,
		JurisdictionID:     sourceDomain.JurisdictionID,
		Allowed:            allowed,
		Reason:             reason,
		Timestamp:      	time.Now().Unix(),
		Evidence:           []string{},
	}, nil
}

// EnforceBoundary enforces boundary check and raises if not allowed.
func (be *BoundaryEnforcer) EnforceBoundary(
	artifactID string,
	sourceDomainID string,
	targetDomainID string,
) error {
	proof, err := be.CheckBoundary(artifactID, sourceDomainID, targetDomainID)
	if err != nil {
		return err
	}
	if !proof.Allowed {
		return &JurisdictionalViolation{
			JIBError: JIBError{Message: fmt.Sprintf("cross-domain execution denied: %s", proof.Reason)},
		}
	}
	return nil
}
