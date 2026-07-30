package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// BoundaryEnforcer enforces jurisdictional boundaries on intelligence execution.
type BoundaryEnforcer struct {
	Jurisdictions    map[string]*Jurisdiction
	ExecutionDomains map[string]*ExecutionDomain
	BoundArtifacts   map[string][]*CryptographicBinding
	Boundaries       map[string]*Boundary
	mu               sync.RWMutex
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
	if !validJurisdictionRegistration(jurisdiction) {
		return
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	be.Jurisdictions[jurisdiction.ID] = cloneJurisdiction(jurisdiction)
}

// RegisterExecutionDomain registers an execution domain.
func (be *BoundaryEnforcer) RegisterExecutionDomain(domain *ExecutionDomain) {
	if !validExecutionDomainRegistration(domain) {
		return
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	be.ExecutionDomains[domain.ID] = cloneExecutionDomain(domain)
}

// RegisterBoundary registers a boundary rule.
func (be *BoundaryEnforcer) RegisterBoundary(boundary *Boundary) {
	if !validBoundaryRegistration(boundary) {
		return
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	key := fmt.Sprintf("%s:%s", boundary.SourceJurisdictionID, boundary.TargetJurisdictionID)
	if existing, exists := be.Boundaries[key]; exists && existing != nil && existing.Allowed != boundary.Allowed {
		// Conflicting rules are order-independent: a deny can replace an allow,
		// but an allow can never silently overwrite an existing deny.
		if !existing.Allowed {
			return
		}
	}
	be.Boundaries[key] = cloneBoundary(boundary)
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

	if strings.TrimSpace(artifactID) == "" || strings.TrimSpace(artifactHash) == "" {
		return nil, &InvalidJurisdictionBinding{
			JIBError: JIBError{Message: "artifact ID and artifact hash are required"},
		}
	}
	if strings.TrimSpace(jurisdictionID) == "" {
		return nil, &InvalidJurisdictionBinding{
			JIBError: JIBError{Message: "jurisdiction ID is required"},
		}
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, &InvalidJurisdictionBinding{
			JIBError: JIBError{Message: "invalid Ed25519 private key"},
		}
	}
	if bindingType == "" {
		bindingType = DefaultBindingType
	}
	if strings.TrimSpace(bindingType) == "" {
		return nil, &InvalidJurisdictionBinding{
			JIBError: JIBError{Message: "binding type is required"},
		}
	}

	if _, exists := be.Jurisdictions[jurisdictionID]; !exists {
		return nil, &InvalidJurisdictionBinding{
			JIBError: JIBError{Message: fmt.Sprintf("jurisdiction %s not registered", jurisdictionID)},
		}
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, &InvalidJurisdictionBinding{
			JIBError: JIBError{Message: fmt.Sprintf("failed to generate binding ID: %v", err)},
		}
	}
	timestamp := time.Now().Unix()
	bindingID := fmt.Sprintf("%x", nonce)

	binding := &CryptographicBinding{
		ID:                 bindingID,
		ArtifactID:         artifactID,
		JurisdictionID:     jurisdictionID,
		BindingType:        bindingType,
		SignatureAlgorithm: "Ed25519",
		PublicKey:          privateKey.Public().(ed25519.PublicKey),
		Signature:          []byte{},
		ArtifactHash:       artifactHash,
		Timestamp:          timestamp,
	}

	canonical := binding.CanonicalForm()
	signature := ed25519.Sign(privateKey, []byte(canonical))
	binding.Signature = signature

	if _, exists := be.BoundArtifacts[artifactID]; !exists {
		be.BoundArtifacts[artifactID] = make([]*CryptographicBinding, 0)
	}
	be.BoundArtifacts[artifactID] = append(be.BoundArtifacts[artifactID], cloneIntegrationBinding(binding))

	return cloneIntegrationBinding(binding), nil
}

// ResolveJurisdictionForArtifact resolves the jurisdiction(s) bound to an artifact.
func (be *BoundaryEnforcer) ResolveJurisdictionForArtifact(artifactID string) []string {
	be.mu.RLock()
	defer be.mu.RUnlock()

	bindings, exists := be.BoundArtifacts[artifactID]
	if !exists {
		return []string{}
	}
	jurisdictionSet := make(map[string]struct{})
	for _, binding := range bindings {
		if !validBindingForArtifact(binding, artifactID) {
			continue
		}
		jurisdiction, exists := be.Jurisdictions[binding.JurisdictionID]
		if !exists || !validJurisdictionRegistration(jurisdiction) || jurisdiction.ID != binding.JurisdictionID {
			continue
		}
		jurisdictionSet[binding.JurisdictionID] = struct{}{}
	}
	jurisdictions := make([]string, 0, len(jurisdictionSet))
	for jurisdictionID := range jurisdictionSet {
		jurisdictions = append(jurisdictions, jurisdictionID)
	}
	sort.Strings(jurisdictions)
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
	if strings.TrimSpace(artifactID) == "" || strings.TrimSpace(sourceDomainID) == "" || strings.TrimSpace(targetDomainID) == "" {
		return nil, &JurisdictionalViolation{
			JIBError: JIBError{Message: "artifact, source domain, and target domain IDs are required"},
		}
	}

	sourceDomain, exists1 := be.ExecutionDomains[sourceDomainID]
	targetDomain, exists2 := be.ExecutionDomains[targetDomainID]

	if !exists1 || !exists2 || !validExecutionDomainRegistration(sourceDomain) || !validExecutionDomainRegistration(targetDomain) ||
		sourceDomain.ID != sourceDomainID || targetDomain.ID != targetDomainID {
		return nil, &JurisdictionalViolation{
			JIBError: JIBError{Message: "source or target execution domain is not registered or is invalid"},
		}
	}
	sourceJurisdiction, exists := be.Jurisdictions[sourceDomain.JurisdictionID]
	if !exists || !validJurisdictionRegistration(sourceJurisdiction) || sourceJurisdiction.ID != sourceDomain.JurisdictionID {
		return nil, &JurisdictionalViolation{
			JIBError: JIBError{Message: fmt.Sprintf("source jurisdiction %s is not registered", sourceDomain.JurisdictionID)},
		}
	}
	targetJurisdiction, exists := be.Jurisdictions[targetDomain.JurisdictionID]
	if !exists || !validJurisdictionRegistration(targetJurisdiction) || targetJurisdiction.ID != targetDomain.JurisdictionID {
		return nil, &JurisdictionalViolation{
			JIBError: JIBError{Message: fmt.Sprintf("target jurisdiction %s is not registered", targetDomain.JurisdictionID)},
		}
	}

	bindings, exists := be.BoundArtifacts[artifactID]
	if !exists || len(bindings) == 0 {
		return nil, &InvalidJurisdictionBinding{
			JIBError: JIBError{Message: fmt.Sprintf("artifact %s has no jurisdiction bindings", artifactID)},
		}
	}

	found := false
	evidenceSet := make(map[string]struct{})
	for _, binding := range bindings {
		if !validBindingForArtifact(binding, artifactID) {
			bindingID := "<invalid>"
			if binding != nil && strings.TrimSpace(binding.ID) != "" {
				bindingID = binding.ID
			}
			return nil, &InvalidJurisdictionBinding{
				JIBError: JIBError{Message: fmt.Sprintf("binding %s is invalid for artifact %s", bindingID, artifactID)},
			}
		}
		if binding.JurisdictionID == sourceDomain.JurisdictionID {
			found = true
			evidenceSet[binding.ID] = struct{}{}
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
	evidence := make([]string, 0, len(evidenceSet))
	for bindingID := range evidenceSet {
		evidence = append(evidence, bindingID)
	}
	sort.Strings(evidence)

	// Check if target domain is allowed by jurisdiction
	boundaryKey := fmt.Sprintf("%s:%s", sourceDomain.JurisdictionID, targetDomain.JurisdictionID)
	boundary, exists := be.Boundaries[boundaryKey]

	var allowed bool
	var reason string

	if exists && validBoundaryRegistration(boundary) &&
		boundary.SourceJurisdictionID == sourceDomain.JurisdictionID &&
		boundary.TargetJurisdictionID == targetDomain.JurisdictionID {
		allowed = boundary.Allowed
		reason = boundary.Reason
	} else if exists {
		allowed = false
		reason = "Invalid boundary rule"
	} else {
		// Default to deny if no explicit boundary defined
		allowed = false
		reason = "No explicit boundary rule defined"
	}

	proof := &BoundaryProof{
		ArtifactID:     artifactID,
		SourceDomainID: sourceDomainID,
		TargetDomainID: targetDomainID,
		JurisdictionID: sourceDomain.JurisdictionID,
		Allowed:        allowed,
		Reason:         reason,
		Timestamp:      time.Now().UnixNano(),
		Evidence:       evidence,
	}
	proof.ID = proof.Hash()
	return proof, nil
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

func validJurisdictionRegistration(jurisdiction *Jurisdiction) bool {
	if jurisdiction == nil || strings.TrimSpace(jurisdiction.ID) == "" || strings.TrimSpace(jurisdiction.Name) == "" {
		return false
	}
	if jurisdiction.Type != SOVEREIGN && jurisdiction.Type != LEGAL && jurisdiction.Type != REGULATORY {
		return false
	}
	return jurisdiction.ParentID == nil || strings.TrimSpace(*jurisdiction.ParentID) != ""
}

func validExecutionDomainRegistration(domain *ExecutionDomain) bool {
	return domain != nil && strings.TrimSpace(domain.ID) != "" && strings.TrimSpace(domain.Name) != "" && strings.TrimSpace(domain.JurisdictionID) != ""
}

func validBoundaryRegistration(boundary *Boundary) bool {
	return boundary != nil && strings.TrimSpace(boundary.ID) != "" &&
		strings.TrimSpace(boundary.SourceJurisdictionID) != "" &&
		strings.TrimSpace(boundary.TargetJurisdictionID) != "" &&
		strings.TrimSpace(boundary.Reason) != ""
}

func validBindingForArtifact(binding *CryptographicBinding, artifactID string) bool {
	return binding != nil && binding.ArtifactID == artifactID && binding.validateUnsigned() == nil && binding.Verify()
}

func cloneJurisdiction(jurisdiction *Jurisdiction) *Jurisdiction {
	clone := *jurisdiction
	if jurisdiction.ParentID != nil {
		parentID := *jurisdiction.ParentID
		clone.ParentID = &parentID
	}
	clone.Attributes = cloneMetadata(jurisdiction.Attributes)
	return &clone
}

func cloneExecutionDomain(domain *ExecutionDomain) *ExecutionDomain {
	clone := *domain
	clone.Metadata = cloneMetadata(domain.Metadata)
	return &clone
}

func cloneBoundary(boundary *Boundary) *Boundary {
	clone := *boundary
	return &clone
}

func cloneMetadata(metadata map[string]interface{}) map[string]interface{} {
	if metadata == nil {
		return nil
	}
	clone := make(map[string]interface{}, len(metadata))
	for key, value := range metadata {
		clone[key] = cloneMetadataValue(value, 0)
	}
	return clone
}

func cloneMetadataValue(value interface{}, depth int) interface{} {
	if depth >= 64 {
		return nil
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		clone := make(map[string]interface{}, len(typed))
		for key, nested := range typed {
			clone[key] = cloneMetadataValue(nested, depth+1)
		}
		return clone
	case []interface{}:
		clone := make([]interface{}, len(typed))
		for index, nested := range typed {
			clone[index] = cloneMetadataValue(nested, depth+1)
		}
		return clone
	case []string:
		return append([]string(nil), typed...)
	case []byte:
		return append([]byte(nil), typed...)
	case map[string]string:
		clone := make(map[string]string, len(typed))
		for key, nested := range typed {
			clone[key] = nested
		}
		return clone
	default:
		return value
	}
}
