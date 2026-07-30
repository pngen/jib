package core

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// IntegrationAdapter handles integration with external systems.
type IntegrationAdapter struct {
	Bindings map[string]*CryptographicBinding
	Proofs   map[string]*BoundaryProof
	mutex    sync.RWMutex
}

// NewIntegrationAdapter creates a new instance of IntegrationAdapter.
func NewIntegrationAdapter() *IntegrationAdapter {
	return &IntegrationAdapter{
		Bindings: make(map[string]*CryptographicBinding),
		Proofs:   make(map[string]*BoundaryProof),
	}
}

// RegisterBinding registers a binding for integration purposes.
func (ia *IntegrationAdapter) RegisterBinding(binding *CryptographicBinding) error {
	if ia == nil {
		return fmt.Errorf("integration adapter is nil")
	}
	if binding == nil {
		return fmt.Errorf("binding is nil")
	}
	candidate := cloneIntegrationBinding(binding)
	if !candidate.Verify() {
		return fmt.Errorf("binding %q failed cryptographic verification", candidate.ID)
	}

	ia.mutex.Lock()
	defer ia.mutex.Unlock()
	if ia.Bindings == nil {
		ia.Bindings = make(map[string]*CryptographicBinding)
	}
	if existing, exists := ia.Bindings[candidate.ID]; exists {
		if equalIntegrationBindings(existing, candidate) {
			return nil
		}
		return fmt.Errorf("binding ID %q is already registered with different content", candidate.ID)
	}
	ia.Bindings[candidate.ID] = candidate
	return nil
}

// PrepareExecutionContext prepares execution context for an artifact in a domain.
func (ia *IntegrationAdapter) PrepareExecutionContext(artifactID string, domainID string) map[string]interface{} {
	if ia == nil {
		return map[string]interface{}{
			"artifact_id":           artifactID,
			"domain_id":             domainID,
			"jurisdiction_bindings": []map[string]interface{}{},
		}
	}
	ia.mutex.RLock()
	defer ia.mutex.RUnlock()

	var bindings []*CryptographicBinding
	for _, binding := range ia.Bindings {
		if binding != nil && binding.ArtifactID == artifactID {
			bindings = append(bindings, binding)
		}
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].ID < bindings[j].ID })

	jurisdictionBindings := make([]map[string]interface{}, len(bindings))
	for i, binding := range bindings {
		jurisdictionBindings[i] = map[string]interface{}{
			"id":                  binding.ID,
			"artifact_id":         binding.ArtifactID,
			"jurisdiction_id":     binding.JurisdictionID,
			"binding_type":        binding.BindingType,
			"signature_algorithm": binding.SignatureAlgorithm,
			"public_key":          append([]byte(nil), binding.PublicKey...),
			"signature":           append([]byte(nil), binding.Signature...),
			"artifact_hash":       binding.ArtifactHash,
			"timestamp":           binding.Timestamp,
		}
	}

	return map[string]interface{}{
		"artifact_id":           artifactID,
		"domain_id":             domainID,
		"jurisdiction_bindings": jurisdictionBindings,
	}
}

// EmitProof emits a boundary proof to external systems.
func (ia *IntegrationAdapter) EmitProof(proof *BoundaryProof) error {
	if ia == nil {
		return fmt.Errorf("integration adapter is nil")
	}
	candidate := cloneIntegrationProof(proof)
	if err := validateIntegrationProof(candidate); err != nil {
		return err
	}

	ia.mutex.Lock()
	defer ia.mutex.Unlock()
	if ia.Proofs == nil {
		ia.Proofs = make(map[string]*BoundaryProof)
	}
	if existing, exists := ia.Proofs[candidate.ID]; exists {
		if equalIntegrationProofs(existing, candidate) {
			return nil
		}
		return fmt.Errorf("proof ID %q is already registered with different content", candidate.ID)
	}
	ia.Proofs[candidate.ID] = candidate
	return nil
}

// GetProof retrieves a previously emitted proof.
func (ia *IntegrationAdapter) GetProof(proofID string) *BoundaryProof {
	if ia == nil {
		return nil
	}
	ia.mutex.RLock()
	defer ia.mutex.RUnlock()
	return cloneIntegrationProof(ia.Proofs[proofID])
}

// ValidateExecutionDomain validates that an execution domain is properly configured.
func (ia *IntegrationAdapter) ValidateExecutionDomain(domain *ExecutionDomain) bool {
	return domain != nil && strings.TrimSpace(domain.ID) != "" && strings.TrimSpace(domain.JurisdictionID) != ""
}

// GetJurisdictionInfo gets jurisdiction information for integration purposes.
func (ia *IntegrationAdapter) GetJurisdictionInfo(jurisdictionID string) map[string]interface{} {
	return map[string]interface{}{
		"id":   jurisdictionID,
		"name": "Unknown Jurisdiction",
		"type": "unknown",
	}
}

// GetAllProofs returns all emitted proofs.
func (ia *IntegrationAdapter) GetAllProofs() []*BoundaryProof {
	if ia == nil {
		return []*BoundaryProof{}
	}
	ia.mutex.RLock()
	defer ia.mutex.RUnlock()

	ids := make([]string, 0, len(ia.Proofs))
	for id := range ia.Proofs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	proofs := make([]*BoundaryProof, 0, len(ids))
	for _, id := range ids {
		if proof := ia.Proofs[id]; proof != nil {
			proofs = append(proofs, cloneIntegrationProof(proof))
		}
	}
	return proofs
}

// GetBindingsForArtifact returns all bindings for a specific artifact.
func (ia *IntegrationAdapter) GetBindingsForArtifact(artifactID string) []*CryptographicBinding {
	if ia == nil {
		return []*CryptographicBinding{}
	}
	ia.mutex.RLock()
	defer ia.mutex.RUnlock()

	bindings := make([]*CryptographicBinding, 0)
	for _, binding := range ia.Bindings {
		if binding != nil && binding.ArtifactID == artifactID {
			bindings = append(bindings, cloneIntegrationBinding(binding))
		}
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].ID < bindings[j].ID })
	return bindings
}

func cloneIntegrationBinding(binding *CryptographicBinding) *CryptographicBinding {
	if binding == nil {
		return nil
	}
	clone := *binding
	clone.PublicKey = append([]byte(nil), binding.PublicKey...)
	clone.Signature = append([]byte(nil), binding.Signature...)
	return &clone
}

func equalIntegrationBindings(left, right *CryptographicBinding) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.ID == right.ID &&
		left.ArtifactID == right.ArtifactID &&
		left.JurisdictionID == right.JurisdictionID &&
		left.BindingType == right.BindingType &&
		left.SignatureAlgorithm == right.SignatureAlgorithm &&
		bytes.Equal(left.PublicKey, right.PublicKey) &&
		bytes.Equal(left.Signature, right.Signature) &&
		left.ArtifactHash == right.ArtifactHash &&
		left.Timestamp == right.Timestamp
}

func cloneIntegrationProof(proof *BoundaryProof) *BoundaryProof {
	if proof == nil {
		return nil
	}
	clone := *proof
	clone.Evidence = append([]string{}, proof.Evidence...)
	return &clone
}

func validateIntegrationProof(proof *BoundaryProof) error {
	if proof == nil {
		return fmt.Errorf("proof is nil")
	}
	if strings.TrimSpace(proof.ID) == "" {
		return fmt.Errorf("proof ID is required")
	}
	if strings.TrimSpace(proof.ArtifactID) == "" {
		return fmt.Errorf("proof artifact ID is required")
	}
	if strings.TrimSpace(proof.SourceDomainID) == "" || strings.TrimSpace(proof.TargetDomainID) == "" {
		return fmt.Errorf("proof source and target domain IDs are required")
	}
	if strings.TrimSpace(proof.JurisdictionID) == "" {
		return fmt.Errorf("proof jurisdiction ID is required")
	}
	if strings.TrimSpace(proof.Reason) == "" {
		return fmt.Errorf("proof reason is required")
	}
	if proof.Timestamp <= 0 {
		return fmt.Errorf("proof timestamp must be positive")
	}
	if proof.ID != proof.Hash() {
		return fmt.Errorf("proof ID does not match semantic content hash")
	}
	return nil
}

func equalIntegrationProofs(left, right *BoundaryProof) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.ID == right.ID && left.Hash() == right.Hash()
}
