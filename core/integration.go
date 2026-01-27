package core

import (
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
func (ia *IntegrationAdapter) RegisterBinding(binding *CryptographicBinding) {
	ia.mutex.Lock()
	defer ia.mutex.Unlock()
	ia.Bindings[binding.ID] = binding
}

// PrepareExecutionContext prepares execution context for an artifact in a domain.
func (ia *IntegrationAdapter) PrepareExecutionContext(artifactID string, domainID string) map[string]interface{} {
	ia.mutex.RLock()
	defer ia.mutex.RUnlock()

	var bindings []*CryptographicBinding
	for _, binding := range ia.Bindings {
		if binding.ArtifactID == artifactID {
			bindings = append(bindings, binding)
		}
	}

	jurisdictionBindings := make([]map[string]interface{}, len(bindings))
	for i, binding := range bindings {
		jurisdictionBindings[i] = map[string]interface{}{
			"id":              binding.ID,
			"jurisdiction_id": binding.JurisdictionID,
			"binding_type":    binding.BindingType,
		}
	}

	return map[string]interface{}{
		"artifact_id":           artifactID,
		"domain_id":             domainID,
		"jurisdiction_bindings": jurisdictionBindings,
	}
}

// EmitProof emits a boundary proof to external systems.
func (ia *IntegrationAdapter) EmitProof(proof *BoundaryProof) {
	ia.mutex.Lock()
	defer ia.mutex.Unlock()
	ia.Proofs[proof.ID] = proof
}

// GetProof retrieves a previously emitted proof.
func (ia *IntegrationAdapter) GetProof(proofID string) *BoundaryProof {
	ia.mutex.RLock()
	defer ia.mutex.RUnlock()
	return ia.Proofs[proofID]
}

// ValidateExecutionDomain validates that an execution domain is properly configured.
func (ia *IntegrationAdapter) ValidateExecutionDomain(domain *ExecutionDomain) bool {
	return domain != nil && domain.ID != "" && domain.JurisdictionID != ""
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
	ia.mutex.RLock()
	defer ia.mutex.RUnlock()
	
	proofs := make([]*BoundaryProof, 0, len(ia.Proofs))
	for _, proof := range ia.Proofs {
		proofs = append(proofs, proof)
	}
	return proofs
}

// GetBindingsForArtifact returns all bindings for a specific artifact.
func (ia *IntegrationAdapter) GetBindingsForArtifact(artifactID string) []*CryptographicBinding {
	ia.mutex.RLock()
	defer ia.mutex.RUnlock()
	
	bindings := make([]*CryptographicBinding, 0)
	for _, binding := range ia.Bindings {
		if binding.ArtifactID == artifactID {
			bindings = append(bindings, binding)
		}
	}
	return bindings
}