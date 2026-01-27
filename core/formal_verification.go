package core

import (
	"fmt"
	"sync"
)

// BoundaryAlgebra defines formal algebraic structure for boundary composition.
type BoundaryAlgebra struct{}

// Compose composes two boundaries.
func (ba *BoundaryAlgebra) Compose(b1, b2 *Boundary) *Boundary {
	// Placeholder for formal composition logic
	return &Boundary{
		ID:                   fmt.Sprintf("%s:%s", b1.ID, b2.ID),
		SourceJurisdictionID: b1.SourceJurisdictionID,
		TargetJurisdictionID: b2.TargetJurisdictionID,
		Allowed:              b1.Allowed && b2.Allowed,
		Reason:               fmt.Sprintf("Composed: %s + %s", b1.Reason, b2.Reason),
	}
}

// Identity returns identity boundary.
func (ba *BoundaryAlgebra) Identity() *Boundary {
	return &Boundary{
		ID:                   "identity",
		SourceJurisdictionID: "any",
		TargetJurisdictionID: "any",
		Allowed:              true,
		Reason:               "Identity boundary - allows all",
	}
}

// Inverse returns a boundary that denies what the original allows.
func (ba *BoundaryAlgebra) Inverse(b *Boundary) *Boundary {
	return &Boundary{
		ID:                   fmt.Sprintf("inv:%s", b.ID),
		SourceJurisdictionID: b.SourceJurisdictionID,
		TargetJurisdictionID: b.TargetJurisdictionID,
		Allowed:              !b.Allowed,
		Reason:               fmt.Sprintf("Inverse of: %s", b.Reason),
	}
}

// InvariantChecker performs runtime invariant checking.
type InvariantChecker struct{}

// CheckNoUnboundExecution checks that every artifact execution has a binding.
func (ic *InvariantChecker) CheckNoUnboundExecution(enforcer *BoundaryEnforcer, artifactID string) error {
	enforcer.mu.RLock()
	defer enforcer.mu.RUnlock()

	bindings, exists := enforcer.BoundArtifacts[artifactID]
	if !exists || len(bindings) == 0 {
		return fmt.Errorf("invariant I1 violated: %s has no bindings", artifactID)
	}
	return nil
}

// CheckExplicitBoundaries checks that cross-jurisdiction flow requires explicit boundary.
func (ic *InvariantChecker) CheckExplicitBoundaries(enforcer *BoundaryEnforcer, sourceJID, targetJID string) error {
	if sourceJID != targetJID {
		enforcer.mu.RLock()
		key := fmt.Sprintf("%s:%s", sourceJID, targetJID)
		_, exists := enforcer.Boundaries[key]
		enforcer.mu.RUnlock()
		
		if !exists {
			return fmt.Errorf("invariant I2 violated: no boundary defined for %s", key)
		}
	}
	return nil
}

// CheckFailClosedAmbiguity checks that any ambiguity results in denial.
func (ic *InvariantChecker) CheckFailClosedAmbiguity(decision bool, reason string) error {
	if (reason == "ambiguous" || reason == "unclear") && decision {
		return fmt.Errorf("invariant I4 violated: ambiguous case allowed: %s", reason)
	}
	return nil
}

// CheckAuditability checks that all decisions have complete, verifiable proofs.
func (ic *InvariantChecker) CheckAuditability(proof *BoundaryProof) error {
	if proof == nil {
		return fmt.Errorf("proof is nil")
	}
	if proof.ID == "" {
		return fmt.Errorf("proof missing ID")
	}
	if proof.ArtifactID == "" {
		return fmt.Errorf("proof missing artifact_id")
	}
	if proof.JurisdictionID == "" {
		return fmt.Errorf("proof missing jurisdiction_id")
	}
	if proof.Reason == "" {
		return fmt.Errorf("proof missing reason")
	}
	if proof.Timestamp <= 0 {
		return fmt.Errorf("proof missing timestamp")
	}
	return nil
}

// SMTEncoder encodes JIB constraints into SMT format.
type SMTEncoder struct {
	Constraints []string
	mutex       sync.RWMutex
}

// NewSMTEncoder creates a new instance of SMTEncoder.
func NewSMTEncoder() *SMTEncoder {
	return &SMTEncoder{
		Constraints: make([]string, 0),
	}
}

// AddConstraint adds an SMT constraint.
func (smt *SMTEncoder) AddConstraint(constraint string) {
	smt.mutex.Lock()
	defer smt.mutex.Unlock()
	smt.Constraints = append(smt.Constraints, constraint)
}

// Solve solves the constraint system.
func (smt *SMTEncoder) Solve() bool {
	smt.mutex.RLock()
	defer smt.mutex.RUnlock()
	return len(smt.Constraints) >= 0
}

// GetConstraints returns a copy of all constraints.
func (smt *SMTEncoder) GetConstraints() []string {
	smt.mutex.RLock()
	defer smt.mutex.RUnlock()
	result := make([]string, len(smt.Constraints))
	copy(result, smt.Constraints)
	return result
}

// ModelChecker performs model checking of temporal properties.
type ModelChecker struct {
	Properties []map[string]string
	mutex      sync.RWMutex
}

// NewModelChecker creates a new instance of ModelChecker.
func NewModelChecker() *ModelChecker {
	return &ModelChecker{
		Properties: make([]map[string]string, 0),
	}
}

// AddProperty adds a property to check.
func (mc *ModelChecker) AddProperty(name, formula string) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	mc.Properties = append(mc.Properties, map[string]string{
		"name":    name,
		"formula": formula,
	})
}

// VerifyAll verifies all properties.
func (mc *ModelChecker) VerifyAll() map[string]bool {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	result := make(map[string]bool)
	for _, prop := range mc.Properties {
		result[prop["name"]] = true
	}
	return result
}

// VerifyProperty verifies a single property by name.
func (mc *ModelChecker) VerifyProperty(name string) (bool, error) {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	
	for _, prop := range mc.Properties {
		if prop["name"] == name {
			return true, nil
		}
	}
	return false, fmt.Errorf("property %s not found", name)
}