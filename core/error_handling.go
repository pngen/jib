package core

import (
	"fmt"
	"time"
)

// BoundaryEnforcementError enhances error with recovery context.
type BoundaryEnforcementError struct {
	Message      string
	Ctx          map[string]interface{}
	Timestamp    int64
	RecoveryHint string
}

func (e *BoundaryEnforcementError) Error() string {
	return e.Message
}

// Context returns the error context.
func (e *BoundaryEnforcementError) Context() map[string]interface{} {
	return e.Ctx
}

// UnauthorizedJurisdictionAccess is raised when unauthorized access to jurisdiction is attempted.
type UnauthorizedJurisdictionAccess struct {
	BoundaryEnforcementError
}

// BindingIntegrityViolation is raised when binding integrity is compromised.
type BindingIntegrityViolation struct {
	BoundaryEnforcementError
}

// TemporalConstraintViolation is raised when temporal constraints are violated.
type TemporalConstraintViolation struct {
	BoundaryEnforcementError
}

// ConsensusFailure is raised when distributed consensus fails.
type ConsensusFailure struct {
	BoundaryEnforcementError
}

// InvariantViolation is raised when system invariants are violated.
type InvariantViolation struct {
	BoundaryEnforcementError
}

// BoundaryVerificationError is raised when boundary verification fails.
type BoundaryVerificationError struct {
	Message   string
	BindingID string
	ErrorType string
	Timestamp int64
}

func (e *BoundaryVerificationError) Error() string {
	return e.Message
}

// JIBRecoveryContext provides information needed to recover from errors.
type JIBRecoveryContext struct {
	Err             error
	RecoveryActions []map[string]interface{}
}

// NewJIBRecoveryContext creates a new recovery context.
func NewJIBRecoveryContext(err error) *JIBRecoveryContext {
	return &JIBRecoveryContext{
		Err:             err,
		RecoveryActions: make([]map[string]interface{}, 0),
	}
}

// AddRecoveryAction adds a recovery action to the context.
func (jrc *JIBRecoveryContext) AddRecoveryAction(action string, details map[string]interface{}) {
	jrc.RecoveryActions = append(jrc.RecoveryActions, map[string]interface{}{
		"action":    action,
		"details":   details,
		"timestamp": time.Now().Unix(),
	})
}

// GetRecoveryPlan gets complete recovery plan.
func (jrc *JIBRecoveryContext) GetRecoveryPlan() map[string]interface{} {
	plan := map[string]interface{}{
		"error_message":    jrc.Err.Error(),
		"recovery_actions": jrc.RecoveryActions,
	}
	
	if ctxProvider, ok := jrc.Err.(interface{ Context() map[string]interface{} }); ok {
		plan["context"] = ctxProvider.Context()
	}
	
	return plan
}

// NewUnauthorizedJurisdictionAccess creates a new unauthorized access error.
func NewUnauthorizedJurisdictionAccess(artifactID, jurisdictionID string) *UnauthorizedJurisdictionAccess {
	return &UnauthorizedJurisdictionAccess{
		BoundaryEnforcementError: BoundaryEnforcementError{
			Message:      fmt.Sprintf("access denied to jurisdiction %s for artifact %s", jurisdictionID, artifactID),
			Ctx:          map[string]interface{}{"artifact_id": artifactID, "requested_jurisdiction": jurisdictionID},
			Timestamp:    time.Now().Unix(),
			RecoveryHint: "check jurisdiction bindings and permissions",
		},
	}
}

// NewBindingIntegrityViolation creates a new binding integrity violation error.
func NewBindingIntegrityViolation(bindingID, artifactID string) *BindingIntegrityViolation {
	return &BindingIntegrityViolation{
		BoundaryEnforcementError: BoundaryEnforcementError{
			Message:      fmt.Sprintf("binding integrity violated for %s", bindingID),
			Ctx:          map[string]interface{}{"binding_id": bindingID, "artifact_id": artifactID},
			Timestamp:    time.Now().Unix(),
			RecoveryHint: "verify binding signature and re-bind if necessary",
		},
	}
}

// NewTemporalConstraintViolation creates a new temporal constraint violation error.
func NewTemporalConstraintViolation(boundaryKey string, timestamp int64) *TemporalConstraintViolation {
	return &TemporalConstraintViolation{
		BoundaryEnforcementError: BoundaryEnforcementError{
			Message:      fmt.Sprintf("no valid temporal boundary for %s at timestamp %d", boundaryKey, timestamp),
			Ctx:          map[string]interface{}{"boundary_key": boundaryKey, "timestamp": timestamp},
			Timestamp:    time.Now().Unix(),
			RecoveryHint: "check temporal boundary validity window",
		},
	}
}

// NewConsensusFailure creates a new consensus failure error.
func NewConsensusFailure(msg string, ctx map[string]interface{}) *ConsensusFailure {
	return &ConsensusFailure{
		BoundaryEnforcementError: BoundaryEnforcementError{
			Message:      msg,
			Ctx:          ctx,
			Timestamp:    time.Now().Unix(),
			RecoveryHint: "retry with increased timeout or check cluster health",
		},
	}
}

// NewInvariantViolation creates a new invariant violation error.
func NewInvariantViolation(invariant string, details map[string]interface{}) *InvariantViolation {
	return &InvariantViolation{
		BoundaryEnforcementError: BoundaryEnforcementError{
			Message:      fmt.Sprintf("invariant violated: %s", invariant),
			Ctx:          details,
			Timestamp:    time.Now().Unix(),
			RecoveryHint: "review system state and correct violations",
		},
	}
}