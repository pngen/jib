package tests

import (
	"testing"
	"time"

	"github.com/pngen/jib/core"
)

func TestBaseJIBError(t *testing.T) {
	error := &core.JIBError{
		Message:   "Test error",
		Ctx:       map[string]interface{}{"context": "test"},
		Timestamp: 1234567890,
	}

	if error.Error() != "Test error" {
		t.Error("Message mismatch")
	}
	if error.Message != "Test error" {
		t.Error("Message field mismatch")
	}
	if error.Ctx["context"] != "test" {
		t.Error("Context mismatch")
	}
}

func TestBoundaryEnforcementError(t *testing.T) {
	err := &core.BoundaryEnforcementError{
		Message:      "Access denied",
		Ctx:          map[string]interface{}{"artifact": "model-x", "user": "user-123"},
		Timestamp:    1234567890,
		RecoveryHint: "Check permissions and bindings",
	}

	if err.Error() != "Access denied" {
		t.Error("Message mismatch")
	}
	if err.Ctx["artifact"] != "model-x" {
		t.Error("Context artifact mismatch")
	}
	if err.RecoveryHint != "Check permissions and bindings" {
		t.Error("Recovery hint mismatch")
	}
}

func TestSpecificErrorTypes(t *testing.T) {
	// Test error types can be created via constructors
	ujaErr := core.NewUnauthorizedJurisdictionAccess("model-x", "us-tx")
	if ujaErr.Error() == "" {
		t.Error("UnauthorizedJurisdictionAccess should have message")
	}

	bivErr := core.NewBindingIntegrityViolation("binding-123", "model-x")
	if bivErr.Error() == "" {
		t.Error("BindingIntegrityViolation should have message")
	}

	tcvErr := core.NewTemporalConstraintViolation("us-ca:us-tx", time.Now().Unix())
	if tcvErr.Error() == "" {
		t.Error("TemporalConstraintViolation should have message")
	}
}

func TestRecoveryContext(t *testing.T) {
	err := &core.BoundaryEnforcementError{
		Message:   "Test error",
		Ctx:       map[string]interface{}{"test": "context"},
		Timestamp: 1234567890,
	}
	ctx := core.NewJIBRecoveryContext(err)

	// Add recovery actions
	ctx.AddRecoveryAction("check_bindings", map[string]interface{}{"artifact": "model-x"})
	ctx.AddRecoveryAction("verify_permissions", map[string]interface{}{"user": "user-123"})

	// Get recovery plan
	plan := ctx.GetRecoveryPlan()
	if plan["error_message"] != "Test error" {
		t.Error("Error message mismatch")
	}
	if len(plan["recovery_actions"].([]map[string]interface{})) != 2 {
		t.Error("Should have two recovery actions")
	}
}

func TestErrorInheritance(t *testing.T) {
	// All specific errors implement error interface
	errors := []error{
		&core.UnauthorizedJurisdictionAccess{},
		&core.BindingIntegrityViolation{},
		&core.TemporalConstraintViolation{},
		&core.ConsensusFailure{},
		&core.InvariantViolation{},
	}

	for _, err := range errors {
		// Just verify they implement error interface (compilation check)
		_ = err.Error()
	}
}