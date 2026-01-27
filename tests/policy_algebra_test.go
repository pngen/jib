package tests

import (
	"testing"

	"github.com/pngen/jib/core"
)

func TestAtomicBoundary(t *testing.T) {
	// Test allowed boundary
	allowed := core.NewAtomicBoundary("boundary-1", true)
	if !allowed.Evaluate(map[string]interface{}{}) {
		t.Error("Allowed boundary should evaluate to true")
	}

	// Test denied boundary
	denied := core.NewAtomicBoundary("boundary-2", false)
	if denied.Evaluate(map[string]interface{}{}) {
		t.Error("Denied boundary should evaluate to false")
	}
}

func TestBoundaryComposition(t *testing.T) {
	// Create simple boundaries
	a := core.NewAtomicBoundary("a", true)
	b := core.NewAtomicBoundary("b", false)

	// Test AND
	andResult := a.And(b)
	if andResult.Evaluate(map[string]interface{}{}) {
		t.Error("True AND False should be False")
	}

	// Test OR
	orResult := a.Or(b)
	if !orResult.Evaluate(map[string]interface{}{}) {
		t.Error("True OR False should be True")
	}

	// Test NOT
	notResult := a.Not()
	if notResult.Evaluate(map[string]interface{}{}) {
		t.Error("NOT True should be False")
	}
}

func TestComplexComposition(t *testing.T) {
	// Create boundaries
	a := core.NewAtomicBoundary("a", true)
	b := core.NewAtomicBoundary("b", false)
	c := core.NewAtomicBoundary("c", true)

	// Complex expression: (A AND B) OR (NOT C)
	complexExpr := a.And(b).Or(c.Not())

	// Should be False OR False = False
	if complexExpr.Evaluate(map[string]interface{}{}) {
		t.Error("Complex expression should evaluate to false")
	}
}

func TestPolicyNode(t *testing.T) {
	// Create a simple policy node
	expr := core.NewAtomicBoundary("test-boundary", true)
	node := core.NewPolicyNode(
		"policy-1",
		"Test Policy",
		expr,
	) // parentID and version are optional now

	// Evaluate the policy
	result := node.Evaluate(map[string]interface{}{})
	if !result {
		t.Error("Policy should evaluate to true")
	}
}

func TestPolicyManager(t *testing.T) {
	manager := core.NewPolicyManager()

	// Create policies
	boundaryA := core.NewAtomicBoundary("a", true)
	boundaryB := core.NewAtomicBoundary("b", false)

	policyA := core.NewPolicyNode("policy-a", "Policy A", boundaryA)
	policyB := core.NewPolicyNode("policy-b", "Policy B", boundaryB)

	// Add policies to manager
	manager.AddPolicy(policyA)
	manager.AddPolicy(policyB)

	// Evaluate policies
	resultA := manager.EvaluatePolicy("policy-a", map[string]interface{}{})
	resultB := manager.EvaluatePolicy("policy-b", map[string]interface{}{})

	if !resultA {
		t.Error("Policy A should evaluate to true")
	}
	if resultB {
		t.Error("Policy B should evaluate to false")
	}
}

func TestPolicySimulation(t *testing.T) {
	simulator := core.NewPolicySimulator()

	// Create a simple policy
	policy := core.NewAtomicBoundary("test", true)

	// Add test cases
	simulator.AddTestCase(map[string]interface{}{"artifact": "model-x"}, true)
	simulator.AddTestCase(map[string]interface{}{"artifact": "model-y"}, false)

	// Run simulation
	results := simulator.RunSimulation(policy)

	if len(results) != 2 {
		t.Error("Should have 2 results")
	}
}

func TestPolicyConflictDetection(t *testing.T) {
	manager := core.NewPolicyManager()

	// Add some policies (simplified for testing)
	boundaryA := core.NewAtomicBoundary("a", true)
	policyA := core.NewPolicyNode("policy-a", "Policy A", boundaryA)

	manager.AddPolicy(policyA)

	// Find conflicts (should be empty in simple case)
	conflicts := manager.FindConflicts()
	if len(conflicts) != 0 {
		t.Error("Should have no conflicts")
	}
}