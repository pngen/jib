package core

// BoundaryExpression abstract base for composable boundary expressions.
type BoundaryExpression interface {
	Evaluate(context map[string]interface{}) bool
}

// AtomicBoundary represents primitive boundary rule.
type AtomicBoundary struct {
	BoundaryID string
	Allowed    bool
}

// NewAtomicBoundary creates a new instance of AtomicBoundary.
func NewAtomicBoundary(boundaryID string, allowed bool) *AtomicBoundary {
	return &AtomicBoundary{
		BoundaryID: boundaryID,
		Allowed:    allowed,
	}
}

// Evaluate evaluates boundary expression in context.
func (ab *AtomicBoundary) Evaluate(context map[string]interface{}) bool {
	// In a real implementation, this would look up the actual boundary
	// For now, we'll simulate with a simple lookup
	return ab.Allowed
}

// And returns conjunction of this boundary with another.
func (ab *AtomicBoundary) And(other BoundaryExpression) *AndBoundary {
	return NewAndBoundary(ab, other)
}

// Or returns disjunction of this boundary with another.
func (ab *AtomicBoundary) Or(other BoundaryExpression) *OrBoundary {
	return NewOrBoundary(ab, other)
}

// Not returns negation of this boundary.
func (ab *AtomicBoundary) Not() *NotBoundary {
	return NewNotBoundary(ab)
}

// AndBoundary represents conjunction of two boundaries.
type AndBoundary struct {
	Left  BoundaryExpression
	Right BoundaryExpression
}

// NewAndBoundary creates a new instance of AndBoundary.
func NewAndBoundary(left, right BoundaryExpression) *AndBoundary {
	return &AndBoundary{
		Left:  left,
		Right: right,
	}
}

// Evaluate evaluates boundary expression in context.
func (ab *AndBoundary) Evaluate(context map[string]interface{}) bool {
	return ab.Left.Evaluate(context) && ab.Right.Evaluate(context)
}

// And returns conjunction of this boundary with another.
func (ab *AndBoundary) And(other BoundaryExpression) *AndBoundary {
	return NewAndBoundary(ab, other)
}

// Or returns disjunction of this boundary with another.
func (ab *AndBoundary) Or(other BoundaryExpression) *OrBoundary {
	return NewOrBoundary(ab, other)
}

// Not returns negation of this boundary.
func (ab *AndBoundary) Not() *NotBoundary {
	return NewNotBoundary(ab)
}

// OrBoundary represents disjunction of two boundaries.
type OrBoundary struct {
	Left  BoundaryExpression
	Right BoundaryExpression
}

// NewOrBoundary creates a new instance of OrBoundary.
func NewOrBoundary(left, right BoundaryExpression) *OrBoundary {
	return &OrBoundary{
		Left:  left,
		Right: right,
	}
}

// Evaluate evaluates boundary expression in context.
func (ob *OrBoundary) Evaluate(context map[string]interface{}) bool {
	return ob.Left.Evaluate(context) || ob.Right.Evaluate(context)
}

// And returns conjunction of this boundary with another.
func (ob *OrBoundary) And(other BoundaryExpression) *AndBoundary {
	return NewAndBoundary(ob, other)
}

// Or returns disjunction of this boundary with another.
func (ob *OrBoundary) Or(other BoundaryExpression) *OrBoundary {
	return NewOrBoundary(ob, other)
}

// Not returns negation of this boundary.
func (ob *OrBoundary) Not() *NotBoundary {
	return NewNotBoundary(ob)
}

// NotBoundary represents negation of a boundary.
type NotBoundary struct {
	Expr BoundaryExpression
}

// NewNotBoundary creates a new instance of NotBoundary.
func NewNotBoundary(expr BoundaryExpression) *NotBoundary {
	return &NotBoundary{
		Expr: expr,
	}
}

// Evaluate evaluates boundary expression in context.
func (nb *NotBoundary) Evaluate(context map[string]interface{}) bool {
	return !nb.Expr.Evaluate(context)
}

// And returns conjunction of this boundary with another.
func (nb *NotBoundary) And(other BoundaryExpression) *AndBoundary {
	return NewAndBoundary(nb, other)
}

// Or returns disjunction of this boundary with another.
func (nb *NotBoundary) Or(other BoundaryExpression) *OrBoundary {
	return NewOrBoundary(nb, other)
}

// Not returns negation of this boundary.
func (nb *NotBoundary) Not() *NotBoundary {
	return NewNotBoundary(nb)
}

// PolicyNode represents node in policy tree for hierarchical policy management.
type PolicyNode struct {
	ID          string
	Name        string
	Expression  BoundaryExpression
	ParentID    *string
	Version     string
	Children    []*PolicyNode
}

// NewPolicyNode creates a new instance of PolicyNode.
func NewPolicyNode(
	id, name string,
	expression BoundaryExpression,
	parentIDAndVersion ...string,
) *PolicyNode {
	var parentID *string
	version := ""
	if len(parentIDAndVersion) > 0 {
		parentID = &parentIDAndVersion[0]
	}
	if len(parentIDAndVersion) > 1 {
		version = parentIDAndVersion[1]
	}
	return &PolicyNode{
		ID:          id,
		Name:        name,
		Expression:  expression,
		ParentID:    parentID,
		Version:     version,
		Children:    make([]*PolicyNode, 0),
	}
}

// AddChild adds a child policy node.
func (pn *PolicyNode) AddChild(child *PolicyNode) {
	pn.Children = append(pn.Children, child)
}

// Evaluate evaluates this policy and all children.
func (pn *PolicyNode) Evaluate(context map[string]interface{}) bool {
	result := pn.Expression.Evaluate(context)

	// If this is an AND policy, all children must also be true
	if _, ok := pn.Expression.(*AndBoundary); ok {
		for _, child := range pn.Children {
			if !child.Evaluate(context) {
				return false
			}
		}
	}

	return result
}

// PolicyManager manages hierarchical policies and policy composition.
type PolicyManager struct {
	Policies   map[string]*PolicyNode
	PolicyTree map[string][]string // parent -> children
}

// NewPolicyManager creates a new instance of PolicyManager.
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		Policies:   make(map[string]*PolicyNode),
		PolicyTree: make(map[string][]string),
	}
}

// AddPolicy adds a policy to the manager.
func (pm *PolicyManager) AddPolicy(policy *PolicyNode) {
	pm.Policies[policy.ID] = policy

	if policy.ParentID != nil {
		if _, exists := pm.PolicyTree[*policy.ParentID]; !exists {
			pm.PolicyTree[*policy.ParentID] = make([]string, 0)
		}
		pm.PolicyTree[*policy.ParentID] = append(pm.PolicyTree[*policy.ParentID], policy.ID)
	}
}

// EvaluatePolicy evaluates a specific policy.
func (pm *PolicyManager) EvaluatePolicy(policyID string, context map[string]interface{}) bool {
	policy, exists := pm.Policies[policyID]
	if !exists {
		return false // Policy not found
	}

	return policy.Evaluate(context)
}

// GetPolicyTree gets the policy hierarchy tree.
func (pm *PolicyManager) GetPolicyTree() map[string][]string {
	treeCopy := make(map[string][]string)
	for k, v := range pm.PolicyTree {
		treeCopy[k] = append(treeCopy[k], v...)
	}
	return treeCopy
}

// FindConflicts finds conflicting policies in the system.
func (pm *PolicyManager) FindConflicts() []map[string]interface{} {
	conflicts := make([]map[string]interface{}, 0)
	// Simple conflict detection - check for overlapping boundaries
	// In a real implementation, this would be more sophisticated
	return conflicts
}

// NormalizePolicy normalizes a policy to canonical form (CNF/DNF).
func (pm *PolicyManager) NormalizePolicy(policyID string) BoundaryExpression {
	policy, exists := pm.Policies[policyID]
	if !exists {
		return NewAtomicBoundary("unknown", false)
	}
	// In a real implementation, this would convert to normal form
	// For now, just return the original
	return policy.Expression
}

// PolicySimulator simulates policy evaluation for testing and validation.
type PolicySimulator struct {
	TestCases []map[string]interface{}
}

// NewPolicySimulator creates a new instance of PolicySimulator.
func NewPolicySimulator() *PolicySimulator {
	return &PolicySimulator{
		TestCases: make([]map[string]interface{}, 0),
	}
}

// AddTestCase adds a test case for policy evaluation.
func (ps *PolicySimulator) AddTestCase(context map[string]interface{}, expectedResult bool) {
	ps.TestCases = append(ps.TestCases, map[string]interface{}{
		"context":    context,
		"expected":   expectedResult,
	})
}

// RunSimulation runs simulation of policy evaluation.
func (ps *PolicySimulator) RunSimulation(policy BoundaryExpression) []map[string]interface{} {
	results := make([]map[string]interface{}, 0)

	for i, testCase := range ps.TestCases {
		context := testCase["context"].(map[string]interface{})
		expected := testCase["expected"].(bool)

		actual := policy.Evaluate(context)
		passed := actual == expected

		result := map[string]interface{}{
			"test_id":   i,
			"context":   context,
			"expected":  expected,
			"actual":    actual,
			"passed":    passed,
		}

		results = append(results, result)
	}

	return results
}