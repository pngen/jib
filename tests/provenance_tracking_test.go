package tests

import (
	"testing"

	"github.com/pngen/jib/core"
)

func TestProvenanceNodeCreation(t *testing.T) {
	node := core.NewProvenanceNode(
		"node-1",
		"model-x",
		"read",
		"us-ca",
		1234567890,
		[]string{"parent-1", "parent-2"},
		map[string]interface{}{"source": "api"},
	)

	if node.ID != "node-1" {
		t.Error("ID mismatch")
	}
	if node.ArtifactID != "model-x" {
		t.Error("Artifact ID mismatch")
	}
	if node.Operation != "read" {
		t.Error("Operation mismatch")
	}
	if node.JurisdictionID != "us-ca" {
		t.Error("Jurisdiction ID mismatch")
	}
	if node.Timestamp != 1234567890 {
		t.Error("Timestamp mismatch")
	}
	if len(node.ParentNodes) != 2 {
		t.Error("Parent nodes count mismatch")
	}
	if node.Metadata["source"].(string) != "api" {
		t.Error("Metadata source mismatch")
	}
}

func TestProvenanceGraph(t *testing.T) {
	graph := core.NewProvenanceGraph()

	// Create nodes
	node1 := core.NewProvenanceNode(
		"node-1",
		"model-x",
		"read",
		"us-ca",
		1234567890,
		[]string{},
		nil,
	)

	node2 := core.NewProvenanceNode(
		"node-2",
		"model-x",
		"transform",
		"us-tx",
		1234567891,
		[]string{"node-1"},
		nil,
	)

	// Add nodes to graph
	graph.AddNode(node1)
	graph.AddNode(node2)

	// Trace lineage
	lineage := graph.TraceLineage("node-2")
	if len(lineage) != 2 {
		t.Error("Should have 2 nodes in lineage")
	}
	if lineage[0].ID != "node-2" {
		t.Error("First node should be node-2")
	}
	if lineage[1].ID != "node-1" {
		t.Error("Second node should be node-1")
	}

	// Find boundary crossings
	crossings := graph.FindBoundaryCrossings("node-2")
	if len(crossings) != 1 {
		t.Error("Should have 1 boundary crossing")
	}
	if crossings[0][0] != "us-ca" || crossings[0][1] != "us-tx" {
		t.Error("Crossing should be from us-ca to us-tx")
	}
}

func TestDataFlowTracker(t *testing.T) {
	tracker := core.NewDataFlowTracker()

	// Record some flows
	tracker.RecordDataFlow("model-x", "read", "us-ca", "us-tx", nil)
	tracker.RecordDataFlow("model-y", "write", "us-ca", "us-ca", nil) // Intra-boundary

	// Get summary
	summary := tracker.GetFlowSummary()
	if summary["total_flows"].(int) != 2 {
		t.Error("Should have 2 total flows")
	}
	if summary["cross_boundary_flows"].(int) != 1 {
		t.Error("Should have 1 cross-boundary flow")
	}
	if summary["intra_boundary_flows"].(int) != 1 {
		t.Error("Should have 1 intra-boundary flow")
	}

	// Get cross-boundary flows
	crossBoundary := tracker.GetCrossBoundaryFlows()
	if len(crossBoundary) != 1 {
		t.Error("Should have 1 cross-boundary flow")
	}
	if crossBoundary[0]["artifact_id"].(string) != "model-x" {
		t.Error("Artifact ID mismatch")
	}

	// Audit compliance
	auditResults := tracker.AuditCompliance("us-ca")
	if len(auditResults) != 2 { // Both flows involve us-ca
		t.Error("Should have 2 audit results for us-ca")
	}
}

func TestGraphValidation(t *testing.T) {
	graph := core.NewProvenanceGraph()

	// Create a simple valid graph
	node1 := core.NewProvenanceNode(
		"node-1",
		"model-x",
		"read",
		"us-ca",
		1234567890,
		[]string{},
		nil,
	)

	node2 := core.NewProvenanceNode(
		"node-2",
		"model-x",
		"transform",
		"us-tx",
		1234567891,
		[]string{"node-1"},
		nil,
	)

	graph.AddNode(node1)
	graph.AddNode(node2)

	// Should be acyclic
	if !graph.ValidateAcyclicity() {
		t.Error("Graph should be acyclic")
	}
}

func TestTaintPropagation(t *testing.T) {
	tracker := core.NewDataFlowTracker()

	// Record flows
	tracker.RecordDataFlow("model-x", "read", "us-ca", "us-tx", nil)
	tracker.RecordDataFlow("model-x", "transform", "us-tx", "us-ca", nil)

	// Check taint propagation (simplified)
	// In a real system, this would be more complex
	// For now, just ensure no panic
}