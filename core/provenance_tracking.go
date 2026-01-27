package core

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// ProvenanceNode represents a node in provenance graph.
type ProvenanceNode struct {
	ID              string
	ArtifactID      string
	Operation       string // "read", "write", "transform", "transmit"
	JurisdictionID  string
	Timestamp       int64
	ParentNodes     []string // IDs of input provenance nodes
	Metadata        map[string]interface{}
}

// NewProvenanceNode creates a new instance of ProvenanceNode.
func NewProvenanceNode(
	id string,
	artifactID string,
	operation string,
	jurisdictionID string,
	timestamp int64,
	parentNodes []string,
	metadata map[string]interface{},
) *ProvenanceNode {
	return &ProvenanceNode{
		ID:             id,
		ArtifactID:     artifactID,
		Operation:      operation,
		JurisdictionID: jurisdictionID,
		Timestamp:      timestamp,
		ParentNodes:    parentNodes,
		Metadata:       metadata,
	}
}

// ProvenanceGraph represents a directed acyclic graph tracking data lineage.
type ProvenanceGraph struct {
	Nodes map[string]*ProvenanceNode
	Edges map[string][]string
	mutex sync.RWMutex
}

// NewProvenanceGraph creates a new instance of ProvenanceGraph.
func NewProvenanceGraph() *ProvenanceGraph {
	return &ProvenanceGraph{
		Nodes: make(map[string]*ProvenanceNode),
		Edges: make(map[string][]string),
	}
}

// AddNode adds provenance node to graph.
func (pg *ProvenanceGraph) AddNode(node *ProvenanceNode) {
	pg.mutex.Lock()
	defer pg.mutex.Unlock()

	pg.Nodes[node.ID] = node
	for _, parentID := range node.ParentNodes {
		if _, exists := pg.Edges[parentID]; !exists {
			pg.Edges[parentID] = make([]string, 0)
		}
		pg.Edges[parentID] = append(pg.Edges[parentID], node.ID)
	}
}

// TraceLineage traces full lineage back to source.
func (pg *ProvenanceGraph) TraceLineage(nodeID string) []*ProvenanceNode {
	pg.mutex.RLock()
	lineage := make([]*ProvenanceNode, 0)
	visited := make(map[string]bool)

	var dfs func(currentID string)
	dfs = func(currentID string) {
		if visited[currentID] {
			return
		}
		visited[currentID] = true

		if node, exists := pg.Nodes[currentID]; exists {
			lineage = append(lineage, node)
			for _, parentID := range node.ParentNodes {
				dfs(parentID)
			}
		}
	}

	dfs(nodeID)
	return lineage
}

// FindBoundaryCrossings finds all jurisdiction boundary crossings in lineage.
func (pg *ProvenanceGraph) FindBoundaryCrossings(nodeID string) []BoundaryCrossing {
	lineage := pg.TraceLineage(nodeID)
	crossings := make([]BoundaryCrossing, 0)

	// lineage is [child, ..., parent], so walk it backwards to emit parent -> child crossings.
	for i := len(lineage) - 1; i > 0; i-- {
		from := lineage[i]
		to := lineage[i-1]

		if from.JurisdictionID != to.JurisdictionID {
			crossings = append(crossings, BoundaryCrossing{from.JurisdictionID, to.JurisdictionID})
		}
	}

	return crossings
}

// CheckTaintPropagation checks if taint from source propagates to target.
func (pg *ProvenanceGraph) CheckTaintPropagation(
	sourceNodeID string,
	targetNodeID string,
	taintLabel string,
) bool {
	lineage := pg.TraceLineage(targetNodeID)

	// Check if source is in the lineage
	for _, node := range lineage {
		if node.ID == sourceNodeID {
			return true
		}
	}

	return false
}

// GetJurisdictionSummary gets summary of jurisdictions involved in lineage.
func (pg *ProvenanceGraph) GetJurisdictionSummary(nodeID string) map[string]int {
	lineage := pg.TraceLineage(nodeID)
	jurisdictionCounts := make(map[string]int)

	for _, node := range lineage {
		jurisdictionCounts[node.JurisdictionID]++
	}

	return jurisdictionCounts
}

// ValidateAcyclicity validates that the graph is acyclic.
func (pg *ProvenanceGraph) ValidateAcyclicity() bool {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var dfs func(nodeID string) bool
	dfs = func(nodeID string) bool {
		if _, exists := pg.Nodes[nodeID]; !exists {
			return true
		}

		if recStack[nodeID] {
			return false // Cycle detected
		}

		if visited[nodeID] {
			return true // Already processed
		}

		visited[nodeID] = true
		recStack[nodeID] = true

		// Check all children
		for _, childID := range pg.Edges[nodeID] {
			if !dfs(childID) {
				return false
			}
		}

		recStack[nodeID] = false
		return true
	}

	// Check all nodes
	for nodeID := range pg.Nodes {
		if !visited[nodeID] {
			if !dfs(nodeID) {
				return false
			}
		}
	}

	return true
}

// DataFlowTracker tracks data flows across jurisdictional boundaries.
type DataFlowTracker struct {
	Graph       *ProvenanceGraph
	FlowRecords []map[string]interface{}
}

// NewDataFlowTracker creates a new instance of DataFlowTracker.
func NewDataFlowTracker() *DataFlowTracker {
	return &DataFlowTracker{
		Graph:       NewProvenanceGraph(),
		FlowRecords: make([]map[string]interface{}, 0),
	}
}

// RecordDataFlow records a data flow event.
func (dft *DataFlowTracker) RecordDataFlow(
	artifactID string,
	operation string,
	sourceJurisdiction string,
	targetJurisdiction string,
	timestamp *int64,
) {
	var ts int64
	if timestamp != nil {
		ts = *timestamp
	} else {
		ts = time.Now().Unix()
	}

	// Create provenance node for this operation
	nodeID := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%s:%d", artifactID, operation, sourceJurisdiction, targetJurisdiction, ts))))

	node := NewProvenanceNode(
		nodeID,
		artifactID,
		operation,
		sourceJurisdiction,
		ts,
		[]string{}, // No parents for initial flow
		map[string]interface{}{
			"target_jurisdiction": targetJurisdiction,
			"flow_type":           "cross_boundary",
		},
	)

	dft.Graph.AddNode(node)

	// Record the flow
	flowRecord := map[string]interface{}{
		"node_id":              nodeID,
		"artifact_id":          artifactID,
		"operation":            operation,
		"source_jurisdiction":  sourceJurisdiction,
		"target_jurisdiction":  targetJurisdiction,
		"timestamp":            ts,
		"cross_boundary":       sourceJurisdiction != targetJurisdiction,
	}

	dft.FlowRecords = append(dft.FlowRecords, flowRecord)
}

// GetCrossBoundaryFlows gets all cross-boundary data flows.
func (dft *DataFlowTracker) GetCrossBoundaryFlows() []map[string]interface{} {
	crossBoundary := make([]map[string]interface{}, 0)
	for _, record := range dft.FlowRecords {
		if record["cross_boundary"].(bool) {
			crossBoundary = append(crossBoundary, record)
		}
	}
	return crossBoundary
}

// GetFlowSummary gets summary of all recorded flows.
func (dft *DataFlowTracker) GetFlowSummary() map[string]interface{} {
	totalFlows := len(dft.FlowRecords)
	crossBoundaryFlows := 0
	for _, record := range dft.FlowRecords {
		if record["cross_boundary"].(bool) {
			crossBoundaryFlows++
		}
	}

	return map[string]interface{}{
		"total_flows":           totalFlows,
		"cross_boundary_flows":  crossBoundaryFlows,
		"intra_boundary_flows":  totalFlows - crossBoundaryFlows,
	}
}

// AuditCompliance audits compliance for a specific jurisdiction.
func (dft *DataFlowTracker) AuditCompliance(jurisdictionID string) []map[string]interface{} {
	relevantFlows := make([]map[string]interface{}, 0)

	for _, record := range dft.FlowRecords {
		sourceJID := record["source_jurisdiction"].(string)
		targetJID := record["target_jurisdiction"].(string)
		if sourceJID == jurisdictionID || targetJID == jurisdictionID {
			relevantFlows = append(relevantFlows, record)
		}
	}

	return relevantFlows
}