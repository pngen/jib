package core

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// ProvenanceNode represents a node in provenance graph.
type ProvenanceNode struct {
	ID             string
	ArtifactID     string
	Operation      string // "read", "write", "transform", "transmit"
	JurisdictionID string
	Timestamp      int64
	ParentNodes    []string // IDs of input provenance nodes
	Metadata       map[string]interface{}
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
	if node == nil || node.ID == "" {
		return
	}
	pg.mutex.Lock()
	defer pg.mutex.Unlock()

	// Provenance entries are immutable. Reusing an ID must not overwrite the
	// original node while leaving stale edges behind.
	if _, exists := pg.Nodes[node.ID]; exists {
		return
	}
	stored := cloneProvenanceNode(node)
	pg.Nodes[stored.ID] = stored
	for _, parentID := range stored.ParentNodes {
		if _, exists := pg.Edges[parentID]; !exists {
			pg.Edges[parentID] = make([]string, 0)
		}
		alreadyLinked := false
		for _, childID := range pg.Edges[parentID] {
			if childID == stored.ID {
				alreadyLinked = true
				break
			}
		}
		if !alreadyLinked {
			pg.Edges[parentID] = append(pg.Edges[parentID], stored.ID)
		}
	}
}

// TraceLineage traces full lineage back to source.
func (pg *ProvenanceGraph) TraceLineage(nodeID string) []*ProvenanceNode {
	pg.mutex.RLock()
	defer pg.mutex.RUnlock()

	lineage := make([]*ProvenanceNode, 0)
	visited := make(map[string]bool)

	var dfs func(currentID string)
	dfs = func(currentID string) {
		if visited[currentID] {
			return
		}
		visited[currentID] = true

		if node, exists := pg.Nodes[currentID]; exists {
			lineage = append(lineage, cloneProvenanceNode(node))
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
	pg.mutex.RLock()
	defer pg.mutex.RUnlock()

	crossings := make([]BoundaryCrossing, 0)
	visitedEdges := make(map[[2]string]bool)

	var walk func(string)
	walk = func(childID string) {
		child, exists := pg.Nodes[childID]
		if !exists {
			return
		}
		for _, parentID := range child.ParentNodes {
			edge := [2]string{parentID, childID}
			if visitedEdges[edge] {
				continue
			}
			visitedEdges[edge] = true
			if parent, exists := pg.Nodes[parentID]; exists {
				if parent.JurisdictionID != child.JurisdictionID {
					crossings = append(crossings, BoundaryCrossing{parent.JurisdictionID, child.JurisdictionID})
				}
				walk(parentID)
			}
		}
	}
	walk(nodeID)

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
	pg.mutex.RLock()
	defer pg.mutex.RUnlock()

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
	sequence    uint64
	mutex       sync.RWMutex
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

	dft.mutex.Lock()
	defer dft.mutex.Unlock()
	dft.sequence++

	// The sequence prevents distinct events in the same second from collapsing
	// to one graph node while retaining the caller-supplied event timestamp.
	nodeID := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%s:%d:%d", artifactID, operation, sourceJurisdiction, targetJurisdiction, ts, dft.sequence))))

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
		"node_id":             nodeID,
		"artifact_id":         artifactID,
		"operation":           operation,
		"source_jurisdiction": sourceJurisdiction,
		"target_jurisdiction": targetJurisdiction,
		"timestamp":           ts,
		"cross_boundary":      sourceJurisdiction != targetJurisdiction,
	}

	dft.FlowRecords = append(dft.FlowRecords, flowRecord)
}

// GetCrossBoundaryFlows gets all cross-boundary data flows.
func (dft *DataFlowTracker) GetCrossBoundaryFlows() []map[string]interface{} {
	dft.mutex.RLock()
	defer dft.mutex.RUnlock()

	crossBoundary := make([]map[string]interface{}, 0)
	for _, record := range dft.FlowRecords {
		if record["cross_boundary"].(bool) {
			crossBoundary = append(crossBoundary, cloneFlowRecord(record))
		}
	}
	return crossBoundary
}

// GetFlowSummary gets summary of all recorded flows.
func (dft *DataFlowTracker) GetFlowSummary() map[string]interface{} {
	dft.mutex.RLock()
	defer dft.mutex.RUnlock()

	totalFlows := len(dft.FlowRecords)
	crossBoundaryFlows := 0
	for _, record := range dft.FlowRecords {
		if record["cross_boundary"].(bool) {
			crossBoundaryFlows++
		}
	}

	return map[string]interface{}{
		"total_flows":          totalFlows,
		"cross_boundary_flows": crossBoundaryFlows,
		"intra_boundary_flows": totalFlows - crossBoundaryFlows,
	}
}

// AuditCompliance audits compliance for a specific jurisdiction.
func (dft *DataFlowTracker) AuditCompliance(jurisdictionID string) []map[string]interface{} {
	dft.mutex.RLock()
	defer dft.mutex.RUnlock()

	relevantFlows := make([]map[string]interface{}, 0)

	for _, record := range dft.FlowRecords {
		sourceJID := record["source_jurisdiction"].(string)
		targetJID := record["target_jurisdiction"].(string)
		if sourceJID == jurisdictionID || targetJID == jurisdictionID {
			relevantFlows = append(relevantFlows, cloneFlowRecord(record))
		}
	}

	return relevantFlows
}

func cloneProvenanceNode(node *ProvenanceNode) *ProvenanceNode {
	if node == nil {
		return nil
	}
	return &ProvenanceNode{
		ID:             node.ID,
		ArtifactID:     node.ArtifactID,
		Operation:      node.Operation,
		JurisdictionID: node.JurisdictionID,
		Timestamp:      node.Timestamp,
		ParentNodes:    append([]string(nil), node.ParentNodes...),
		Metadata:       cloneFlowRecord(node.Metadata),
	}
}

func cloneFlowRecord(record map[string]interface{}) map[string]interface{} {
	if record == nil {
		return nil
	}
	cloned := make(map[string]interface{}, len(record))
	for key, value := range record {
		switch typed := value.(type) {
		case []string:
			cloned[key] = append([]string(nil), typed...)
		case map[string]interface{}:
			cloned[key] = cloneFlowRecord(typed)
		default:
			cloned[key] = value
		}
	}
	return cloned
}
