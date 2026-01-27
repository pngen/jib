package tests

import (
	"testing"

	"github.com/pngen/jib/core"
)

func TestDistributedEnforcer(t *testing.T) {
	// Create a simple distributed enforcer
	peers := []string{"node-1", "node-2", "node-3"}
	enforcer := core.NewDistributedBoundaryEnforcer("node-1", peers)

	// Test quorum calculation
	votes := map[string]bool{
		"node-1": true,
		"node-2": true,
		"node-3": false,
	}
	if !enforcer.HasQuorum(votes) {
		t.Error("Should have quorum")
	}

	// Test decision computation
	decision := enforcer.ComputeDecision(votes)
	if decision {
		t.Error("Should be false due to not all agreeing")
	}
}

func TestGossipProtocol(t *testing.T) {
	peers := []string{"node-1", "node-2", "node-3"}
	gossip := core.NewGossipProtocol("node-1", peers)

	// Test state synchronization
	testState := map[string]interface{}{
		"boundaries": []string{"boundary-1"},
		"jurisdictions": []string{"us-ca"},
	}
	gossip.State = testState

	// Simulate receiving gossip
	message := map[string]interface{}{
		"state": map[string]interface{}{
			"boundaries": []string{"boundary-2"},
		},
	}
	gossip.ReceiveGossip(message)

	// Test sync
	gossip.SyncState()
	if _, exists := gossip.State["boundaries"]; !exists {
		t.Error("Should have boundaries in state")
	}
}

func TestPartitionDetector(t *testing.T) {
	detector := core.NewPartitionDetector(30)

	// Record heartbeats
	detector.RecordHeartbeat("node-1")
	detector.RecordHeartbeat("node-2")

	// Test partition detection
	if detector.IsPartitioned("node-1") {
		t.Error("Node should not be partitioned")
	}
	if detector.IsPartitioned("node-2") {
		t.Error("Node should not be partitioned")
	}

	// Test unknown node is partitioned
	if !detector.IsPartitioned("unknown-node") {
		t.Error("Unknown node should be considered partitioned")
	}
}

func TestCRDTManager(t *testing.T) {
	crdt := core.NewCRDTManager()

	// Test boundary updates
	boundaryData := map[string]interface{}{
		"id":           "boundary-1",
		"source":       "us-ca",
		"target":       "us-tx",
		"allowed":      true,
	}

	crdt.UpdateBoundary("boundary-1", boundaryData)

	// Retrieve boundary
	retrieved := crdt.GetBoundary("boundary-1")
	if retrieved == nil {
		t.Error("Should retrieve boundary")
	}
	if retrieved.(map[string]interface{})["id"].(string) != "boundary-1" {
		t.Error("Retrieved boundary ID mismatch")
	}

	// Test merge
	otherCrdt := core.NewCRDTManager()
	otherBoundary := map[string]interface{}{
		"id":           "boundary-2",
		"source":       "us-nv",
		"target":       "us-ca",
		"allowed":      false,
	}
	otherCrdt.UpdateBoundary("boundary-2", otherBoundary)

	crdt.MergeState(otherCrdt)
	if crdt.GetBoundary("boundary-2") == nil {
		t.Error("Should have merged boundary")
	}
}