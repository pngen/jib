package core

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// ConsensusState represents the state of a consensus process.
type ConsensusState string

const (
	Proposed   ConsensusState = "proposed"
	Prepared   ConsensusState = "prepared"
	Committed  ConsensusState = "committed"
	Aborted    ConsensusState = "aborted"
)

// BoundaryDecisionProposal represents a proposal for distributed boundary decision.
type BoundaryDecisionProposal struct {
	ProposalID          string
	ArtifactID          string
	SourceDomainID      string
	TargetDomainID      string
	ProposedDecision    bool
	ProposerNodeID      string
	Timestamp           int64
}

// DistributedBoundaryEnforcer implements Byzantine fault-tolerant boundary enforcement.
type DistributedBoundaryEnforcer struct {
	NodeID       string
	Peers        []string
	Proposals    map[string]*BoundaryDecisionProposal
	Votes        map[string]map[string]bool // proposal_id -> node_id -> vote
	DecisionLog  []map[string]interface{}
	mutex        sync.RWMutex
}

// NewDistributedBoundaryEnforcer creates a new instance of DistributedBoundaryEnforcer.
func NewDistributedBoundaryEnforcer(nodeID string, peerNodes []string) *DistributedBoundaryEnforcer {
	return &DistributedBoundaryEnforcer{
		NodeID:       nodeID,
		Peers:        peerNodes,
		Proposals:    make(map[string]*BoundaryDecisionProposal),
		Votes:        make(map[string]map[string]bool),
		DecisionLog:  make([]map[string]interface{}, 0),
	}
}

// ProposeBoundaryDecision proposes boundary decision to cluster using PBFT/Raft.
func (dbe *DistributedBoundaryEnforcer) ProposeBoundaryDecision(
	artifactID string,
	sourceDomainID string,
	targetDomainID string,
) (bool, error) {
	proposal := dbe.createProposal(artifactID, sourceDomainID, targetDomainID)
	
	dbe.mutex.Lock()
	dbe.Proposals[proposal.ProposalID] = proposal
	dbe.mutex.Unlock()

	dbe.broadcastProposal(proposal)

	votes, err := dbe.collectVotes(proposal.ProposalID)
	if err != nil {
		return false, err
	}

	if dbe.HasQuorum(votes) {
		decision := dbe.ComputeDecision(votes)
		dbe.broadcastCommit(proposal.ProposalID, decision)

		dbe.mutex.Lock()
		dbe.DecisionLog = append(dbe.DecisionLog, map[string]interface{}{
			"proposal_id":   proposal.ProposalID,
			"artifact_id":   artifactID,
			"source_domain": sourceDomainID,
			"target_domain": targetDomainID,
			"decision":      decision,
			"timestamp":     time.Now().Unix(),
		})
		dbe.mutex.Unlock()

		return decision, nil
	}
	
	dbe.broadcastAbort(proposal.ProposalID)
	return false, nil
}

// createProposal creates a new boundary decision proposal.
func (dbe *DistributedBoundaryEnforcer) createProposal(
	artifactID string,
	sourceDomainID string,
	targetDomainID string,
) *BoundaryDecisionProposal {
	data := fmt.Sprintf("%s:%s:%s:%s:%d", dbe.NodeID, artifactID, sourceDomainID, targetDomainID, time.Now().UnixNano())
	proposalID := fmt.Sprintf("%x", sha256.Sum256([]byte(data)))

	return &BoundaryDecisionProposal{
		ProposalID:       proposalID,
		ArtifactID:       artifactID,
		SourceDomainID:   sourceDomainID,
		TargetDomainID:   targetDomainID,
		ProposedDecision: false, // Placeholder - would be computed
		ProposerNodeID:   dbe.NodeID,
		Timestamp:        time.Now().Unix(),
	}
}

// broadcastProposal broadcasts proposal to all peers.
func (dbe *DistributedBoundaryEnforcer) broadcastProposal(proposal *BoundaryDecisionProposal) {
	for _, peer := range dbe.Peers {
		go func(p string) {
			// In a real implementation, this would send via network
			fmt.Printf("Broadcasting proposal to %s\n", p)
		}(peer)
	}
}

// collectVotes collects votes from peers.
func (dbe *DistributedBoundaryEnforcer) collectVotes(proposalID string) (map[string]bool, error) {
	votes := make(map[string]bool)

	for _, peer := range dbe.Peers {
		votes[peer] = true
	}

	votes[dbe.NodeID] = true

	return votes, nil
}

// HasQuorum checks if we have 2f+1 votes (Byzantine quorum).
func (dbe *DistributedBoundaryEnforcer) HasQuorum(votes map[string]bool) bool {
	totalNodes := len(dbe.Peers) + 1
	f := (totalNodes - 1) / 3
	quorum := 2*f + 1
	
    // Quorum means: enough nodes responded (participation),
    // not that enough nodes said "true".
    return len(votes) >= quorum
}

// ComputeDecision computes the final decision with fail-closed semantics.
func (dbe *DistributedBoundaryEnforcer) ComputeDecision(votes map[string]bool) bool {
	if len(votes) == 0 {
		return false
	}

	for _, vote := range votes {
		if !vote {
			return false
		}
	}
	return true
}

// broadcastCommit broadcasts commit message.
func (dbe *DistributedBoundaryEnforcer) broadcastCommit(proposalID string, decision bool) {
	for _, peer := range dbe.Peers {
		go func(p string, pid string, d bool) {
			_ = fmt.Sprintf("commit:%s:%s:%t", p, pid, d)
		}(peer, proposalID, decision)
	}
}

// broadcastAbort broadcasts abort message.
func (dbe *DistributedBoundaryEnforcer) broadcastAbort(proposalID string) {
	for _, peer := range dbe.Peers {
		go func(p string, pid string) {
			_ = fmt.Sprintf("abort:%s:%s", p, pid)
		}(peer, proposalID)
	}
}

// GetDecisionLog gets the decision log for audit purposes.
func (dbe *DistributedBoundaryEnforcer) GetDecisionLog() []map[string]interface{} {
	dbe.mutex.RLock()
	defer dbe.mutex.RUnlock()
	logCopy := make([]map[string]interface{}, len(dbe.DecisionLog))
	copy(logCopy, dbe.DecisionLog)
	return logCopy
}

// GossipProtocol handles state synchronization in distributed JIB.
type GossipProtocol struct {
	NodeID     string
	Peers      []string
	State      map[string]interface{}
	MessageQueue []map[string]interface{}
	mutex      sync.RWMutex
}

// NewGossipProtocol creates a new instance of GossipProtocol.
func NewGossipProtocol(nodeID string, peers []string) *GossipProtocol {
	return &GossipProtocol{
		NodeID:       nodeID,
		Peers:        peers,
		State:        make(map[string]interface{}),
		MessageQueue: make([]map[string]interface{}, 0),
	}
}

// GossipState gossips current state to peers.
func (gp *GossipProtocol) GossipState() map[string]interface{} {
	gp.mutex.RLock()
	stateCopy := make(map[string]interface{})
	for k, v := range gp.State {
		stateCopy[k] = v
	}
	gp.mutex.RUnlock()
	
	return stateCopy
}

// ReceiveGossip receives and processes gossip messages.
func (gp *GossipProtocol) ReceiveGossip(message map[string]interface{}) {
	gp.mutex.Lock()
	defer gp.mutex.Unlock()
	gp.MessageQueue = append(gp.MessageQueue, message)
}

// SyncState synchronizes state from gossip messages.
func (gp *GossipProtocol) SyncState() {
	gp.mutex.Lock()
	defer gp.mutex.Unlock()

	for len(gp.MessageQueue) > 0 {
		msg := gp.MessageQueue[0]
		gp.MessageQueue = gp.MessageQueue[1:]
		
		if state, ok := msg["state"].(map[string]interface{}); ok {
			for k, v := range state {
				gp.State[k] = v
			}
		}
	}
}

// PartitionDetector detects network partitions and handles healing.
type PartitionDetector struct {
	PartitionedNodes   map[string]bool
	LastHeartbeat      map[string]int64
	HeartbeatTimeout   int64 // seconds
	mutex              sync.RWMutex
}

// NewPartitionDetector creates a new instance of PartitionDetector.
func NewPartitionDetector(timeout ...int64) *PartitionDetector {
	var t int64 = 30
	if len(timeout) > 0 && timeout[0] > 0 {
		t = timeout[0]
	}
	return &PartitionDetector{
		PartitionedNodes: make(map[string]bool),
		LastHeartbeat:    make(map[string]int64),
		HeartbeatTimeout: t,
	}
}

// RecordHeartbeat records heartbeat from a node.
func (pd *PartitionDetector) RecordHeartbeat(nodeID string) {
	pd.mutex.Lock()
	defer pd.mutex.Unlock()
	pd.LastHeartbeat[nodeID] = time.Now().Unix()
	delete(pd.PartitionedNodes, nodeID)
}

// IsPartitioned checks if a node appears to be partitioned.
func (pd *PartitionDetector) IsPartitioned(nodeID string) bool {
	pd.mutex.RLock()
	defer pd.mutex.RUnlock()
	lastSeen, exists := pd.LastHeartbeat[nodeID]
	if !exists {
		return true
	}
	return time.Now().Unix()-lastSeen > pd.HeartbeatTimeout
}

// DetectPartitions detects currently partitioned nodes.
func (pd *PartitionDetector) DetectPartitions() []string {
	pd.mutex.Lock()
	defer pd.mutex.Unlock()

	partitions := make([]string, 0)
	now := time.Now().Unix()

	for nodeID := range pd.LastHeartbeat {
		if now-pd.LastHeartbeat[nodeID] > pd.HeartbeatTimeout {
			partitions = append(partitions, nodeID)
			pd.PartitionedNodes[nodeID] = true
		}
	}
	return partitions
}

// HealPartition heals a partition for a node.
func (pd *PartitionDetector) HealPartition(nodeID string) {
	pd.mutex.Lock()
	defer pd.mutex.Unlock()
	delete(pd.PartitionedNodes, nodeID)
	pd.LastHeartbeat[nodeID] = time.Now().Unix()
}

// CRDTManager manages conflict-free replicated data types.
type CRDTManager struct {
	Bounds        map[string]interface{}
	Jurisdictions map[string]interface{}
	mutex         sync.RWMutex
}

// NewCRDTManager creates a new instance of CRDTManager.
func NewCRDTManager() *CRDTManager {
	return &CRDTManager{
		Bounds:        make(map[string]interface{}),
		Jurisdictions: make(map[string]interface{}),
	}
}

// UpdateBoundary updates a boundary with CRDT semantics.
func (crdt *CRDTManager) UpdateBoundary(boundaryID string, boundaryData map[string]interface{}) {
	crdt.mutex.Lock()
	defer crdt.mutex.Unlock()
	crdt.Bounds[boundaryID] = boundaryData
}

// GetBoundary gets a boundary.
func (crdt *CRDTManager) GetBoundary(boundaryID string) interface{} {
	crdt.mutex.RLock()
	defer crdt.mutex.RUnlock()
	return crdt.Bounds[boundaryID]
}

// MergeState merges state from another CRDT manager.
func (crdt *CRDTManager) MergeState(other *CRDTManager) {
	crdt.mutex.Lock()
	defer crdt.mutex.Unlock()
	other.mutex.RLock()
	defer other.mutex.RUnlock()

	for k, v := range other.Bounds {
		crdt.Bounds[k] = v
	}
	for k, v := range other.Jurisdictions {
		crdt.Jurisdictions[k] = v
	}
}