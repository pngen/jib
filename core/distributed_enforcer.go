package core

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ConsensusState represents the state of a consensus process.
type ConsensusState string

const (
	Proposed  ConsensusState = "proposed"
	Prepared  ConsensusState = "prepared"
	Committed ConsensusState = "committed"
	Aborted   ConsensusState = "aborted"
)

// BoundaryDecisionProposal represents a proposal for distributed boundary decision.
type BoundaryDecisionProposal struct {
	ProposalID       string
	ArtifactID       string
	SourceDomainID   string
	TargetDomainID   string
	ProposedDecision bool
	ProposerNodeID   string
	Timestamp        int64
}

// DistributedBoundaryEnforcer implements Byzantine fault-tolerant boundary enforcement.
type DistributedBoundaryEnforcer struct {
	NodeID      string
	Peers       []string
	Proposals   map[string]*BoundaryDecisionProposal
	Votes       map[string]map[string]bool // proposal_id -> node_id -> vote
	DecisionLog []map[string]interface{}
	mutex       sync.RWMutex
}

// NewDistributedBoundaryEnforcer creates a new instance of DistributedBoundaryEnforcer.
func NewDistributedBoundaryEnforcer(nodeID string, peerNodes []string) *DistributedBoundaryEnforcer {
	seen := make(map[string]bool, len(peerNodes))
	peers := make([]string, 0, len(peerNodes))
	for _, peer := range peerNodes {
		if peer == "" || peer == nodeID || seen[peer] {
			continue
		}
		seen[peer] = true
		peers = append(peers, peer)
	}
	sort.Strings(peers)
	return &DistributedBoundaryEnforcer{
		NodeID:      nodeID,
		Peers:       peers,
		Proposals:   make(map[string]*BoundaryDecisionProposal),
		Votes:       make(map[string]map[string]bool),
		DecisionLog: make([]map[string]interface{}, 0),
	}
}

// ProposeBoundaryDecision proposes boundary decision to cluster using PBFT/Raft.
func (dbe *DistributedBoundaryEnforcer) ProposeBoundaryDecision(
	artifactID string,
	sourceDomainID string,
	targetDomainID string,
) (bool, error) {
	// The legacy API has no authoritative local decision to propose, so it must
	// fail closed instead of manufacturing an allow vote.
	return dbe.ProposeBoundaryDecisionWithDecision(artifactID, sourceDomainID, targetDomainID, false)
}

// ProposeBoundaryDecisionWithDecision proposes an already-computed local
// enforcement decision. Configured peers must contribute their own votes;
// their presence is never treated as an affirmative response.
func (dbe *DistributedBoundaryEnforcer) ProposeBoundaryDecisionWithDecision(
	artifactID string,
	sourceDomainID string,
	targetDomainID string,
	proposedDecision bool,
) (bool, error) {
	proposal := dbe.createProposal(artifactID, sourceDomainID, targetDomainID, proposedDecision)

	dbe.mutex.Lock()
	dbe.Proposals[proposal.ProposalID] = proposal
	if _, exists := dbe.Votes[proposal.ProposalID]; !exists {
		dbe.Votes[proposal.ProposalID] = make(map[string]bool)
	}
	dbe.Votes[proposal.ProposalID][dbe.NodeID] = proposedDecision
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
	proposedDecision bool,
) *BoundaryDecisionProposal {
	data := fmt.Sprintf("%s:%s:%s:%s:%t", dbe.NodeID, artifactID, sourceDomainID, targetDomainID, proposedDecision)
	proposalID := fmt.Sprintf("%x", sha256.Sum256([]byte(data)))

	return &BoundaryDecisionProposal{
		ProposalID:       proposalID,
		ArtifactID:       artifactID,
		SourceDomainID:   sourceDomainID,
		TargetDomainID:   targetDomainID,
		ProposedDecision: proposedDecision,
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
	dbe.mutex.RLock()
	defer dbe.mutex.RUnlock()
	stored, exists := dbe.Votes[proposalID]
	if !exists {
		return map[string]bool{}, nil
	}
	votes := make(map[string]bool, len(stored))
	for nodeID, vote := range stored {
		if dbe.isMember(nodeID) {
			votes[nodeID] = vote
		}
	}
	return votes, nil
}

// RecordVote records a vote from a configured cluster member. Unknown nodes
// and unknown proposals are rejected rather than influencing quorum.
func (dbe *DistributedBoundaryEnforcer) RecordVote(proposalID, nodeID string, decision bool) bool {
	dbe.mutex.Lock()
	defer dbe.mutex.Unlock()
	if !dbe.isMember(nodeID) {
		return false
	}
	if _, exists := dbe.Proposals[proposalID]; !exists {
		return false
	}
	if _, exists := dbe.Votes[proposalID]; !exists {
		dbe.Votes[proposalID] = make(map[string]bool)
	}
	dbe.Votes[proposalID][nodeID] = decision
	return true
}

// HasQuorum checks if we have 2f+1 votes (Byzantine quorum).
func (dbe *DistributedBoundaryEnforcer) HasQuorum(votes map[string]bool) bool {
	totalNodes := len(dbe.Peers) + 1
	f := (totalNodes - 1) / 3
	quorum := 2*f + 1
	majority := totalNodes/2 + 1
	if majority > quorum {
		quorum = majority
	}
	participants := 0
	for nodeID := range votes {
		if dbe.isMember(nodeID) {
			participants++
		}
	}
	return participants >= quorum
}

func (dbe *DistributedBoundaryEnforcer) isMember(nodeID string) bool {
	if nodeID == dbe.NodeID {
		return true
	}
	for _, peer := range dbe.Peers {
		if peer == nodeID {
			return true
		}
	}
	return false
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
	for index, entry := range dbe.DecisionLog {
		logCopy[index] = cloneDistributedValue(entry).(map[string]interface{})
	}
	return logCopy
}

// GossipProtocol handles state synchronization in distributed JIB.
type GossipProtocol struct {
	NodeID       string
	Peers        []string
	State        map[string]interface{}
	MessageQueue []map[string]interface{}
	mutex        sync.RWMutex
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
	stateCopy := cloneDistributedValue(gp.State).(map[string]interface{})
	gp.mutex.RUnlock()

	return stateCopy
}

// ReceiveGossip receives and processes gossip messages.
func (gp *GossipProtocol) ReceiveGossip(message map[string]interface{}) {
	if message == nil {
		return
	}
	gp.mutex.Lock()
	defer gp.mutex.Unlock()
	gp.MessageQueue = append(gp.MessageQueue, cloneDistributedValue(message).(map[string]interface{}))
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
	PartitionedNodes map[string]bool
	LastHeartbeat    map[string]int64
	HeartbeatTimeout int64 // seconds
	mutex            sync.RWMutex
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
	if boundaryID == "" || boundaryData == nil {
		return
	}
	crdt.mutex.Lock()
	defer crdt.mutex.Unlock()
	crdt.Bounds[boundaryID] = cloneDistributedValue(boundaryData)
}

// GetBoundary gets a boundary.
func (crdt *CRDTManager) GetBoundary(boundaryID string) interface{} {
	crdt.mutex.RLock()
	defer crdt.mutex.RUnlock()
	return cloneDistributedValue(crdt.Bounds[boundaryID])
}

// MergeState merges state from another CRDT manager.
func (crdt *CRDTManager) MergeState(other *CRDTManager) {
	if other == nil {
		return
	}
	other.mutex.RLock()
	otherBounds := make(map[string]interface{}, len(other.Bounds))
	for key, value := range other.Bounds {
		otherBounds[key] = cloneDistributedValue(value)
	}
	otherJurisdictions := make(map[string]interface{}, len(other.Jurisdictions))
	for key, value := range other.Jurisdictions {
		otherJurisdictions[key] = cloneDistributedValue(value)
	}
	other.mutex.RUnlock()

	crdt.mutex.Lock()
	defer crdt.mutex.Unlock()
	for key, incoming := range otherBounds {
		if existing, exists := crdt.Bounds[key]; exists {
			crdt.Bounds[key] = mergeDistributedValue(existing, incoming)
		} else {
			crdt.Bounds[key] = cloneDistributedValue(incoming)
		}
	}
	for key, incoming := range otherJurisdictions {
		if existing, exists := crdt.Jurisdictions[key]; exists {
			crdt.Jurisdictions[key] = mergeDistributedValue(existing, incoming)
		} else {
			crdt.Jurisdictions[key] = cloneDistributedValue(incoming)
		}
	}
}

func mergeDistributedValue(existing, incoming interface{}) interface{} {
	existingMap, existingIsMap := existing.(map[string]interface{})
	incomingMap, incomingIsMap := incoming.(map[string]interface{})
	if existingIsMap && incomingIsMap {
		existingAllowed, existingHasAllowed := existingMap["allowed"].(bool)
		incomingAllowed, incomingHasAllowed := incomingMap["allowed"].(bool)
		if existingHasAllowed && incomingHasAllowed && existingAllowed != incomingAllowed {
			if !existingAllowed {
				return cloneDistributedValue(existingMap)
			}
			return cloneDistributedValue(incomingMap)
		}
	}
	existingJSON, existingErr := json.Marshal(existing)
	incomingJSON, incomingErr := json.Marshal(incoming)
	if existingErr != nil || incomingErr != nil {
		// Unsupported conflicts cannot safely replace established governance.
		return cloneDistributedValue(existing)
	}
	if string(incomingJSON) < string(existingJSON) {
		return cloneDistributedValue(incoming)
	}
	return cloneDistributedValue(existing)
}

func cloneDistributedValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		cloned := make(map[string]interface{}, len(typed))
		for key, nested := range typed {
			cloned[key] = cloneDistributedValue(nested)
		}
		return cloned
	case []interface{}:
		cloned := make([]interface{}, len(typed))
		for index, nested := range typed {
			cloned[index] = cloneDistributedValue(nested)
		}
		return cloned
	case []string:
		return append([]string(nil), typed...)
	default:
		return value
	}
}
