package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sync"
)

// KeyManager manages cryptographic keys for JIB bindings.
type KeyManager struct {
	Keys map[string]ed25519.PrivateKey
	mu   sync.RWMutex
}

// NewKeyManager creates a new instance of KeyManager.
func NewKeyManager() *KeyManager {
	return &KeyManager{
		Keys: make(map[string]ed25519.PrivateKey),
	}
}

// GenerateKeyPair generates a new Ed25519 key pair.
func (km *KeyManager) GenerateKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

// SignBinding signs a binding with the given private key.
func (km *KeyManager) SignBinding(privateKey ed25519.PrivateKey, binding *CryptographicBinding) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	canonical := binding.CanonicalForm()
	return ed25519.Sign(privateKey, []byte(canonical)), nil
}

// StoreKey stores a private key for later use.
func (km *KeyManager) StoreKey(keyID string, privateKey ed25519.PrivateKey) {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.Keys[keyID] = privateKey
}

// GetPublicKeyBytes gets the public key bytes from a private key.
func (km *KeyManager) GetPublicKeyBytes(privateKey ed25519.PrivateKey) []byte {
	return privateKey.Public().(ed25519.PublicKey)
}

// GetKey retrieves a stored private key.
func (km *KeyManager) GetKey(keyID string) (ed25519.PrivateKey, bool) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	key, exists := km.Keys[keyID]
	return key, exists
}

// MerkleTree provides tamper-evident log of all bindings.
type MerkleTree struct {
	Leaves []string
	Tree   [][]string
	mu     sync.RWMutex
}

// NewMerkleTree creates a new instance of MerkleTree.
func NewMerkleTree() *MerkleTree {
	return &MerkleTree{
		Leaves: make([]string, 0),
		Tree:   make([][]string, 0),
	}
}

// AddLeaf adds a leaf to the Merkle tree.
func (mt *MerkleTree) AddLeaf(leafHash string) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.Leaves = append(mt.Leaves, leafHash)
	mt.rebuildTree()
}

// GetRoot gets the Merkle root.
func (mt *MerkleTree) GetRoot() string {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	if len(mt.Tree) == 0 {
		return ""
	}
	if len(mt.Tree[len(mt.Tree)-1]) == 0 {
		return ""
	}
	return mt.Tree[len(mt.Tree)-1][0]
}

// GetProof gets a Merkle proof for a specific leaf.
func (mt *MerkleTree) GetProof(leafIndex int) []string {
	if len(mt.Tree) == 0 || leafIndex >= len(mt.Leaves) {
		return []string{}
	}

	proof := make([]string, 0)
	currentIndex := leafIndex

	for i := 0; i < len(mt.Tree)-1; i++ {
		level := mt.Tree[i]
		siblingIndex := currentIndex ^ 1
		if siblingIndex < len(level) {
			proof = append(proof, level[siblingIndex])
		}
		currentIndex /= 2
	}

	return proof
}

// rebuildTree rebuilds the Merkle tree from leaves.
func (mt *MerkleTree) rebuildTree() {
	if len(mt.Leaves) == 0 {
		mt.Tree = make([][]string, 0)
		return
	}

	currentLevel := append(make([]string, 0), mt.Leaves...)
	mt.Tree = append(mt.Tree, currentLevel)

	for len(currentLevel) > 1 {
		nextLevel := make([]string, 0)
		for i := 0; i < len(currentLevel); i += 2 {
			left := currentLevel[i]
			var right string
			if i+1 < len(currentLevel) {
				right = currentLevel[i+1]
			} else {
				right = left
			}
			combined := fmt.Sprintf("%x", sha256.Sum256([]byte(left + right)))
			nextLevel = append(nextLevel, combined)
		}
		currentLevel = nextLevel
		mt.Tree = append(mt.Tree, currentLevel)
	}
}

// ThresholdSignature allows multiple parties to jointly sign a binding.
type ThresholdSignature struct {
	Threshold   int
	TotalParties int
	Signers     map[string]ed25519.PublicKey
}

// NewThresholdSignature creates a new instance of ThresholdSignature.
func NewThresholdSignature(threshold, totalParties int) *ThresholdSignature {
	return &ThresholdSignature{
		Threshold:   threshold,
		TotalParties: totalParties,
		Signers:     make(map[string]ed25519.PublicKey),
	}
}

// AddSigner adds a signer to the threshold scheme.
func (ts *ThresholdSignature) AddSigner(partyID string, publicKey ed25519.PublicKey) {
	ts.Signers[partyID] = publicKey
}

// SignWithThreshold signs with threshold number of parties.
func (ts *ThresholdSignature) SignWithThreshold(binding *CryptographicBinding, privateKeys []ed25519.PrivateKey) ([]byte, error) {
	if len(privateKeys) < ts.Threshold {
		return nil, fmt.Errorf("not enough signers for threshold")
	}

	canonical := binding.CanonicalForm()
	signatures := make([][]byte, 0)

	for _, key := range privateKeys[:ts.Threshold] {
		sig := ed25519.Sign(key, []byte(canonical))
		signatures = append(signatures, sig)
	}

	// Combine signatures (simplified - real implementation would use proper scheme)
	combined := make([]byte, 0)
	for _, sig := range signatures {
		combined = append(combined, sig...)
	}
	return combined, nil
}

// BindingRevocation supports temporal validity and key rotation.
type BindingRevocation struct {
	RevokedBindings map[string]int64 // binding_id -> revocation_time
}

// NewBindingRevocation creates a new instance of BindingRevocation.
func NewBindingRevocation() *BindingRevocation {
	return &BindingRevocation{
		RevokedBindings: make(map[string]int64),
	}
}

// RevokeBinding revokes a binding at the given timestamp.
func (br *BindingRevocation) RevokeBinding(bindingID string, timestamp int64) {
	br.RevokedBindings[bindingID] = timestamp
}

// IsRevoked checks if a binding has been revoked before the given timestamp.
func (br *BindingRevocation) IsRevoked(bindingID string, timestamp int64) bool {
	revocationTime, exists := br.RevokedBindings[bindingID]
	if !exists {
		return false
	}
	return revocationTime <= timestamp
}