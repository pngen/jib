package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
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
	return append(ed25519.PrivateKey(nil), privateKey...), append(ed25519.PublicKey(nil), publicKey...), nil
}

// SignBinding signs a binding with the given private key.
func (km *KeyManager) SignBinding(privateKey ed25519.PrivateKey, binding *CryptographicBinding) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length: %d", len(privateKey))
	}
	if err := binding.validateUnsigned(); err != nil {
		return nil, fmt.Errorf("invalid binding: %w", err)
	}
	publicKey := privateKey[ed25519.SeedSize:]
	if !bytes.Equal(publicKey, binding.PublicKey) {
		return nil, fmt.Errorf("private key does not match binding public key")
	}
	canonical := binding.CanonicalForm()
	signature := ed25519.Sign(privateKey, []byte(canonical))
	return append([]byte(nil), signature...), nil
}

// StoreKey stores a private key for later use.
func (km *KeyManager) StoreKey(keyID string, privateKey ed25519.PrivateKey) error {
	if km == nil {
		return fmt.Errorf("key manager is nil")
	}
	if strings.TrimSpace(keyID) == "" {
		return fmt.Errorf("key ID is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid Ed25519 private key length: %d", len(privateKey))
	}
	km.mu.Lock()
	defer km.mu.Unlock()
	if km.Keys == nil {
		km.Keys = make(map[string]ed25519.PrivateKey)
	}
	km.Keys[keyID] = append(ed25519.PrivateKey(nil), privateKey...)
	return nil
}

// GetPublicKeyBytes gets the public key bytes from a private key.
func (km *KeyManager) GetPublicKeyBytes(privateKey ed25519.PrivateKey) []byte {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil
	}
	return append([]byte(nil), privateKey[ed25519.SeedSize:]...)
}

// GetKey retrieves a stored private key.
func (km *KeyManager) GetKey(keyID string) (ed25519.PrivateKey, bool) {
	if km == nil {
		return nil, false
	}
	km.mu.RLock()
	defer km.mu.RUnlock()
	key, exists := km.Keys[keyID]
	if !exists || len(key) != ed25519.PrivateKeySize {
		return nil, false
	}
	return append(ed25519.PrivateKey(nil), key...), true
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
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	if len(mt.Tree) == 0 || leafIndex < 0 || leafIndex >= len(mt.Leaves) {
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

	mt.Tree = make([][]string, 0)
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
			combined := fmt.Sprintf("%x", sha256.Sum256([]byte(left+right)))
			nextLevel = append(nextLevel, combined)
		}
		currentLevel = nextLevel
		mt.Tree = append(mt.Tree, currentLevel)
	}
}

// ThresholdSignature allows multiple parties to jointly sign a binding.
type ThresholdSignature struct {
	Threshold    int
	TotalParties int
	Signers      map[string]ed25519.PublicKey
	mu           sync.RWMutex
}

// NewThresholdSignature creates a new instance of ThresholdSignature.
func NewThresholdSignature(threshold, totalParties int) *ThresholdSignature {
	return &ThresholdSignature{
		Threshold:    threshold,
		TotalParties: totalParties,
		Signers:      make(map[string]ed25519.PublicKey),
	}
}

// AddSigner adds a signer to the threshold scheme.
func (ts *ThresholdSignature) AddSigner(partyID string, publicKey ed25519.PublicKey) error {
	if ts == nil {
		return fmt.Errorf("threshold signature is nil")
	}
	if err := ts.validateConfiguration(); err != nil {
		return err
	}
	if strings.TrimSpace(partyID) == "" {
		return fmt.Errorf("party ID is required")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key length: %d", len(publicKey))
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.Signers == nil {
		ts.Signers = make(map[string]ed25519.PublicKey)
	}
	if existing, exists := ts.Signers[partyID]; exists {
		if bytes.Equal(existing, publicKey) {
			return nil
		}
		return fmt.Errorf("party %q is already registered with a different key", partyID)
	}
	if len(ts.Signers) >= ts.TotalParties {
		return fmt.Errorf("registered signer count exceeds total parties")
	}
	for existingID, existing := range ts.Signers {
		if bytes.Equal(existing, publicKey) {
			return fmt.Errorf("public key is already registered to party %q", existingID)
		}
	}
	ts.Signers[partyID] = append(ed25519.PublicKey(nil), publicKey...)
	return nil
}

// SignWithThreshold signs with threshold number of parties.
func (ts *ThresholdSignature) SignWithThreshold(binding *CryptographicBinding, privateKeys []ed25519.PrivateKey) ([]byte, error) {
	if ts == nil {
		return nil, fmt.Errorf("threshold signature is nil")
	}
	if err := ts.validateConfiguration(); err != nil {
		return nil, err
	}
	if err := binding.validateUnsigned(); err != nil {
		return nil, fmt.Errorf("invalid binding: %w", err)
	}

	ts.mu.RLock()
	registered := make(map[string]struct{}, len(ts.Signers))
	for partyID, publicKey := range ts.Signers {
		if strings.TrimSpace(partyID) == "" || len(publicKey) != ed25519.PublicKeySize {
			ts.mu.RUnlock()
			return nil, fmt.Errorf("registered signer set contains invalid entries")
		}
		fingerprint := fmt.Sprintf("%x", sha256.Sum256(publicKey))
		if _, duplicate := registered[fingerprint]; duplicate {
			ts.mu.RUnlock()
			return nil, fmt.Errorf("registered signer set contains duplicate public keys")
		}
		registered[fingerprint] = struct{}{}
	}
	ts.mu.RUnlock()

	if len(registered) < ts.Threshold {
		return nil, fmt.Errorf("not enough distinct registered signers for threshold")
	}
	if len(registered) > ts.TotalParties {
		return nil, fmt.Errorf("registered signer count exceeds total parties")
	}
	if len(privateKeys) < ts.Threshold {
		return nil, fmt.Errorf("not enough private keys for threshold")
	}

	type thresholdKey struct {
		fingerprint string
		privateKey  ed25519.PrivateKey
	}
	keys := make([]thresholdKey, 0, len(privateKeys))
	seen := make(map[string]struct{}, len(privateKeys))
	for _, privateKey := range privateKeys {
		if len(privateKey) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid Ed25519 private key length: %d", len(privateKey))
		}
		publicKey := privateKey[ed25519.SeedSize:]
		fingerprint := fmt.Sprintf("%x", sha256.Sum256(publicKey))
		if _, ok := registered[fingerprint]; !ok {
			return nil, fmt.Errorf("private key is not registered as a signer")
		}
		if _, duplicate := seen[fingerprint]; duplicate {
			return nil, fmt.Errorf("duplicate private key supplied for threshold signing")
		}
		seen[fingerprint] = struct{}{}
		keys = append(keys, thresholdKey{
			fingerprint: fingerprint,
			privateKey:  append(ed25519.PrivateKey(nil), privateKey...),
		})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].fingerprint < keys[j].fingerprint })

	canonical := []byte(binding.CanonicalForm())
	combined := make([]byte, 0, ts.Threshold*ed25519.SignatureSize)
	for _, key := range keys[:ts.Threshold] {
		combined = append(combined, ed25519.Sign(key.privateKey, canonical)...)
	}
	return combined, nil
}

func (ts *ThresholdSignature) validateConfiguration() error {
	if ts.Threshold <= 0 {
		return fmt.Errorf("threshold must be positive")
	}
	if ts.TotalParties <= 0 {
		return fmt.Errorf("total parties must be positive")
	}
	if ts.Threshold > ts.TotalParties {
		return fmt.Errorf("threshold cannot exceed total parties")
	}
	return nil
}

// BindingRevocation supports temporal validity and key rotation.
type BindingRevocation struct {
	RevokedBindings map[string]int64 // binding_id -> revocation_time
	mu              sync.RWMutex
}

// NewBindingRevocation creates a new instance of BindingRevocation.
func NewBindingRevocation() *BindingRevocation {
	return &BindingRevocation{
		RevokedBindings: make(map[string]int64),
	}
}

// RevokeBinding revokes a binding at the given timestamp.
func (br *BindingRevocation) RevokeBinding(bindingID string, timestamp int64) {
	if br == nil {
		return
	}
	br.mu.Lock()
	defer br.mu.Unlock()
	if br.RevokedBindings == nil {
		br.RevokedBindings = make(map[string]int64)
	}
	br.RevokedBindings[bindingID] = timestamp
}

// IsRevoked checks if a binding has been revoked before the given timestamp.
func (br *BindingRevocation) IsRevoked(bindingID string, timestamp int64) bool {
	if br == nil {
		return false
	}
	br.mu.RLock()
	defer br.mu.RUnlock()
	revocationTime, exists := br.RevokedBindings[bindingID]
	if !exists {
		return false
	}
	return revocationTime <= timestamp
}
