package tests

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"
	
	"github.com/pngen/jib/core"
)

func TestCryptographicBindingVerification(t *testing.T) {
	// Generate key pair
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create a binding
	binding := &core.CryptographicBinding{
		ID:                 "binding-123",
		ArtifactID:         "model-x",
		JurisdictionID:     "us-ca",
		BindingType:        "static",
		SignatureAlgorithm: "Ed25519",
		PublicKey:          publicKey,
		Signature:          []byte{},
		ArtifactHash:       "abc123def456",
		Timestamp:          1234567890,
	}

	// Sign the binding
	canonical := binding.CanonicalForm()
	signature := ed25519.Sign(privateKey, []byte(canonical))

	// Update binding with signature
	bindingWithSig := &core.CryptographicBinding{
		ID:                 binding.ID,
		ArtifactID:         binding.ArtifactID,
		JurisdictionID:     binding.JurisdictionID,
		BindingType:        binding.BindingType,
		SignatureAlgorithm: binding.SignatureAlgorithm,
		PublicKey:          binding.PublicKey,
		Signature:          signature,
		ArtifactHash:       binding.ArtifactHash,
		Timestamp:          binding.Timestamp,
	}

	// Verify the signature
	if !bindingWithSig.Verify() {
		t.Error("Binding verification failed")
	}
}

func TestKeyManager(t *testing.T) {
	km := core.NewKeyManager()

	// Generate key pair
	privateKey, _, err := km.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test getting public key bytes
	pubBytes := km.GetPublicKeyBytes(privateKey)
	if len(pubBytes) != 32 { // Ed25519 public key size
		t.Error("Public key byte length mismatch")
	}
}

func TestMerkleTree(t *testing.T) {
	mt := core.NewMerkleTree()

	// Add some leaves
	leaf1Hash := "hash1"
	leaf2Hash := "hash2"
	leaf3Hash := "hash3"

	mt.AddLeaf(leaf1Hash)
	mt.AddLeaf(leaf2Hash)
	mt.AddLeaf(leaf3Hash)

	// Get root
	root := mt.GetRoot()
	if root == "" {
		t.Error("Merkle tree root should not be empty")
	}

	// Get proof for first leaf
	proof := mt.GetProof(0)
	if len(proof) == 0 {
		t.Error("Merkle tree proof should not be empty")
	}
}

func TestThresholdSignature(t *testing.T) {
	// Create threshold scheme (2-of-3)
	ts := core.NewThresholdSignature(2, 3)

	// Generate keys for 3 parties
	privateKeys := make([]ed25519.PrivateKey, 0)
	publicKeys := make([]ed25519.PublicKey, 0)

	for i := 0; i < 3; i++ {
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}
		privateKeys = append(privateKeys, privateKey)
		publicKeys = append(publicKeys, publicKey)
	}

	// Add signers to threshold scheme
	for i, pubKey := range publicKeys {
		ts.AddSigner(fmt.Sprintf("party-%d", i), pubKey)
	}

	// Create binding
	binding := &core.CryptographicBinding{
		ID:                 "test-binding",
		ArtifactID:         "model-x",
		JurisdictionID:     "us-ca",
		BindingType:        "static",
		SignatureAlgorithm: "Ed25519",
		PublicKey:          publicKeys[0],
		Signature:          []byte{},
		ArtifactHash:       "abc123def456",
		Timestamp:          1234567890,
	}

	// Sign with threshold (should work with 2 keys)
	signature, err := ts.SignWithThreshold(binding, privateKeys[:2])
	if err != nil {
		t.Fatalf("Threshold signing failed: %v", err)
	}
	if len(signature) == 0 {
		t.Error("Signature should not be empty")
	}
}

func TestBindingRevocation(t *testing.T) {
	revoker := core.NewBindingRevocation()

	// Revoke a binding
	timestamp := time.Now().Unix()
	revoker.RevokeBinding("binding-123", timestamp)

	// Check if revoked
	if !revoker.IsRevoked("binding-123", timestamp) {
		t.Error("Binding should be revoked")
	}
	if revoker.IsRevoked("binding-123", timestamp-1) {
		t.Error("Binding should not be revoked before timestamp")
	}

	// Check non-revoked binding
	if revoker.IsRevoked("nonexistent", timestamp) {
		t.Error("Non-existent binding should not be revoked")
	}
}