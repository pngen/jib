package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"time"

	"github.com/pngen/jib/core"
)

// SampleJurisdiction fixture for testing.
func SampleJurisdiction() *core.Jurisdiction {
	return &core.Jurisdiction{
		ID:   "test-jid",
		Name: "Test Jurisdiction",
		Type: core.SOVEREIGN,
	}
}

// SampleExecutionDomain fixture for testing.
func SampleExecutionDomain(jurisdiction *core.Jurisdiction) *core.ExecutionDomain {
	return &core.ExecutionDomain{
		ID:             "test-domain",
		Name:           "Test Domain",
		JurisdictionID: jurisdiction.ID,
	}
}

// SamplePrivateKey fixture for testing.
func SamplePrivateKey() ed25519.PrivateKey {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { panic(err) }
	return privateKey
}

// SampleKeyPair returns both private and public keys.
func SampleKeyPair() (ed25519.PrivateKey, ed25519.PublicKey) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { panic(err) }
	return privateKey, publicKey
}

// ResearchEnforcer fixture for testing.
func ResearchEnforcer() *core.ResearchGradeBoundaryEnforcer {
	return core.NewResearchGradeBoundaryEnforcer("test-node", []string{})
}

// Int64Ptr helper for creating int64 pointers in tests.
func Int64Ptr(i int64) *int64 {
	return &i
}

// NowUnix returns current Unix timestamp.
func NowUnix() int64 {
	return time.Now().Unix()
}