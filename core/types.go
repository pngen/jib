package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// JurisdictionType represents type of jurisdiction.
type JurisdictionType string

const (
	SOVEREIGN     JurisdictionType = "sovereign"
	LEGAL         JurisdictionType = "legal"
	REGULATORY    JurisdictionType = "regulatory"
)

// BindingType constants
const DefaultBindingType = "static"

// Jurisdiction represents a legally or sovereignly defined execution domain.
type Jurisdiction struct {
	ID          string
	Name        string
	Type        JurisdictionType
	ParentID    *string
	Attributes  map[string]interface{}
}

// ExecutionDomain represents a concrete environment where intelligence runs.
type ExecutionDomain struct {
	ID              string
	Name            string
	JurisdictionID  string
	Metadata        map[string]interface{}
}

// Boundary represents a hard constraint preventing cross-domain execution or data flow.
type Boundary struct {
	ID                   string
	SourceJurisdictionID string
	TargetJurisdictionID string
	Allowed              bool
	Reason               string
}

// BoundaryCrossing represents a single jurisdiction transition: [from, to].
type BoundaryCrossing [2]string

// JurisdictionalClaim represents a declaration of where execution is allowed or prohibited.
type JurisdictionalClaim struct {
	ID             string
	ArtifactID     string
	JurisdictionID string
	ClaimType      string // e.g., "execution", "data-access"
	Metadata       map[string]interface{}
}

// CryptographicBinding represents non-repudiable cryptographic binding between artifact and jurisdiction.
type CryptographicBinding struct {
	ID                 string
	ArtifactID         string
	JurisdictionID     string
	BindingType        string
	SignatureAlgorithm string
	PublicKey          ed25519.PublicKey
	Signature          []byte
	ArtifactHash       string
	Timestamp          int64
}

// Verify cryptographically verifies binding integrity.
func (cb *CryptographicBinding) Verify() bool {
	if cb.PublicKey == nil || len(cb.Signature) == 0 {
		return false
	}
	canonical := cb.CanonicalForm()
	return ed25519.Verify(cb.PublicKey, []byte(canonical), cb.Signature)
}

// CanonicalForm returns deterministic serialization for signing.
func (cb *CryptographicBinding) CanonicalForm() string {
	data := map[string]interface{}{
		"artifact_hash":   cb.ArtifactHash,
		"artifact_id":     cb.ArtifactID,
		"binding_type":    cb.BindingType,
		"jurisdiction_id": cb.JurisdictionID,
		"timestamp":       cb.Timestamp,
	}
	bytes, _ := json.Marshal(data)
	return string(bytes)
}

// Hash returns SHA256 hash of the binding for Merkle tree.
func (cb *CryptographicBinding) Hash() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(cb.CanonicalForm())))
}

// BoundaryProof represents a machine-verifiable explanation of why execution was permitted or denied.
type BoundaryProof struct {
	ID             string
	ArtifactID     string
	SourceDomainID string
	TargetDomainID string
	JurisdictionID string
	Allowed        bool
	Reason         string
	Timestamp      int64
	Evidence       []string
}

// Hash returns SHA256 hash of the proof for Merkle tree.
func (bp *BoundaryProof) Hash() string {
	data := fmt.Sprintf("%s:%s:%s:%s:%t:%d",
		bp.ID, bp.ArtifactID, bp.SourceDomainID, bp.TargetDomainID, bp.Allowed, bp.Timestamp)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
}

// JIBError is the base exception for JIB errors.
type JIBError struct {
	Message   string
	Ctx       map[string]interface{}
	Timestamp int64
}

func (e *JIBError) Error() string {
	return e.Message
}

// Context returns the error context.
func (e *JIBError) GetContext() map[string]interface{} {
	return e.Ctx
}

// JurisdictionalViolation is raised when a jurisdictional boundary is violated.
type JurisdictionalViolation struct {
	JIBError
}

// InvalidJurisdictionBinding is raised when a binding is invalid.
type InvalidJurisdictionBinding struct {
	JIBError
}

// AmbiguousJurisdiction is raised when jurisdiction resolution is ambiguous.
type AmbiguousJurisdiction struct {
	JIBError
}

// Int64Ptr is a helper to create pointer to int64.
func Int64Ptr(i int64) *int64 {
	return &i
}