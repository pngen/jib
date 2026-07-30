package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// JurisdictionType represents type of jurisdiction.
type JurisdictionType string

const (
	SOVEREIGN  JurisdictionType = "sovereign"
	LEGAL      JurisdictionType = "legal"
	REGULATORY JurisdictionType = "regulatory"
)

// BindingType constants
const DefaultBindingType = "static"

// Jurisdiction represents a legally or sovereignly defined execution domain.
type Jurisdiction struct {
	ID         string
	Name       string
	Type       JurisdictionType
	ParentID   *string
	Attributes map[string]interface{}
}

// ExecutionDomain represents a concrete environment where intelligence runs.
type ExecutionDomain struct {
	ID             string
	Name           string
	JurisdictionID string
	Metadata       map[string]interface{}
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

type canonicalBinding struct {
	ID                   string `json:"id"`
	ArtifactID           string `json:"artifact_id"`
	JurisdictionID       string `json:"jurisdiction_id"`
	BindingType          string `json:"binding_type"`
	SignatureAlgorithm   string `json:"signature_algorithm"`
	PublicKey            string `json:"public_key"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	ArtifactHash         string `json:"artifact_hash"`
	Timestamp            int64  `json:"timestamp"`
}

func (cb *CryptographicBinding) validateUnsigned() error {
	if cb == nil {
		return fmt.Errorf("binding is nil")
	}
	if strings.TrimSpace(cb.ID) == "" {
		return fmt.Errorf("binding ID is required")
	}
	if strings.TrimSpace(cb.ArtifactID) == "" {
		return fmt.Errorf("artifact ID is required")
	}
	if strings.TrimSpace(cb.JurisdictionID) == "" {
		return fmt.Errorf("jurisdiction ID is required")
	}
	if strings.TrimSpace(cb.BindingType) == "" {
		return fmt.Errorf("binding type is required")
	}
	if cb.SignatureAlgorithm != "Ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q", cb.SignatureAlgorithm)
	}
	if len(cb.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key length: %d", len(cb.PublicKey))
	}
	if strings.TrimSpace(cb.ArtifactHash) == "" {
		return fmt.Errorf("artifact hash is required")
	}
	if cb.Timestamp <= 0 {
		return fmt.Errorf("binding timestamp must be positive")
	}
	return nil
}

func (cb *CryptographicBinding) canonicalPayload() canonicalBinding {
	publicKeyHash := sha256.Sum256(cb.PublicKey)
	return canonicalBinding{
		ID:                   cb.ID,
		ArtifactID:           cb.ArtifactID,
		JurisdictionID:       cb.JurisdictionID,
		BindingType:          cb.BindingType,
		SignatureAlgorithm:   cb.SignatureAlgorithm,
		PublicKey:            hex.EncodeToString(cb.PublicKey),
		PublicKeyFingerprint: hex.EncodeToString(publicKeyHash[:]),
		ArtifactHash:         cb.ArtifactHash,
		Timestamp:            cb.Timestamp,
	}
}

// Verify cryptographically verifies binding integrity.
func (cb *CryptographicBinding) Verify() bool {
	if cb.validateUnsigned() != nil || len(cb.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(cb.PublicKey, []byte(cb.CanonicalForm()), cb.Signature)
}

// CanonicalForm returns deterministic serialization for signing.
func (cb *CryptographicBinding) CanonicalForm() string {
	if cb == nil {
		return ""
	}
	bytes, _ := json.Marshal(cb.canonicalPayload())
	return string(bytes)
}

// Hash returns SHA256 hash of the binding for Merkle tree.
func (cb *CryptographicBinding) Hash() string {
	if cb == nil {
		return ""
	}
	envelope := struct {
		Payload   canonicalBinding `json:"payload"`
		Signature string           `json:"signature"`
	}{
		Payload:   cb.canonicalPayload(),
		Signature: hex.EncodeToString(cb.Signature),
	}
	bytes, _ := json.Marshal(envelope)
	return fmt.Sprintf("%x", sha256.Sum256(bytes))
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
	if bp == nil {
		return ""
	}
	evidence := append([]string{}, bp.Evidence...)
	sort.Strings(evidence)
	data := struct {
		ArtifactID     string   `json:"artifact_id"`
		SourceDomainID string   `json:"source_domain_id"`
		TargetDomainID string   `json:"target_domain_id"`
		JurisdictionID string   `json:"jurisdiction_id"`
		Allowed        bool     `json:"allowed"`
		Reason         string   `json:"reason"`
		Timestamp      int64    `json:"timestamp"`
		Evidence       []string `json:"evidence"`
	}{
		ArtifactID:     bp.ArtifactID,
		SourceDomainID: bp.SourceDomainID,
		TargetDomainID: bp.TargetDomainID,
		JurisdictionID: bp.JurisdictionID,
		Allowed:        bp.Allowed,
		Reason:         bp.Reason,
		Timestamp:      bp.Timestamp,
		Evidence:       evidence,
	}
	bytes, _ := json.Marshal(data)
	return fmt.Sprintf("%x", sha256.Sum256(bytes))
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
