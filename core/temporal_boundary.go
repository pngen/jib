package core

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// TemporalOperator represents linear temporal logic operators.
type TemporalOperator string

const (
	Always     TemporalOperator = "G"
	Eventually TemporalOperator = "F"
	Until      TemporalOperator = "U"
	Next       TemporalOperator = "X"
)

// TemporalBoundary represents a time-bounded jurisdictional constraint.
type TemporalBoundary struct {
	ID                   string
	SourceJurisdictionID string
	TargetJurisdictionID string
	Allowed              bool
	Reason               string
	ValidFrom            *int64
	ValidUntil           *int64
	TemporalOperator     TemporalOperator
	RenewalPolicy        *string
}

// IsValidAt checks if boundary is temporally valid.
func (tb *TemporalBoundary) IsValidAt(timestamp int64) bool {
	if tb == nil || !supportedTemporalBoundary(tb) {
		return false
	}
	if tb.ValidFrom != nil && timestamp < *tb.ValidFrom {
		return false
	}
	if tb.ValidUntil != nil && timestamp > *tb.ValidUntil {
		return false
	}
	return true
}

// IsExpired checks if boundary has expired.
func (tb *TemporalBoundary) IsExpired() bool {
	if tb == nil || tb.ValidUntil == nil {
		return false
	}
	return time.Now().Unix() > *tb.ValidUntil
}

// RemainingValidity returns seconds until expiration, or -1 if no expiration.
func (tb *TemporalBoundary) RemainingValidity() int64 {
	if tb == nil || tb.ValidUntil == nil {
		return -1
	}
	remaining := *tb.ValidUntil - time.Now().Unix()
	if remaining < 0 {
		return 0
	}
	return remaining
}

// State represents a system state for temporal logic evaluation.
type State struct {
	Timestamp int64
	Bounds    []*TemporalBoundary
}

// TemporalBoundaryManager manages temporal boundaries and their lifecycle.
type TemporalBoundaryManager struct {
	TemporalBoundaries map[string]*TemporalBoundary
	ExpiryCallbacks    map[string]func(*TemporalBoundary)
	mutex              sync.RWMutex
}

// NewTemporalBoundaryManager creates a new instance of TemporalBoundaryManager.
func NewTemporalBoundaryManager() *TemporalBoundaryManager {
	return &TemporalBoundaryManager{
		TemporalBoundaries: make(map[string]*TemporalBoundary),
		ExpiryCallbacks:    make(map[string]func(*TemporalBoundary)),
	}
}

// RegisterBoundary registers a temporal boundary.
func (tbm *TemporalBoundaryManager) RegisterBoundary(boundary *TemporalBoundary) {
	if !validTemporalBoundaryIdentity(boundary) {
		return
	}

	tbm.mutex.Lock()
	defer tbm.mutex.Unlock()
	if existing, exists := tbm.TemporalBoundaries[boundary.ID]; exists && existing != nil && existing.Allowed != boundary.Allowed {
		if !existing.Allowed {
			return
		}
	}
	tbm.TemporalBoundaries[boundary.ID] = cloneTemporalBoundary(boundary)
}

// RegisterExpiryCallback registers a callback for when a boundary expires.
func (tbm *TemporalBoundaryManager) RegisterExpiryCallback(boundaryID string, callback func(*TemporalBoundary)) {
	if strings.TrimSpace(boundaryID) == "" || callback == nil {
		return
	}

	tbm.mutex.Lock()
	defer tbm.mutex.Unlock()
	tbm.ExpiryCallbacks[boundaryID] = callback
}

// CheckValidity checks if a boundary is valid at the given time.
func (tbm *TemporalBoundaryManager) CheckValidity(boundaryID string, timestamp *int64) bool {
	tbm.mutex.RLock()
	defer tbm.mutex.RUnlock()

	var ts int64
	if timestamp != nil {
		ts = *timestamp
	} else {
		ts = time.Now().Unix()
	}

	boundary, exists := tbm.TemporalBoundaries[boundaryID]
	if !exists {
		return false
	}

	return supportedTemporalBoundary(boundary) && boundary.IsValidAt(ts)
}

// HandleExpiry handles expiry of a boundary.
func (tbm *TemporalBoundaryManager) HandleExpiry(boundaryID string) {
	tbm.mutex.Lock()
	boundary, exists := tbm.TemporalBoundaries[boundaryID]
	if !exists || boundary == nil || !boundary.IsExpired() {
		tbm.mutex.Unlock()
		return
	}

	callback, exists := tbm.ExpiryCallbacks[boundaryID]
	callbackBoundary := cloneTemporalBoundary(boundary)
	tbm.mutex.Unlock()

	if exists && callback != nil {
		callback(callbackBoundary)
	}

	if supportedTemporalBoundary(boundary) && boundary.RenewalPolicy != nil && *boundary.RenewalPolicy == "auto" {
		tbm.attemptRenewal(boundary)
	}
}

// attemptRenewal attempts to renew a boundary.
func (tbm *TemporalBoundaryManager) attemptRenewal(boundary *TemporalBoundary) {
	if boundary == nil {
		return
	}

	tbm.mutex.Lock()
	defer tbm.mutex.Unlock()
	stored, exists := tbm.TemporalBoundaries[boundary.ID]
	if !exists || stored != boundary || boundary.ValidUntil == nil || !supportedTemporalBoundary(boundary) {
		return
	}

	duration := int64(3600)
	if boundary.ValidFrom != nil && boundary.ValidUntil != nil {
		duration = *boundary.ValidUntil - *boundary.ValidFrom
	}
	if duration <= 0 {
		return
	}

	newValidFrom := time.Now().Unix()
	newValidUntil := newValidFrom + duration
	if newValidUntil < newValidFrom {
		return
	}
	boundary.ValidFrom = &newValidFrom
	boundary.ValidUntil = &newValidUntil
}

// GetExpiredBoundaries gets all boundaries that have expired.
func (tbm *TemporalBoundaryManager) GetExpiredBoundaries() []*TemporalBoundary {
	tbm.mutex.RLock()
	defer tbm.mutex.RUnlock()

	currentTime := time.Now().Unix()
	expired := make([]*TemporalBoundary, 0)

	for _, boundary := range tbm.TemporalBoundaries {
		if boundary != nil && supportedTemporalBoundary(boundary) && boundary.ValidUntil != nil && currentTime > *boundary.ValidUntil {
			expired = append(expired, cloneTemporalBoundary(boundary))
		}
	}
	sort.Slice(expired, func(i, j int) bool { return expired[i].ID < expired[j].ID })

	return expired
}

// GetValidBoundaries gets all currently valid boundaries.
func (tbm *TemporalBoundaryManager) GetValidBoundaries() []*TemporalBoundary {
	tbm.mutex.RLock()
	defer tbm.mutex.RUnlock()

	currentTime := time.Now().Unix()
	valid := make([]*TemporalBoundary, 0)

	for _, boundary := range tbm.TemporalBoundaries {
		if boundary != nil && supportedTemporalBoundary(boundary) && boundary.IsValidAt(currentTime) {
			valid = append(valid, cloneTemporalBoundary(boundary))
		}
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].ID < valid[j].ID })

	return valid
}

// RemoveBoundary removes a temporal boundary.
func (tbm *TemporalBoundaryManager) RemoveBoundary(boundaryID string) {
	tbm.mutex.Lock()
	defer tbm.mutex.Unlock()
	delete(tbm.TemporalBoundaries, boundaryID)
	delete(tbm.ExpiryCallbacks, boundaryID)
}

// GracePeriodManager manages grace periods and transition semantics.
type GracePeriodManager struct {
	DefaultGracePeriod int64
}

// NewGracePeriodManager creates a new instance of GracePeriodManager.
func NewGracePeriodManager(defaultGracePeriod int64) *GracePeriodManager {
	if defaultGracePeriod <= 0 {
		defaultGracePeriod = 3600
	}
	return &GracePeriodManager{
		DefaultGracePeriod: defaultGracePeriod,
	}
}

// IsInGracePeriod checks if we're in a grace period for this boundary.
func (gpm *GracePeriodManager) IsInGracePeriod(boundary *TemporalBoundary, timestamp *int64) bool {
	if boundary == nil || !supportedTemporalBoundary(boundary) {
		return false
	}
	var ts int64
	if timestamp != nil {
		ts = *timestamp
	} else {
		ts = time.Now().Unix()
	}

	if boundary.ValidUntil == nil {
		return false
	}

	graceStart := *boundary.ValidUntil - gpm.DefaultGracePeriod
	return graceStart <= ts && ts <= *boundary.ValidUntil
}

// GetRemainingTime gets remaining time until boundary expires.
func (gpm *GracePeriodManager) GetRemainingTime(boundary *TemporalBoundary, timestamp *int64) int64 {
	if boundary == nil || !supportedTemporalBoundary(boundary) {
		return -1
	}
	var ts int64
	if timestamp != nil {
		ts = *timestamp
	} else {
		ts = time.Now().Unix()
	}

	if boundary.ValidUntil == nil {
		return -1
	}

	remaining := *boundary.ValidUntil - ts
	if remaining < 0 {
		return 0
	}
	return remaining
}

// GetGraceTimeRemaining returns time remaining in grace period, or -1 if not in grace.
func (gpm *GracePeriodManager) GetGraceTimeRemaining(boundary *TemporalBoundary, timestamp *int64) int64 {
	if !gpm.IsInGracePeriod(boundary, timestamp) {
		return -1
	}
	return gpm.GetRemainingTime(boundary, timestamp)
}

func validTemporalBoundaryIdentity(boundary *TemporalBoundary) bool {
	return boundary != nil && strings.TrimSpace(boundary.ID) != "" &&
		strings.TrimSpace(boundary.SourceJurisdictionID) != "" &&
		strings.TrimSpace(boundary.TargetJurisdictionID) != "" &&
		strings.TrimSpace(boundary.Reason) != ""
}

func supportedTemporalBoundary(boundary *TemporalBoundary) bool {
	if !validTemporalBoundaryIdentity(boundary) {
		return false
	}
	if boundary.ValidFrom != nil && boundary.ValidUntil != nil && *boundary.ValidFrom > *boundary.ValidUntil {
		return false
	}
	// Only a direct validity window (the zero value) and the pointwise Always
	// operator have defined runtime semantics. Other LTL operators need trace
	// state and must fail closed until such an evaluator exists.
	return boundary.TemporalOperator == "" || boundary.TemporalOperator == Always
}

func cloneTemporalBoundary(boundary *TemporalBoundary) *TemporalBoundary {
	if boundary == nil {
		return nil
	}
	clone := *boundary
	if boundary.ValidFrom != nil {
		validFrom := *boundary.ValidFrom
		clone.ValidFrom = &validFrom
	}
	if boundary.ValidUntil != nil {
		validUntil := *boundary.ValidUntil
		clone.ValidUntil = &validUntil
	}
	if boundary.RenewalPolicy != nil {
		renewalPolicy := *boundary.RenewalPolicy
		clone.RenewalPolicy = &renewalPolicy
	}
	return &clone
}
