package core

import (
	"sync"
	"time"
)

// TemporalOperator represents linear temporal logic operators.
type TemporalOperator string

const (
	Always   TemporalOperator = "G"
	Eventually TemporalOperator = "F"
	Until    TemporalOperator = "U"
	Next     TemporalOperator = "X"
)

// TemporalBoundary represents a time-bounded jurisdictional constraint.
type TemporalBoundary struct {
	ID                   string
	SourceJurisdictionID string
	TargetJurisdictionID string
	Allowed              bool
	Reason               string
	ValidFrom        	*int64
	ValidUntil       	*int64
	TemporalOperator 	TemporalOperator
	RenewalPolicy    	*string
}

// IsValidAt checks if boundary is temporally valid.
func (tb *TemporalBoundary) IsValidAt(timestamp int64) bool {
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
	if tb.ValidUntil == nil {
		return false
	}
	return time.Now().Unix() > *tb.ValidUntil
}

// RemainingValidity returns seconds until expiration, or -1 if no expiration.
func (tb *TemporalBoundary) RemainingValidity() int64 {
	if tb.ValidUntil == nil {
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
	tbm.mutex.Lock()
	defer tbm.mutex.Unlock()
	tbm.TemporalBoundaries[boundary.ID] = boundary
}

// RegisterExpiryCallback registers a callback for when a boundary expires.
func (tbm *TemporalBoundaryManager) RegisterExpiryCallback(boundaryID string, callback func(*TemporalBoundary)) {
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

	return boundary.IsValidAt(ts)
}

// HandleExpiry handles expiry of a boundary.
func (tbm *TemporalBoundaryManager) HandleExpiry(boundaryID string) {
	tbm.mutex.Lock()
	boundary, exists := tbm.TemporalBoundaries[boundaryID]
	if !exists {
		tbm.mutex.Unlock()
		return
	}

	callback, exists := tbm.ExpiryCallbacks[boundaryID]
	tbm.mutex.Unlock()
	
	if exists && callback != nil {
		callback(boundary)
	}

	if boundary.RenewalPolicy != nil && *boundary.RenewalPolicy == "auto" {
		tbm.attemptRenewal(boundary)
	}
}

// attemptRenewal attempts to renew a boundary.
func (tbm *TemporalBoundaryManager) attemptRenewal(boundary *TemporalBoundary) {
	if boundary.ValidUntil == nil {
		return
	}
	
	tbm.mutex.Lock()
	defer tbm.mutex.Unlock()
	
	duration := int64(3600)
	if boundary.ValidFrom != nil && boundary.ValidUntil != nil {
		duration = *boundary.ValidUntil - *boundary.ValidFrom
	}
	
	newValidFrom := time.Now().Unix()
	newValidUntil := newValidFrom + duration
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
		if boundary.ValidUntil != nil && currentTime > *boundary.ValidUntil {
			expired = append(expired, boundary)
		}
	}

	return expired
}

// GetValidBoundaries gets all currently valid boundaries.
func (tbm *TemporalBoundaryManager) GetValidBoundaries() []*TemporalBoundary {
	tbm.mutex.RLock()
	defer tbm.mutex.RUnlock()

	currentTime := time.Now().Unix()
	valid := make([]*TemporalBoundary, 0)

	for _, boundary := range tbm.TemporalBoundaries {
		if boundary.IsValidAt(currentTime) {
			valid = append(valid, boundary)
		}
	}

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