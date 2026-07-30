package core

import (
	"container/list"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// LRUCache implements LRU Cache for performance optimization.
type LRUCache struct {
	MaxSize int
	cache   map[string]*list.Element
	ll      *list.List
	mutex   sync.RWMutex
}

type cacheEntry struct {
	key   string
	value interface{}
}

// cloneOptimizedMap copies the map and the slice values used by optimized
// bindings and proofs. The optimized API intentionally accepts interface maps,
// so copies at storage and return boundaries prevent callers from mutating
// cached enforcement state through an alias.
func cloneOptimizedMap(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}

	cloned := make(map[string]interface{}, len(input))
	for key, value := range input {
		switch typed := value.(type) {
		case []string:
			cloned[key] = append([]string(nil), typed...)
		case []byte:
			cloned[key] = append([]byte(nil), typed...)
		case []interface{}:
			cloned[key] = append([]interface{}(nil), typed...)
		case map[string]string:
			mapCopy := make(map[string]string, len(typed))
			for nestedKey, nestedValue := range typed {
				mapCopy[nestedKey] = nestedValue
			}
			cloned[key] = mapCopy
		default:
			cloned[key] = value
		}
	}
	return cloned
}

func cloneOptimizedValue(value interface{}) interface{} {
	if mapped, ok := value.(map[string]interface{}); ok {
		return cloneOptimizedMap(mapped)
	}
	return value
}

func requiredOptimizedString(values map[string]interface{}, key string) (string, bool) {
	raw, ok := values[key].(string)
	if !ok {
		return "", false
	}
	value := strings.TrimSpace(raw)
	return value, value != ""
}

// NewLRUCache creates a new instance of LRUCache.
func NewLRUCache(maxsize int) *LRUCache {
	if maxsize <= 0 {
		maxsize = 1000
	}
	return &LRUCache{
		MaxSize: maxsize,
		cache:   make(map[string]*list.Element),
		ll:      list.New(),
	}
}

// Get gets item from cache.
func (lru *LRUCache) Get(key string) interface{} {
	lru.mutex.Lock()
	defer lru.mutex.Unlock()

	if elem, exists := lru.cache[key]; exists {
		lru.ll.MoveToFront(elem)
		return cloneOptimizedValue(elem.Value.(*cacheEntry).value)
	}
	return nil
}

// Put puts item in cache.
func (lru *LRUCache) Put(key string, value interface{}) {
	lru.mutex.Lock()
	defer lru.mutex.Unlock()

	if elem, exists := lru.cache[key]; exists {
		lru.ll.MoveToFront(elem)
		elem.Value.(*cacheEntry).value = cloneOptimizedValue(value)
		return
	}

	if lru.ll.Len() >= lru.MaxSize {
		oldest := lru.ll.Back()
		if oldest != nil {
			delete(lru.cache, oldest.Value.(*cacheEntry).key)
			lru.ll.Remove(oldest)
		}
	}

	entry := &cacheEntry{key: key, value: cloneOptimizedValue(value)}
	elem := lru.ll.PushFront(entry)
	lru.cache[key] = elem
}

// Size gets current cache size.
func (lru *LRUCache) Size() int {
	lru.mutex.RLock()
	defer lru.mutex.RUnlock()
	return lru.ll.Len()
}

// Clear clears the cache.
func (lru *LRUCache) Clear() {
	lru.mutex.Lock()
	defer lru.mutex.Unlock()
	lru.cache = make(map[string]*list.Element)
	lru.ll.Init()
}

// OptimizedBoundaryEnforcer provides performance-optimized enforcer with caching and indexing.
type OptimizedBoundaryEnforcer struct {
	Jurisdictions    map[string]interface{}
	ExecutionDomains map[string]interface{}
	BoundArtifacts   map[string][]interface{}
	Boundaries       map[string]interface{}
	BoundaryIndex    map[[2]string]interface{}
	ProofCache       *LRUCache
	BindingCache     *LRUCache
	mutex            sync.RWMutex
}

// NewOptimizedBoundaryEnforcer creates a new instance of OptimizedBoundaryEnforcer.
func NewOptimizedBoundaryEnforcer() *OptimizedBoundaryEnforcer {
	return &OptimizedBoundaryEnforcer{
		Jurisdictions:    make(map[string]interface{}),
		ExecutionDomains: make(map[string]interface{}),
		BoundArtifacts:   make(map[string][]interface{}),
		Boundaries:       make(map[string]interface{}),
		BoundaryIndex:    make(map[[2]string]interface{}),
		ProofCache:       NewLRUCache(10000),
		BindingCache:     NewLRUCache(5000),
	}
}

// RegisterJurisdiction registers a jurisdiction.
func (obe *OptimizedBoundaryEnforcer) RegisterJurisdiction(jurisdiction interface{}) {
	jurisdictionMap, ok := jurisdiction.(map[string]interface{})
	if !ok || jurisdictionMap == nil {
		return
	}
	jurisdictionID, ok := requiredOptimizedString(jurisdictionMap, "id")
	if !ok {
		return
	}

	stored := cloneOptimizedMap(jurisdictionMap)
	stored["id"] = jurisdictionID

	obe.mutex.Lock()
	defer obe.mutex.Unlock()
	obe.Jurisdictions[jurisdictionID] = stored
	obe.ProofCache.Clear()
}

// RegisterExecutionDomain registers an execution domain.
func (obe *OptimizedBoundaryEnforcer) RegisterExecutionDomain(domain interface{}) {
	domainMap, ok := domain.(map[string]interface{})
	if !ok || domainMap == nil {
		return
	}
	domainID, ok := requiredOptimizedString(domainMap, "id")
	if !ok {
		return
	}
	jurisdictionID, ok := requiredOptimizedString(domainMap, "jurisdiction_id")
	if !ok {
		return
	}

	obe.mutex.Lock()
	defer obe.mutex.Unlock()
	if !obe.hasRegisteredJurisdictionLocked(jurisdictionID) {
		return
	}

	stored := cloneOptimizedMap(domainMap)
	stored["id"] = domainID
	stored["jurisdiction_id"] = jurisdictionID
	obe.ExecutionDomains[domainID] = stored
	obe.ProofCache.Clear()
}

// BindArtifactToJurisdiction binds an artifact to a jurisdiction.
func (obe *OptimizedBoundaryEnforcer) BindArtifactToJurisdiction(
	artifactID string,
	jurisdictionID string,
) interface{} {
	artifactID = strings.TrimSpace(artifactID)
	jurisdictionID = strings.TrimSpace(jurisdictionID)
	if artifactID == "" || jurisdictionID == "" {
		return nil
	}

	obe.mutex.Lock()
	defer obe.mutex.Unlock()
	if !obe.hasRegisteredJurisdictionLocked(jurisdictionID) {
		return nil
	}

	cacheKey := fmt.Sprintf("binding:%q:%q", artifactID, jurisdictionID)
	if cached := obe.BindingCache.Get(cacheKey); cached != nil {
		return cloneOptimizedValue(cached)
	}

	// A cache clear must not manufacture a duplicate binding. Recover an
	// existing valid state entry before creating a new identity.
	for _, rawBinding := range obe.BoundArtifacts[artifactID] {
		binding, ok := rawBinding.(map[string]interface{})
		if !ok || binding == nil {
			continue
		}
		boundArtifactID, artifactOK := requiredOptimizedString(binding, "artifact_id")
		boundJurisdictionID, jurisdictionOK := requiredOptimizedString(binding, "jurisdiction_id")
		bindingID, idOK := requiredOptimizedString(binding, "id")
		if artifactOK && jurisdictionOK && idOK && boundArtifactID == artifactID && boundJurisdictionID == jurisdictionID && bindingID != "" {
			stored := cloneOptimizedMap(binding)
			obe.BindingCache.Put(cacheKey, stored)
			return cloneOptimizedMap(stored)
		}
	}

	binding := map[string]interface{}{
		"id":              fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", artifactID, jurisdictionID, time.Now().UnixNano())))),
		"artifact_id":     artifactID,
		"jurisdiction_id": jurisdictionID,
		"binding_type":    "static",
		"timestamp":       time.Now().Unix(),
	}

	obe.BindingCache.Put(cacheKey, cloneOptimizedMap(binding))

	if _, exists := obe.BoundArtifacts[artifactID]; !exists {
		obe.BoundArtifacts[artifactID] = make([]interface{}, 0)
	}
	obe.BoundArtifacts[artifactID] = append(obe.BoundArtifacts[artifactID], cloneOptimizedMap(binding))
	obe.ProofCache.Clear()

	return cloneOptimizedMap(binding)
}

// RegisterBoundary registers a boundary with O(1) index.
func (obe *OptimizedBoundaryEnforcer) RegisterBoundary(boundary interface{}) {
	boundaryMap, ok := boundary.(map[string]interface{})
	if !ok || boundaryMap == nil {
		return
	}
	boundaryID, ok := requiredOptimizedString(boundaryMap, "id")
	if !ok {
		return
	}
	source, ok := requiredOptimizedString(boundaryMap, "source_jurisdiction_id")
	if !ok {
		return
	}
	target, ok := requiredOptimizedString(boundaryMap, "target_jurisdiction_id")
	if !ok {
		return
	}
	allowed, ok := boundaryMap["allowed"].(bool)
	if !ok {
		return
	}
	reason, ok := requiredOptimizedString(boundaryMap, "reason")
	if !ok {
		return
	}

	obe.mutex.Lock()
	defer obe.mutex.Unlock()
	if !obe.hasRegisteredJurisdictionLocked(source) || !obe.hasRegisteredJurisdictionLocked(target) {
		return
	}

	key := [2]string{source, target}

	// Keep the ID and route indexes one-to-one. Re-registering either an ID
	// or a route replaces the previous entry without leaving a stale alias.
	if existingRaw, exists := obe.Boundaries[boundaryID]; exists {
		if existing, valid := existingRaw.(map[string]interface{}); valid {
			oldSource, sourceOK := requiredOptimizedString(existing, "source_jurisdiction_id")
			oldTarget, targetOK := requiredOptimizedString(existing, "target_jurisdiction_id")
			if sourceOK && targetOK {
				oldKey := [2]string{oldSource, oldTarget}
				if indexedRaw, indexed := obe.BoundaryIndex[oldKey]; indexed {
					if indexedBoundary, valid := indexedRaw.(map[string]interface{}); valid {
						indexedID, idOK := requiredOptimizedString(indexedBoundary, "id")
						if idOK && indexedID == boundaryID {
							delete(obe.BoundaryIndex, oldKey)
						}
					}
				}
			}
		}
	}
	if existingRaw, exists := obe.BoundaryIndex[key]; exists {
		if existing, valid := existingRaw.(map[string]interface{}); valid {
			if existingID, idOK := requiredOptimizedString(existing, "id"); idOK && existingID != boundaryID {
				delete(obe.Boundaries, existingID)
			}
		}
	}

	stored := cloneOptimizedMap(boundaryMap)
	stored["id"] = boundaryID
	stored["source_jurisdiction_id"] = source
	stored["target_jurisdiction_id"] = target
	stored["allowed"] = allowed
	stored["reason"] = reason
	obe.BoundaryIndex[key] = cloneOptimizedMap(stored)
	obe.Boundaries[boundaryID] = cloneOptimizedMap(stored)
	obe.ProofCache.Clear()
}

// hasRegisteredJurisdictionLocked reports whether the indexed value is a
// well-formed jurisdiction whose declared ID matches its map key. The caller
// must hold obe.mutex.
func (obe *OptimizedBoundaryEnforcer) hasRegisteredJurisdictionLocked(jurisdictionID string) bool {
	raw, exists := obe.Jurisdictions[jurisdictionID]
	if !exists {
		return false
	}
	jurisdiction, ok := raw.(map[string]interface{})
	if !ok || jurisdiction == nil {
		return false
	}
	storedID, ok := requiredOptimizedString(jurisdiction, "id")
	return ok && storedID == jurisdictionID
}

// domainJurisdictionLocked resolves a registered domain to a registered
// jurisdiction. The caller must hold obe.mutex for reading or writing.
func (obe *OptimizedBoundaryEnforcer) domainJurisdictionLocked(domainID string) (string, bool) {
	raw, exists := obe.ExecutionDomains[domainID]
	if !exists {
		return "", false
	}
	domain, ok := raw.(map[string]interface{})
	if !ok || domain == nil {
		return "", false
	}
	storedID, idOK := requiredOptimizedString(domain, "id")
	jurisdictionID, jurisdictionOK := requiredOptimizedString(domain, "jurisdiction_id")
	if !idOK || !jurisdictionOK || storedID != domainID || !obe.hasRegisteredJurisdictionLocked(jurisdictionID) {
		return "", false
	}
	return jurisdictionID, true
}

// bindingEvidenceLocked returns stable evidence IDs for bindings that match
// both the requested artifact and its resolved source jurisdiction. The caller
// must hold obe.mutex for reading or writing.
func (obe *OptimizedBoundaryEnforcer) bindingEvidenceLocked(artifactID, jurisdictionID string) []string {
	seen := make(map[string]struct{})
	evidence := make([]string, 0)
	for _, raw := range obe.BoundArtifacts[artifactID] {
		binding, ok := raw.(map[string]interface{})
		if !ok || binding == nil {
			continue
		}
		storedArtifactID, artifactOK := requiredOptimizedString(binding, "artifact_id")
		storedJurisdictionID, jurisdictionOK := requiredOptimizedString(binding, "jurisdiction_id")
		bindingID, idOK := requiredOptimizedString(binding, "id")
		if !artifactOK || !jurisdictionOK || !idOK || storedArtifactID != artifactID || storedJurisdictionID != jurisdictionID {
			continue
		}
		if _, duplicate := seen[bindingID]; duplicate {
			continue
		}
		seen[bindingID] = struct{}{}
		evidence = append(evidence, bindingID)
	}
	sort.Strings(evidence)
	return evidence
}

// CheckBoundary checks boundary with caching.
func (obe *OptimizedBoundaryEnforcer) CheckBoundary(
	artifactID string,
	sourceDomainID string,
	targetDomainID string,
) map[string]interface{} {
	artifactID = strings.TrimSpace(artifactID)
	sourceDomainID = strings.TrimSpace(sourceDomainID)
	targetDomainID = strings.TrimSpace(targetDomainID)
	cacheKey := fmt.Sprintf("boundary:%q:%q:%q", artifactID, sourceDomainID, targetDomainID)

	obe.mutex.RLock()
	defer obe.mutex.RUnlock()

	if cachedProof := obe.ProofCache.Get(cacheKey); cachedProof != nil {
		if proof, ok := cachedProof.(map[string]interface{}); ok {
			return cloneOptimizedMap(proof)
		}
	}

	proof := map[string]interface{}{
		"id":               fmt.Sprintf("%x", sha256.Sum256([]byte(cacheKey))),
		"artifact_id":      artifactID,
		"source_domain_id": sourceDomainID,
		"target_domain_id": targetDomainID,
		"jurisdiction_id":  "unknown",
		"allowed":          false,
		"reason":           "no boundary defined",
		"timestamp":        time.Now().Unix(),
		"evidence":         []string{},
	}

	if artifactID == "" || sourceDomainID == "" || targetDomainID == "" {
		proof["reason"] = "invalid boundary check identifiers"
		obe.ProofCache.Put(cacheKey, proof)
		return cloneOptimizedMap(proof)
	}

	sourceJurisdictionID, sourceExists := obe.domainJurisdictionLocked(sourceDomainID)
	targetJurisdictionID, targetExists := obe.domainJurisdictionLocked(targetDomainID)
	if !sourceExists || !targetExists {
		proof["reason"] = "source or target domain not registered"
		obe.ProofCache.Put(cacheKey, proof)
		return cloneOptimizedMap(proof)
	}
	proof["jurisdiction_id"] = sourceJurisdictionID

	evidence := obe.bindingEvidenceLocked(artifactID, sourceJurisdictionID)
	if len(evidence) == 0 {
		proof["reason"] = "artifact not bound to source jurisdiction"
		obe.ProofCache.Put(cacheKey, proof)
		return cloneOptimizedMap(proof)
	}
	proof["evidence"] = evidence

	key := [2]string{sourceJurisdictionID, targetJurisdictionID}
	boundaryRaw, exists := obe.BoundaryIndex[key]
	if !exists {
		obe.ProofCache.Put(cacheKey, proof)
		return cloneOptimizedMap(proof)
	}
	boundaryMap, ok := boundaryRaw.(map[string]interface{})
	if !ok || boundaryMap == nil {
		proof["reason"] = "invalid boundary definition"
		obe.ProofCache.Put(cacheKey, proof)
		return cloneOptimizedMap(proof)
	}
	boundarySource, sourceOK := requiredOptimizedString(boundaryMap, "source_jurisdiction_id")
	boundaryTarget, targetOK := requiredOptimizedString(boundaryMap, "target_jurisdiction_id")
	allowed, allowedOK := boundaryMap["allowed"].(bool)
	reason, reasonOK := requiredOptimizedString(boundaryMap, "reason")
	if !sourceOK || !targetOK || !allowedOK || !reasonOK || boundarySource != sourceJurisdictionID || boundaryTarget != targetJurisdictionID {
		proof["reason"] = "invalid boundary definition"
		obe.ProofCache.Put(cacheKey, proof)
		return cloneOptimizedMap(proof)
	}
	proof["allowed"] = allowed
	proof["reason"] = reason

	obe.ProofCache.Put(cacheKey, proof)

	return cloneOptimizedMap(proof)
}

// BatchCheckBoundaries performs batch check multiple boundaries.
func (obe *OptimizedBoundaryEnforcer) BatchCheckBoundaries(checks [][3]string) []map[string]interface{} {
	results := make([]map[string]interface{}, len(checks))
	for i, check := range checks {
		results[i] = obe.CheckBoundary(check[0], check[1], check[2])
	}
	return results
}

// GetCacheStats gets cache statistics.
func (obe *OptimizedBoundaryEnforcer) GetCacheStats() map[string]int {
	return map[string]int{
		"proof_cache_size":   obe.ProofCache.Size(),
		"binding_cache_size": obe.BindingCache.Size(),
	}
}

// ClearCaches clears all caches.
func (obe *OptimizedBoundaryEnforcer) ClearCaches() {
	obe.mutex.Lock()
	defer obe.mutex.Unlock()
	obe.ProofCache.Clear()
	obe.BindingCache.Clear()
}

// PerformanceMonitor monitors performance of JIB operations.
type PerformanceMonitor struct {
	Metrics         map[string][]float64
	OperationCounts map[string]int
	mutex           sync.RWMutex
}

// NewPerformanceMonitor creates a new instance of PerformanceMonitor.
func NewPerformanceMonitor() *PerformanceMonitor {
	return &PerformanceMonitor{
		Metrics:         make(map[string][]float64),
		OperationCounts: make(map[string]int),
	}
}

// RecordOperation records an operation's duration.
func (pm *PerformanceMonitor) RecordOperation(operationName string, duration float64) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, exists := pm.Metrics[operationName]; !exists {
		pm.Metrics[operationName] = make([]float64, 0)
		pm.OperationCounts[operationName] = 0
	}

	pm.Metrics[operationName] = append(pm.Metrics[operationName], duration)
	pm.OperationCounts[operationName]++
}

// GetAverageDuration gets average duration for an operation.
func (pm *PerformanceMonitor) GetAverageDuration(operationName string) float64 {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	durations, exists := pm.Metrics[operationName]
	if !exists || len(durations) == 0 {
		return 0.0
	}

	sum := 0.0
	for _, d := range durations {
		sum += d
	}
	return sum / float64(len(durations))
}

// GetOperationCount gets count of operations performed.
func (pm *PerformanceMonitor) GetOperationCount(operationName string) int {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.OperationCounts[operationName]
}

// ResetMetrics resets all metrics.
func (pm *PerformanceMonitor) ResetMetrics() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.Metrics = make(map[string][]float64)
	pm.OperationCounts = make(map[string]int)
}

// GetAllMetrics returns all recorded metrics.
func (pm *PerformanceMonitor) GetAllMetrics() map[string]map[string]interface{} {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	result := make(map[string]map[string]interface{})
	for name, durations := range pm.Metrics {
		sum := 0.0
		for _, d := range durations {
			sum += d
		}
		result[name] = map[string]interface{}{
			"count":   pm.OperationCounts[name],
			"average": sum / float64(len(durations)),
			"total":   sum,
		}
	}
	return result
}
