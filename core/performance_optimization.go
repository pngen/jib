package core

import (
	"container/list"
	"crypto/sha256"
	"fmt"
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
		return elem.Value.(*cacheEntry).value
	}
	return nil
}

// Put puts item in cache.
func (lru *LRUCache) Put(key string, value interface{}) {
	lru.mutex.Lock()
	defer lru.mutex.Unlock()

	if elem, exists := lru.cache[key]; exists {
		lru.ll.MoveToFront(elem)
		elem.Value.(*cacheEntry).value = value
		return
	}

	if lru.ll.Len() >= lru.MaxSize {
		oldest := lru.ll.Back()
		if oldest != nil {
			delete(lru.cache, oldest.Value.(*cacheEntry).key)
			lru.ll.Remove(oldest)
		}
	}

	entry := &cacheEntry{key: key, value: value}
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
	Jurisdictions     map[string]interface{}
	ExecutionDomains  map[string]interface{}
	BoundArtifacts    map[string][]interface{}
	Boundaries       map[string]interface{}
	BoundaryIndex    map[[2]string]interface{}
	ProofCache        *LRUCache
	BindingCache      *LRUCache
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
	obe.mutex.Lock()
	defer obe.mutex.Unlock()
	obe.Jurisdictions[jurisdiction.(map[string]interface{})["id"].(string)] = jurisdiction
}

// RegisterExecutionDomain registers an execution domain.
func (obe *OptimizedBoundaryEnforcer) RegisterExecutionDomain(domain interface{}) {
	obe.mutex.Lock()
	defer obe.mutex.Unlock()
	obe.ExecutionDomains[domain.(map[string]interface{})["id"].(string)] = domain
}

// BindArtifactToJurisdiction binds an artifact to a jurisdiction.
func (obe *OptimizedBoundaryEnforcer) BindArtifactToJurisdiction(
	artifactID string,
	jurisdictionID string,
) interface{} {
	cacheKey := fmt.Sprintf("binding:%s:%s", artifactID, jurisdictionID)
	if cached := obe.BindingCache.Get(cacheKey); cached != nil {
		return cached
	}

	obe.mutex.Lock()
	defer obe.mutex.Unlock()

	binding := map[string]interface{}{
		"id":              fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", artifactID, jurisdictionID, time.Now().UnixNano())))),
		"artifact_id":     artifactID,
		"jurisdiction_id": jurisdictionID,
		"binding_type":    "static",
		"timestamp":       time.Now().Unix(),
	}

	obe.BindingCache.Put(cacheKey, binding)

	if _, exists := obe.BoundArtifacts[artifactID]; !exists {
		obe.BoundArtifacts[artifactID] = make([]interface{}, 0)
	}
	obe.BoundArtifacts[artifactID] = append(obe.BoundArtifacts[artifactID], binding)

	return binding
}

// RegisterBoundary registers a boundary with O(1) index.
func (obe *OptimizedBoundaryEnforcer) RegisterBoundary(boundary interface{}) {
	obe.mutex.Lock()
	defer obe.mutex.Unlock()

	source := boundary.(map[string]interface{})["source_jurisdiction_id"].(string)
	target := boundary.(map[string]interface{})["target_jurisdiction_id"].(string)
	key := [2]string{source, target}
	obe.BoundaryIndex[key] = boundary
	obe.Boundaries[boundary.(map[string]interface{})["id"].(string)] = boundary
}

// CheckBoundary checks boundary with caching.
func (obe *OptimizedBoundaryEnforcer) CheckBoundary(
	artifactID string,
	sourceDomainID string,
	targetDomainID string,
) map[string]interface{} {
	cacheKey := fmt.Sprintf("boundary:%s:%s:%s", artifactID, sourceDomainID, targetDomainID)

	if cachedProof := obe.ProofCache.Get(cacheKey); cachedProof != nil {
		return cachedProof.(map[string]interface{})
	}

	obe.mutex.RLock()
	key := [2]string{sourceDomainID, targetDomainID}
	boundary, exists := obe.BoundaryIndex[key]
	obe.mutex.RUnlock()

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

	if exists {
		boundaryMap := boundary.(map[string]interface{})
		proof["allowed"] = boundaryMap["allowed"]
		proof["reason"] = boundaryMap["reason"]
		if jid, ok := boundaryMap["source_jurisdiction_id"]; ok {
			proof["jurisdiction_id"] = jid
		}
	}

	obe.ProofCache.Put(cacheKey, proof)

	return proof
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