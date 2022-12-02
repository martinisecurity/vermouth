package stivs

import (
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"time"
)

var ourCrlCache = &crlCache{}

type crlCache struct {
	sync.RWMutex
	crlMap map[string]*CrlCacheEntry
}

func GetCrlCache() *crlCache {
	return ourCrlCache
}

func InitCrlCache() {
	ourCrlCache.crlMap = make(map[string]*CrlCacheEntry)
}

func (cache *crlCache) AddUpdateEntry(crlUrl string, entry *CrlCacheEntry) {
	cache.Lock()
	defer cache.Unlock()
	cache.crlMap[crlUrl] = entry
}

func (cache *crlCache) GetEntry(crlUrl string) (*CrlCacheEntry, bool) {
	cache.RLock()
	defer cache.RUnlock()
	cacheEntry, ok := ourCrlCache.crlMap[crlUrl]
	if !ok {
		return nil, false
	}
	return cacheEntry, true
}

func (cache *crlCache) CopyEntry(crlUrl string) *CrlCacheEntry {
	cache.RLock()
	defer cache.RUnlock()

	orig, ok := cache.crlMap[crlUrl]
	if !ok {
		return nil
	}

	deepNumber := new(big.Int)
	if orig.Number != nil {
		deepNumber.Set(orig.Number)
	}

	ourCopy := CrlCacheEntry{
		URI:             orig.URI,
		PreviouslyValid: orig.PreviouslyValid,
		Status:          orig.Status,
		ErrorCount:      orig.ErrorCount,
		LastAttempt:     orig.LastAttempt,
		Number:          deepNumber,
		NextUpdate:      time.Time{},
		// No need to copy these since the entire point is to update this
		Revocations: nil,
	}

	return &ourCopy

}

type CrlCacheEntryStatus int64

const (
	Initializing CrlCacheEntryStatus = iota
	Valid
	Problematic
	InvalidDestPoint // Will still refresh if more than 24 hours and new call comes in
)

type CrlCacheEntry struct {
	URI             string
	PreviouslyValid bool
	Status          CrlCacheEntryStatus
	ErrorCount      int
	LastAttempt     time.Time
	Number          *big.Int
	NextUpdate      time.Time
	Revocations     []*RevokedCertLight
}

func (entry *CrlCacheEntry) IncrementError() string {
	nextAttempt := ""
	if entry.ErrorCount > 12 {
		entry.Status = InvalidDestPoint
	} else {
		entry.ErrorCount++
		entry.Status = Problematic
		nextAttempt = entry.URI + ";10m"
	}
	return nextAttempt
}

type RevokedCertLight struct {
	SerialNumber *big.Int
	Issuer       pkix.Name
}
