package stivs

import (
	"crypto/x509"
	"sync"
	"time"
)

var ourCertCache = &certCache{}

type certCache struct {
	sync.RWMutex
	certMap map[string]CertCacheEntry
}

type CertCacheEntry struct {
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
	Expires       *time.Time
	Forced        bool
	CertBytes     *[]byte
}

func GetCertCache() *certCache {
	return ourCertCache
}

func InitCertCache() {
	ourCertCache.certMap = make(map[string]CertCacheEntry)
}

func (cache *certCache) GetKeysAsArray() []string {
	cache.RLock()
	defer cache.RUnlock()
	keys := make([]string, 0, len(cache.certMap))
	for key := range cache.certMap {
		keys = append(keys, key)
	}
	return keys
}

func (cache *certCache) AddEntry(certUrl string, entry CertCacheEntry) {
	cache.Lock()
	defer cache.Unlock()
	cache.certMap[certUrl] = entry
}

func (cache *certCache) RemoveEntry(certUrl string) {
	cache.Lock()
	defer cache.Unlock()
	delete(cache.certMap, certUrl)
}

func (cache *certCache) GetEntry(certUrl string) (*CertCacheEntry, bool) {
	cache.RLock()
	entry, found := cache.certMap[certUrl]
	if found {
		if entry.Expires.Before(time.Now()) {
			// If entry is expired, we need to release the read-lock so that RemoveEntry can acquire the write-lock
			cache.RUnlock()
			cache.RemoveEntry(certUrl)
			return nil, false
		}
	}
	cache.RUnlock()
	return &entry, found
}

func (cache *certCache) CleanExpired() {
	cache.Lock()
	defer cache.Unlock()
	for certUrl, entry := range cache.certMap {
		if entry.Expires.Before(time.Now()) {
			delete(cache.certMap, certUrl)
		}
	}
}
