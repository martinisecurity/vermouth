package vermouth

import (
	"bytes"
	"encoding/json"
	"github.com/ipifony/vermouth/logger"
	"github.com/ipifony/vermouth/stivs"
	"net/http"
	"sync"
	"time"
)

type SigningStatus uint

const (
	SigningSuccess SigningStatus = iota
	SigningFailureInvalid
	SigningFailureNotReady
)

type VerificationStatus uint

const (
	VerificationValidA VerificationStatus = iota
	VerificationValidB
	VerificationValidC
	VerificationNoSignature
	VerificationInvalidSignature
	VerificationNotTrusted
	VerificationTnMismatch
	VerificationBadFormat
	VerificationStale
)

const ( // 15, 60 * 12
	MinutesPerBucket = 15
	// ReportingIntervalMinutes determines how often aggregate data is set to be collected. Must be divisible by MinutesPerBucket
	ReportingIntervalMinutes = 60 * 12
	TotalIntervals           = ReportingIntervalMinutes / MinutesPerBucket
	SigningUrl               = "https://m.vermouth.link/signing"
	VerificationUrl          = "https://m.vermouth.link/verification"
	CertRepoReportingUrl     = "https://m.vermouth.link/certs"
)

var (
	SigningData      = &signingCollection{}
	VerificationData = &verificationCollection{}
)

func readyDataCollection() {
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Data Collection: Initializing..."}

	if GlobalConfig.isDbEnabled() {
		err := InitPool()
		if err != nil {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "DB Access Failed..."}
			GlobalConfig.setDbEnabled(false)
		}
	}

	SigningData.signingBuckets = make([]SigningBucket, TotalIntervals)
	SigningData.ready = false
	VerificationData.verificationBuckets = make([]VerificationBucket, TotalIntervals)
	VerificationData.ready = false
	periodStarting := roundUpTime(time.Now(), MinutesPerBucket*time.Minute)
	periodEnding := periodStarting.Add(MinutesPerBucket * time.Minute)
	SigningData.signingBuckets[0].PeriodEnding = periodEnding
	SigningData.signingBuckets[0].PeriodEndingUnix = periodEnding.Unix()
	VerificationData.verificationBuckets[0].PeriodEnding = periodEnding
	VerificationData.verificationBuckets[0].PeriodEndingUnix = periodEnding.Unix()

	// To create our even intervals, we need to delay and align as close as possible to the wall clock
	go func() {
		readyAt := periodStarting.Sub(time.Now())
		readyTimer := time.NewTimer(readyAt)
		<-readyTimer.C
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Stats: - Readying stat engine"}
		SigningData.setReady(true)
		VerificationData.setReady(true)
		bucketTicker := time.NewTicker(MinutesPerBucket * time.Minute)
		for {
			select {
			case <-bucketTicker.C:
				SigningData.rotateBucket()
				VerificationData.rotateBucket()
			}
		}
	}()
}

type signingCollection struct {
	sync.Mutex
	signingBuckets []SigningBucket
	bucketIndex    int
	ready          bool
}

type SigningBucket struct {
	PeriodEnding     time.Time `json:"json:-"`
	PeriodEndingUnix int64     `json:"periodEnding"`
	Requests         int       `json:"requests"`
	SuccessCount     int       `json:"successCount"`
	InvalidCount     int       `json:"invalidCount"`
	NotReadyCount    int       `json:"notReadyCount"`
}

// SigningDataExport is used for transmitting the signing data across the wire
type SigningDataExport struct {
	Ocn        string           `json:"ocn"`
	InstanceId string           `json:"instanceId"`
	Buckets    *[]SigningBucket `json:"buckets"`
}

type verificationCollection struct {
	sync.Mutex
	verificationBuckets []VerificationBucket
	bucketIndex         int
	ready               bool
}

type VerificationBucket struct {
	PeriodEnding     time.Time `json:"-"`
	PeriodEndingUnix int64     `json:"periodEnding"`
	Requests         int       `json:"requests"`
	ValidA           int       `json:"validA"`
	ValidB           int       `json:"validB"`
	ValidC           int       `json:"validC"`
	Valid            int       `json:"valid"`
	NoSignature      int       `json:"noSignature"`
	InvalidSignature int       `json:"invalidSignature"` // key does match cert
	NotTrusted       int       `json:"notTrusted"`       // CRL or doesn't chain to valid root
	TnMismatch       int       `json:"tnMismatch"`       // source or dest doesn't match signature
	BadFormat        int       `json:"badFormat"`
	Stale            int       `json:"stale"`
}

// VerificationDataExport is used for transmitting the signing data across the wire
type VerificationDataExport struct {
	ValidatorOcn string                `json:"validatorOcn"`
	InstanceId   string                `json:"instanceId"`
	Buckets      *[]VerificationBucket `json:"buckets"`
}

type CertUrls struct {
	Urls []string `json:"urls"`
}

func (c *verificationCollection) setReady(ready bool) {
	c.Lock()
	defer c.Unlock()
	c.ready = ready
}

func (c *verificationCollection) rotateBucket() {
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Stats: Rotating verification bucket"}
	c.Lock()
	defer c.Unlock()
	nextPeriodEnding := c.verificationBuckets[c.bucketIndex].PeriodEnding.Add(time.Minute * MinutesPerBucket)
	c.bucketIndex = (c.bucketIndex + 1) % TotalIntervals
	if c.bucketIndex == 0 {
		// We need to post the data and then reset the data collection
		dataCopy := make([]VerificationBucket, TotalIntervals)
		copy(dataCopy, VerificationData.verificationBuckets)
		dataExport := VerificationDataExport{
			ValidatorOcn: GlobalConfig.GetStiAsCarrierOcn(),
			InstanceId:   GlobalConfig.GetServerInstanceId(),
			Buckets:      &dataCopy,
		}
		if !GlobalConfig.IsTelemetryDisabled() {
			logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Stats: Posting verification data"}
			go func() {
				jsonBytes, err := json.Marshal(&dataExport)
				if err != nil {
					return
				}
				req, err := http.NewRequest(http.MethodPost, VerificationUrl, bytes.NewBuffer(jsonBytes))
				if err != nil {
					return
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Set("User-Agent", UserAgent)
				resp, err := httpClient.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()
			}()
			logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Stats: Posting cert repo data"}
			go func() {
				urls := stivs.GetCertCache().GetKeysAsArray()
				if len(urls) > 0 {
					certUrls := CertUrls{Urls: urls}
					jsonBytes, err := json.Marshal(certUrls)
					if err != nil {
						return
					}
					req, err := http.NewRequest(http.MethodPost, CertRepoReportingUrl, bytes.NewBuffer(jsonBytes))
					req.Header.Add("Content-Type", "application/json")
					req.Header.Set("User-Agent", UserAgent)
					resp, err := httpClient.Do(req)
					if err != nil {
						return
					}
					defer resp.Body.Close()
				}
			}()
		}
		VerificationData.verificationBuckets = make([]VerificationBucket, TotalIntervals)
	}
	c.verificationBuckets[c.bucketIndex].PeriodEnding = nextPeriodEnding
	c.verificationBuckets[c.bucketIndex].PeriodEndingUnix = nextPeriodEnding.Unix()
}

func (c *verificationCollection) AddDataPoint(status VerificationStatus) {
	c.Lock()
	defer c.Unlock()
	if c.ready {
		c.verificationBuckets[c.bucketIndex].Requests++
		switch status {
		case VerificationValidA:
			c.verificationBuckets[c.bucketIndex].ValidA++
			c.verificationBuckets[c.bucketIndex].Valid++
		case VerificationValidB:
			c.verificationBuckets[c.bucketIndex].ValidB++
			c.verificationBuckets[c.bucketIndex].Valid++
		case VerificationValidC:
			c.verificationBuckets[c.bucketIndex].ValidC++
			c.verificationBuckets[c.bucketIndex].Valid++
		case VerificationNoSignature:
			c.verificationBuckets[c.bucketIndex].NoSignature++
		case VerificationInvalidSignature:
			c.verificationBuckets[c.bucketIndex].InvalidSignature++
		case VerificationNotTrusted:
			c.verificationBuckets[c.bucketIndex].NotTrusted++
		case VerificationTnMismatch:
			c.verificationBuckets[c.bucketIndex].TnMismatch++
		case VerificationBadFormat:
			c.verificationBuckets[c.bucketIndex].BadFormat++
		case VerificationStale:
			c.verificationBuckets[c.bucketIndex].Stale++
		}
	}
}

func (c *signingCollection) setReady(ready bool) {
	c.Lock()
	defer c.Unlock()
	c.ready = ready
}

func (c *signingCollection) rotateBucket() {
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Stats: Rotating signing bucket"}
	c.Lock()
	defer c.Unlock()
	nextPeriodEnding := c.signingBuckets[c.bucketIndex].PeriodEnding.Add(time.Minute * MinutesPerBucket)
	c.bucketIndex = (c.bucketIndex + 1) % TotalIntervals
	if c.bucketIndex == 0 {
		// We need to post the data and then reset the data collection
		dataCopy := make([]SigningBucket, TotalIntervals)
		copy(dataCopy, SigningData.signingBuckets)
		dataExport := SigningDataExport{
			Ocn:        GlobalConfig.GetStiAsCarrierOcn(),
			InstanceId: GlobalConfig.GetServerInstanceId(),
			Buckets:    &dataCopy,
		}
		if !GlobalConfig.IsTelemetryDisabled() {
			logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Stats: Posting signing data"}
			go func() {
				jsonBytes, err := json.Marshal(&dataExport)
				if err != nil {
					return
				}
				req, err := http.NewRequest(http.MethodPost, SigningUrl, bytes.NewBuffer(jsonBytes))
				if err != nil {
					return
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Set("User-Agent", UserAgent)
				resp, err := httpClient.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()
			}()
		}
		SigningData.signingBuckets = make([]SigningBucket, TotalIntervals)
	}
	c.signingBuckets[c.bucketIndex].PeriodEnding = nextPeriodEnding
	c.signingBuckets[c.bucketIndex].PeriodEndingUnix = nextPeriodEnding.Unix()
}

func (c *signingCollection) AddDataPoint(status SigningStatus) {
	c.Lock()
	defer c.Unlock()
	if c.ready {
		c.signingBuckets[c.bucketIndex].Requests++
		switch status {
		case SigningSuccess:
			c.signingBuckets[c.bucketIndex].SuccessCount++
		case SigningFailureInvalid:
			c.signingBuckets[c.bucketIndex].InvalidCount++
		case SigningFailureNotReady:
			c.signingBuckets[c.bucketIndex].NotReadyCount++
		}
	}
}

// roundUpTime rounds time t up to the requested interval given by time.Duration
func roundUpTime(t time.Time, roundOn time.Duration) time.Time {
	t = t.Round(roundOn)
	if time.Since(t) >= 0 {
		t = t.Add(roundOn)
	}
	return t
}
