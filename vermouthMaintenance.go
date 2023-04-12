package vermouth

import (
	"crypto/x509"
	"encoding/json"
	"github.com/ipifony/vermouth/logger"
	"github.com/ipifony/vermouth/stivs"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var (
	AppName    = "Vermouth"
	AppVersion = "0.0.0-dev"
	UserAgent  = AppName + "/" + AppVersion + " (" + runtime.GOOS + ")"
)

var (
	httpClient     = &http.Client{}
	startTime      = time.Now()
	lastCaRefresh  = time.Time{}
	lastCrlRefresh = time.Time{}
	stiPaRootCert  *x509.Certificate
)

func BeginVermouthOperations() {
	// Begin listening for OS signals
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGINT)
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				// We use this for logging rotation
				logger.OurLogger.RotateLogs()
			case syscall.SIGINT:
				close(sigChan)
				logger.OurLogger.SyncAndCloseLogs(0)
			}
		}
	}()

	// First let's check to see if we are the latest version of the software
	go checkForUpdate()
	// Load STI-PA Root
	tmpRootCert, err := loadStiPaRoot()
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.FATAL, MsgStr: "STI-PA Trust: STI-PA Root unavailable - " + err.Error()}
		return
	}
	stiPaRootCert = tmpRootCert

	// Add STI-PA Root to cert pool
	stiPaRootPool := x509.NewCertPool()
	stiPaRootPool.AddCert(stiPaRootCert)

	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA Trust: Root cert ready"}
	// Load known STI-PA CRL URLs
	crlUrls := GlobalConfig.GetStiPaApiCrlUrls()

	// Load CA trust cache
	loadCachedTrust()

	// Configure our HTTP client for later use
	tr := &http.Transport{
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     30 * time.Second,
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	}
	httpClient = &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
	}
	// crlWorkChan will act as a resource constrained CRL fetcher and verifier
	crlWorkChan := make(chan string)

	// responseChan will be used by any go routines passing messages upstream
	responseChan := make(chan Message, 20)

	caTrustRefreshTicker := time.NewTicker(24 * time.Hour)

	dnoRefreshTicker := time.NewTicker(24 * 7 * time.Hour)
	refreshDNO(responseChan)

	var acmeCertRefreshTicker = &time.Ticker{}

	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Vermouth: STI-AS will operate in ACME mode"}
	acmeCertRefreshTicker = time.NewTicker(24 * time.Hour)

	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Vermouth: Initial Refresh of trust stores..."}

	go refreshTrustAnchors(responseChan, stiPaRootPool)

	go beginCrlWorkerQueue(responseChan, crlWorkChan)

	// Initialize CRLs
	for _, url := range crlUrls {
		crlWorkChan <- url
	}

	go readyDataCollection()

	go startAuthVerifyServer(responseChan, crlWorkChan)

	cacheCleanupTimer := time.NewTicker(24 * time.Hour)

	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Vermouth: About to enter infinite maintenance loop..."}
	// Do forever
	for {
		select {
		case msg := <-responseChan:
			switch msg.MessageSender {
			case TrustAnchorWorker:
				if msg.MessageType == Success {
					logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CA List: Refresh Successful. Next attempt in 24 hours..."}
					caTrustRefreshTicker.Reset(24 * time.Hour) // 24 hours
					lastCaRefresh = time.Now()
				} else if msg.MessageType == Failure {
					logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CA List: Refresh Failed. Next attempt in 1 hour..."}
					caTrustRefreshTicker.Reset(1 * time.Hour) // 1 hour
				}
			case CrlWorker:
				info := strings.Split(msg.MsgStr, ";")
				if !IsUrl(info[0]) {
					if msg.MessageType == Success {
						lastCrlRefresh = time.Now()
						logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: Refresh Successful but no CRL info was communicated"}
					} else {
						logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: Refresh Failed and no CRL info was communicated"}
					}
					break
				}
				duration, err := time.ParseDuration(info[1])
				if err != nil {
					if msg.MessageType == Success {
						lastCrlRefresh = time.Now()
						logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: Refresh Successful for " + info[0] + " but refresh not scheduled"}
					} else {
						logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: Refresh Failed for " + info[0] + " and refresh not scheduled"}
					}
					break
				}

				if msg.MessageType == Success {
					lastCrlRefresh = time.Now()
					logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: Refresh Successful for " + info[0] + ". Next refresh in " + duration.String()}
				} else {
					logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: Refresh failed for " + info[0] + ". Next refresh in " + duration.String()}
				}
				go scheduleCrlJob(duration, info[0], crlWorkChan)
			case AuthVerifyWorker:
				if msg.MessageType == Failure {
					// For now, let's just delay a few seconds and restart the server if something unexpected happens
					go func() {
						time.Sleep(5 * time.Second)
						go startAuthVerifyServer(responseChan, crlWorkChan)
					}()
				}
			case DNOWorker:
				if msg.MessageType == Success {
					dnoRefreshTicker.Reset(24 * 7 * time.Hour)
					logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "DNO: Refresh successful"}
				} else {
					dnoRefreshTicker.Reset(1 * time.Hour)
					logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "DNO: Refresh failed"}
				}
			}
		case <-caTrustRefreshTicker.C:
			logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CA List: Maintenance..."}
			go refreshTrustAnchors(responseChan, stiPaRootPool)
		case <-acmeCertRefreshTicker.C:
			logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Acme Client: Maintenance..."}
			go CheckAndRefreshAcmeCert()
		case <-cacheCleanupTimer.C:
			logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-VS: Cache Maintenance..."}
			go stivs.GetCertCache().CleanExpired()
			go checkForUpdate() // Just relying on the cache clean-up timer to also check for software updates
		case <-dnoRefreshTicker.C:
			logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Do Not Originate: Refreshing patterns..."}
		}
	}
}

type MessageSender int

const (
	TrustAnchorWorker MessageSender = iota
	CrlWorker
	AuthVerifyWorker
	DNOWorker
)

type MessageType int

const (
	Success MessageType = iota
	Failure
)

func (m MessageType) String() string {
	return [...]string{"Success", "Failure"}[m]
}

type Message struct {
	MessageSender
	MessageType
	MsgStr string
}

type ExternalStableVersion struct {
	CurrentStable string `json:"currentStable"`
}

func checkForUpdate() {
	versionUrl := "https://www.martinisecurity.com/downloads/vermouthversion.json"
	resp, err := httpClient.Get(versionUrl)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	extVersion := ExternalStableVersion{}
	json.Unmarshal(body, &extVersion)
	if AppVersion != extVersion.CurrentStable {
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Vermouth: Software out-of-date! Please update to version " + extVersion.CurrentStable}
	}

}
