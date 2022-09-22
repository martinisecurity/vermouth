package vermouth

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ipifony/vermouth/logger"
	"github.com/ipifony/vermouth/stivs"
	"gopkg.in/square/go-jose.v2"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// CertIssuerOid OID for certIssuer
const CertIssuerOid = "2.5.29.29"

var ourTrustAnchors StirShakenCaPool

func loadStiPaRoot() (*x509.Certificate, error) {
	stiRootBytes, err := os.ReadFile(GlobalConfig.GetStiPaRootPath())
	if err != nil {
		return nil, err
	}
	var buf []byte
	getCertsFromBytes(stiRootBytes, &buf)
	rootCert, err := x509.ParseCertificate(buf)
	return rootCert, nil
}

func loadCachedTrust() {
	// Attempt to load CA Trust List and CRL from cache
	// This allows us to immediately begin operations even if the refresh we are about to attempt would fail
	var trustCacheStr string
	err := readGob(GlobalConfig.GetServerCaTrustCache(), &trustCacheStr)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "Trust Cache: Failed to load from disk: - " + err.Error()}
	} else {
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Trust Cache: Load Succeeded"}
		tmpTrustCache := x509.NewCertPool()
		tmpTrustCache.AppendCertsFromPEM([]byte(trustCacheStr))
		ourTrustAnchors.replacePool(tmpTrustCache)
	}
}

// Expects one or more Base64 encoded PEM certs. buf is appended with the cert decodes
func getCertsFromBytes(PEMBytes []byte, buf *[]byte) {
	for {
		block, rest := pem.Decode(PEMBytes)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			*buf = append(*buf, block.Bytes...)
		}
		if len(rest) == 0 || block == nil {
			break
		}
		PEMBytes = rest
	}
}

type JWTPayload struct {
	Version   string   `json:"version"`
	Sequence  int      `json:"sequence"`
	Exp       int      `json:"exp"`
	TrustList []string `json:"trustList"`
}

type StirShakenCaPool struct {
	sync.RWMutex
	pool *x509.CertPool
}

func (caPool *StirShakenCaPool) replacePool(newPool *x509.CertPool) {
	caPool.Lock()
	defer caPool.Unlock()
	caPool.pool = newPool
}

func (caPool *StirShakenCaPool) assertValidLeafCert(cert *x509.Certificate, intermediates []*x509.Certificate, crlWorkChan chan string) error {
	// First verify chain is good before checking for revocations
	intermediatePool := x509.NewCertPool()
	for _, intermediateCert := range intermediates {
		intermediatePool.AddCert(intermediateCert)
	}

	caPool.RLock()
	defer caPool.RUnlock()
	opts := x509.VerifyOptions{
		Roots:         caPool.pool,
		Intermediates: intermediatePool,
	}
	_, err := cert.Verify(opts)

	if err != nil {
		return err
	}

	// If we made this far, then the chain is valid. Now check for revocations all the way up
	if certWasRevoked(cert, crlWorkChan) {
		return errors.New("leaf cert " + cert.Subject.CommonName + " was revoked!")
	}

	for _, intermediateCert := range intermediates {
		if certWasRevoked(intermediateCert, crlWorkChan) {
			return errors.New("intermediate cert " + intermediateCert.Subject.CommonName + " was revoked!")
		}
	}

	return nil
}

func certWasRevoked(cert *x509.Certificate, crlWorkChan chan string) bool {
	crlDistPoint := ""
	if len(cert.CRLDistributionPoints) > 0 {
		crlDistPoint = cert.CRLDistributionPoints[0]
	}

	if crlDistPoint == "" {
		// We should try the default known CRL URL before giving up hope
		crlDistPoint = GlobalConfig.GetStiPaApiCrlUrls()[0]
	}
	cacheEntry, found := stivs.GetCrlCache().GetEntry(crlDistPoint)
	if !found {
		// Queue up a job to get this crl
		go scheduleCrlJob(0*time.Second, crlDistPoint, crlWorkChan)
		return false
	}
	for _, revokedCert := range cacheEntry.Revocations {
		if cert.SerialNumber == revokedCert.SerialNumber && cert.Issuer.String() == revokedCert.Issuer.String() {
			return true
		}
	}
	return false
}

func getAuthToken(url string, userId string, password string) (string, error) {
	requestBody, _ := json.Marshal(map[string]string{
		"userId":   userId,
		"password": password,
	})

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	var authRespMap map[string]string
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(respBytes, &authRespMap)
	if err != nil {
		return "", err
	}
	if authRespMap["status"] == "success" {
		return authRespMap["accessToken"], nil
	}
	return "", errors.New("auth failed. STI-PA access token not granted")
}

func getCaList(url string, accessToken string) ([]byte, error) {
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Add("Accept", "application/jose+json")
	r.Header.Add("Authorization", accessToken)
	r.Header.Set("User-Agent", UserAgent)
	resp, err := httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func getCertsFromUrl(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func getAccessToken() (*string, error) {
	tokenUrl := GlobalConfig.GetStiPaApiBaseUrl() + "/auth/login"
	token, err := getAuthToken(tokenUrl, GlobalConfig.GetStiPaApiUserId(), GlobalConfig.GetStiPaApiPassword())
	if err != nil {
		return nil, errors.New("error retrieving access token - " + err.Error())
	}
	if len(token) <= 0 {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA: "}
		return nil, errors.New("token parse successful, but accessToken is empty")
	}
	return &token, nil
}

func refreshTrustAnchors(responseChan chan<- Message, stiPaRoots *x509.CertPool) {
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CA List: Refreshing..."}
	statusMsg := Message{
		MessageSender: TrustAnchorWorker,
		MessageType:   Failure,
		MsgStr:        "",
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CA List: Requesting access token"}
	token, err := getAccessToken()
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CA List: " + err.Error()}
		responseChan <- statusMsg
		return
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CA List: Got accessToken. token=" + *token}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CA List: Requesting ca-list..."}
	// Next we fetch and verify the CA List. The signed JWT representing the trust list is part of the JSON response.
	caListUrl := GlobalConfig.GetStiPaApiBaseUrl() + "/ca-list"
	caListResponseBytes, err := getCaList(caListUrl, *token)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CA List: Failed to get response from ca-list request - " + err.Error()}
		responseChan <- statusMsg
		return
	}
	var caList string
	var caListRespMap map[string]string
	err = json.Unmarshal(caListResponseBytes, &caListRespMap)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CA List: Failed to parse CA list JSON - " + err.Error()}
		responseChan <- statusMsg
		return
	}
	if caListRespMap["status"] == "success" {
		caList = caListRespMap["caList"]
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CA List: List parsed"}
	jws, err := jose.ParseSigned(caList)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CA List: JWS parse Failed - " + err.Error()}
		responseChan <- statusMsg
		return
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CA List: JWS parse successful"}
	if jws.Signatures[0].Header.Algorithm != "ES256" {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CA List: Expected ES256. Got " + jws.Signatures[0].Header.Algorithm}
		responseChan <- statusMsg
		return
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CA List: Requesting X5U..."}
	x5uUrl := fmt.Sprintf("%v", jws.Signatures[0].Header.ExtraHeaders["x5u"])
	certBytes, err := getCertsFromUrl(x5uUrl)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CA List: X5U get request failed - " + err.Error()}
		responseChan <- statusMsg
		return
	}
	var buf []byte
	getCertsFromBytes(certBytes, &buf)
	certs, err := x509.ParseCertificates(buf)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CA List: Could not parse X5U certs from bytes - " + err.Error()}
		responseChan <- statusMsg
		return
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CA List: X5U certs parsed"}
	// Time to validate the signature over the JWT
	// We expect the first certificate listed to have signed the JWT with its public key
	payload, err := jws.Verify(certs[0].PublicKey)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CA List: JWT has invalid signature - " + err.Error()}
		responseChan <- statusMsg
		return
	}

	// Chase leaf cert to known root. We will not use a root even if presented to us as such
	intermediates := x509.NewCertPool()
	for _, intCert := range certs {
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CA List: Adding intermediate cert: " + intCert.Subject.CommonName}
		intermediates.AddCert(intCert)
	}

	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         stiPaRoots,
	}

	_, err = certs[0].Verify(opts)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CA List: JWT signer could not chain to STI-PA root - " + err.Error()}
		responseChan <- statusMsg
		return
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CA List: JWT signer validated"}

	payloadObj := JWTPayload{}
	err = json.Unmarshal(payload, &payloadObj)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CA List: JWT unmarshal failed - " + err.Error()}
		responseChan <- statusMsg
		return
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CA List: About to process list"}
	certBlob := strings.Join(payloadObj.TrustList, "\n")
	// We need to prepare for checking the validity of the certs purportedly issued by CA's from the STI-PA CA List
	// These will be used to build the CA List for STIR/SHAKEN INVITES
	tmpTrustListAnchors := x509.NewCertPool()
	tmpTrustListAnchors.AppendCertsFromPEM([]byte(certBlob))
	if len(tmpTrustListAnchors.Subjects()) > 0 {
		str := fmt.Sprintf("STI-PA CA List: Parsed %d of %d presented STIR/SHAKEN CA List", len(tmpTrustListAnchors.Subjects()), len(payloadObj.TrustList))
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: str}
		ourTrustAnchors.replacePool(tmpTrustListAnchors)
		// Write the latest pull of certBlob
		err = writeGob(GlobalConfig.GetServerCaTrustCache(), certBlob)
		if err != nil {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CA List: Failed to write trust cache gob - " + err.Error()}
		}
	} else {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CA List: Failed to add any STIR/SHAKEN CA certs. This will be a problem."}
		responseChan <- statusMsg
		return
	}

	statusMsg.MessageType = Success
	statusMsg.MsgStr = "Refreshed CA list"
	responseChan <- statusMsg
}
