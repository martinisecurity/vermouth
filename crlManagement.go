package vermouth

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"github.com/ipifony/vermouth/logger"
	"github.com/ipifony/vermouth/stivs"
	"io"
	"net/http"
	"strconv"
	"time"
)

func beginCrlWorkerQueue(responseChan chan Message, crlWorkChan chan string) {

	stivs.InitCrlCache()

	for {
		select {
		case uri := <-crlWorkChan:
			refreshCrl(responseChan, uri)
		}
	}
}

func getCrlFromUrl(url string) ([]byte, error) {
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Add("Accept", "application/pkix-crl")
	r.Header.Set("User-Agent", UserAgent)
	resp, err := httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Limit to 2 megs (2097152 bytes)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2097152))
	if err != nil {
		return nil, err
	}

	return body, nil
}

func refreshCrl(responseChan chan<- Message, crlDistPoint string) {
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: About to Refresh " + crlDistPoint}
	statusMsg := Message{
		MessageSender: CrlWorker,
		MessageType:   Failure,
		MsgStr:        crlDistPoint + ";10m",
	}

	// Fetch or create new cache entry from map
	var thisCacheEntry = stivs.GetCrlCache().CopyEntry(crlDistPoint)
	if thisCacheEntry != nil {
		if thisCacheEntry.Status == stivs.Initializing {
			logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: Already Refreshing " + crlDistPoint}
			// We just got this CRL Dist Point. No need to force a refresh since we are currently working on it
			return
		}
	} else {
		thisCacheEntry = &stivs.CrlCacheEntry{}
		thisCacheEntry.URI = crlDistPoint
		thisCacheEntry.Status = stivs.Initializing
		stivs.GetCrlCache().AddUpdateEntry(crlDistPoint, thisCacheEntry)
	}

	// Handle edge case of InvalidDestPoint
	if thisCacheEntry.Status == stivs.InvalidDestPoint {
		// Only willing to retry dest point that keeps erroring out once every 24 hours
		if thisCacheEntry.LastAttempt.Before(thisCacheEntry.LastAttempt.Add(24 * time.Hour)) {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CRL: Refusing to retry invalid dest point " + crlDistPoint + " for now"}
			return
		} else {
			// Reset the last attempt to Now() and immediately store, so we don't accept and work multiple requests for this CRL
			thisCacheEntry.LastAttempt = time.Now()
			stivs.GetCrlCache().AddUpdateEntry(crlDistPoint, thisCacheEntry)
		}
	}

	thisCacheEntry.LastAttempt = time.Now()

	crlBytes, err := getCrlFromUrl(crlDistPoint)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CRL: Could not load CRL - " + err.Error()}
		nextAttempt := thisCacheEntry.IncrementError()
		stivs.GetCrlCache().AddUpdateEntry(crlDistPoint, thisCacheEntry)
		statusMsg.MsgStr = nextAttempt
		responseChan <- statusMsg
		return
	} else {
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: HTTP GET Successful"}
	}

	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: Parsing HTTP response..."}
	var crlDERBytes []byte
	getCrlDERFromPEMBytes(crlBytes, &crlDERBytes)
	revocationList, err := x509.ParseRevocationList(crlDERBytes)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CRL: Could not parse CRL bytes - " + err.Error()}
		nextAttempt := thisCacheEntry.IncrementError()
		stivs.GetCrlCache().AddUpdateEntry(crlDistPoint, thisCacheEntry)
		statusMsg.MsgStr = nextAttempt
		responseChan <- statusMsg
		return
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: Parse Successful"}

	// AIA chasing and chain validation

	// Look through the extensions for the AIA
	var aiaUrl string
	for _, extension := range revocationList.Extensions {
		if extension.Id.Equal(oids["authorityInformationAccess"]) {
			aiaUrl, err = getAIAFromAsn1Extension(extension)
			if err != nil || !IsUrl(aiaUrl) {
				logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CRL: Could not get AIA info"}
				nextAttempt := thisCacheEntry.IncrementError()
				stivs.GetCrlCache().AddUpdateEntry(crlDistPoint, thisCacheEntry)
				statusMsg.MsgStr = nextAttempt
				responseChan <- statusMsg
				return
			}
		}
	}

	certBytes, err := getCertsFromUrl(aiaUrl)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CRL: Could not fetch certs from AIA"}
		nextAttempt := thisCacheEntry.IncrementError()
		stivs.GetCrlCache().AddUpdateEntry(crlDistPoint, thisCacheEntry)
		statusMsg.MsgStr = nextAttempt
		responseChan <- statusMsg
		return
	}
	var buf []byte
	getCertsFromBytes(certBytes, &buf)
	certs, err := x509.ParseCertificates(buf)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CRL: Could not parse certs from AIA"}
		nextAttempt := thisCacheEntry.IncrementError()
		stivs.GetCrlCache().AddUpdateEntry(crlDistPoint, thisCacheEntry)
		statusMsg.MsgStr = nextAttempt
		responseChan <- statusMsg
		return
	}

	// Check CRL Signature against signing cert. Spec says first cert in AIA chain is the signer
	err = revocationList.CheckSignatureFrom(certs[0])
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CRL: CRL signature does not match signer"}
		nextAttempt := thisCacheEntry.IncrementError()
		stivs.GetCrlCache().AddUpdateEntry(crlDistPoint, thisCacheEntry)
		statusMsg.MsgStr = nextAttempt
		responseChan <- statusMsg
		return
	}

	// Build trust chain
	intermediatePool := x509.NewCertPool()
	for _, thisCert := range certs {
		if thisCert.Subject.ToRDNSequence().String() != thisCert.Issuer.ToRDNSequence().String() {
			intermediatePool.AddCert(thisCert)
		}
	}
	intermediatePool.AddCert(stiPaRootCert)

	// Verify CRL signer is authentic
	optsCrlSigner := x509.VerifyOptions{
		Roots: intermediatePool,
	}
	_, err = certs[0].Verify(optsCrlSigner)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CRL: CRL signer does not descent from STI-PA root"}
		nextAttempt := thisCacheEntry.IncrementError()
		stivs.GetCrlCache().AddUpdateEntry(crlDistPoint, thisCacheEntry)
		statusMsg.MsgStr = nextAttempt
		responseChan <- statusMsg
		return
	}

	// We need to compare the Subject and Issuer ourselves
	subjectRdnSeq := certs[0].Subject.ToRDNSequence()
	var subjectName pkix.Name
	subjectName.FillFromRDNSequence(&subjectRdnSeq)

	issuerRdnSeq := revocationList.Issuer.ToRDNSequence()
	var issuerName pkix.Name
	issuerName.FillFromRDNSequence(&issuerRdnSeq)

	if issuerName.String() != subjectName.String() {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CRL: Issuer/Subject Mismatch. Aborting..."}
		nextAttempt := thisCacheEntry.IncrementError()
		stivs.GetCrlCache().AddUpdateEntry(crlDistPoint, thisCacheEntry)
		statusMsg.MsgStr = nextAttempt
		responseChan <- statusMsg
		return
	}

	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: CRL passed all validation measures"}
	thisCacheEntry.Number = revocationList.Number
	thisCacheEntry.ErrorCount = 0
	thisCacheEntry.Status = stivs.Valid
	thisCacheEntry.PreviouslyValid = true
	thisCacheEntry.NextUpdate = revocationList.NextUpdate

	// Build set of revocation data: Issuer DN & Serial Number
	tmpList := make([]*stivs.RevokedCertLight, 0)
	for _, revokedCert := range revocationList.RevokedCertificates {
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: About to process revocation with serial number " + revokedCert.SerialNumber.String()}
		for index := range revokedCert.Extensions {
			if revokedCert.Extensions[index].Id.String() == CertIssuerOid {
				var seq asn1.RawValue
				_, err := asn1.Unmarshal(revokedCert.Extensions[index].Value, &seq)
				if err != nil {
					logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CRL: Failed to unmarshal asn1 data from revocation - " + err.Error()}
					continue
				}
				rest := seq.Bytes
				for len(rest) > 0 {
					var v asn1.RawValue
					rest, err = asn1.Unmarshal(rest, &v)
					if err != nil {
						logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CRL: Failed to unmarshal OID Extension 2.5.29.29 from revocation - " + err.Error()}
						continue
					}
					var myRdnSeq pkix.RDNSequence
					_, err = asn1.Unmarshal(v.Bytes, &myRdnSeq)
					if err != nil {
						logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-PA CRL: Failed to unmarshal RDNSequence from revocation - " + err.Error()}
						continue
					}
					var certEntryIssuer pkix.Name
					certEntryIssuer.FillFromRDNSequence(&myRdnSeq)
					thisRevokedCert := stivs.RevokedCertLight{
						SerialNumber: revokedCert.SerialNumber,
						Issuer:       certEntryIssuer,
					}
					tmpList = append(tmpList, &thisRevokedCert)
					logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: Finished processing revocation with serial number " + revokedCert.SerialNumber.String()}
				}
			}
		}
	}
	// Replace revoked certs with new list
	thisCacheEntry.Revocations = tmpList

	totalRevocations := strconv.Itoa(len(revocationList.RevokedCertificates))
	processedRevocations := strconv.Itoa(len(thisCacheEntry.Revocations))
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-PA CRL: Successfully processed " + processedRevocations + " of " + totalRevocations + " total revocations"}

	durationUntilNextRefresh := "12h" // default refresh
	if revocationList.NextUpdate.Before(time.Now().Add(12 * time.Hour)) {
		// Unless sooner
		durationUntilNextRefresh = (time.Until(revocationList.NextUpdate.Add(5 * time.Minute))).String()
	}

	stivs.GetCrlCache().AddUpdateEntry(crlDistPoint, thisCacheEntry)

	statusMsg.MessageType = Success
	statusMsg.MsgStr = thisCacheEntry.URI + ";" + durationUntilNextRefresh
	responseChan <- statusMsg
}

func getCrlDERFromPEMBytes(PEMBytes []byte, buf *[]byte) {
	block, _ := pem.Decode(PEMBytes)
	if block == nil {
		return
	}
	if block.Type == "X509 CRL" {
		*buf = append(*buf, block.Bytes...)
	}
}

func scheduleCrlJob(duration time.Duration, uri string, crlWorkChan chan string) {
	time.AfterFunc(duration, func() {
		crlWorkChan <- uri
	})
}
