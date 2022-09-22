package vermouth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ipifony/vermouth/logger"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

var acmeAcctKey = &ecdsa.PrivateKey{}
var acmeMethods map[string]string
var nextNonce = &agedNonce{}

const AcmeSignerKey = "signer.key"
const AcmeSignerCert = "signer.crt"

var acmeMetaData = &AcmeMetaData{}

const martiniStaging = "https://wfe.dev.martinisecurity.com/v2/acme/directory"
const martiniProd = "https://wfe.prod.martinisecurity.com/v2/acme/directory"

type AcmeStatus string

const (
	AcmePending     AcmeStatus = "pending"
	AcmeProcessing  AcmeStatus = "processing"
	AcmeReady       AcmeStatus = "ready"
	AcmeValid       AcmeStatus = "valid"
	AcmeInvalid     AcmeStatus = "invalid"
	AcmeRevoked     AcmeStatus = "revoked"
	AcmeDeactivated AcmeStatus = "deactivated"
	AcmeComplete    AcmeStatus = "complete"
)

func initializeAcme() {
	// Attempt to load up existing ACME cert
	err := acmeMetaData.loadMetaData()
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "ACME Client: Could not load meta data."}
	}
	err = readyAcmeApi()
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "ACME Client: API Unavailable!"}
		return
	} else {
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: API Fetch Successful"}
	}
	err = readyAcmeKey()
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "ACME Client: ACME Key Unbound/Unusable - " + err.Error()}
		return
	}
	spcValid := isValidSpcToken()
	if spcValid {
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Cached ACME SPC Token is valid"}
	} else {
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Must request new ACME SPC token"}
		err = requestAndStoreSpcToken()
		if err != nil {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "ACME Client: SPC Token request error - " + err.Error()}
			return
		} else {
			logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: SPC Token request successful"}
		}
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-AS: Attempting to load existing ACME cert..."}
	signingKey := filepath.Clean(GlobalConfig.GetStiAsAcmeDir()) + string(filepath.Separator) + AcmeSignerKey
	ourSigner.Configure(signingKey, acmeMetaData.CrtRepoPubUrl)
	if !ourSigner.IsReady() {
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-AS: ACME cert missing or invalid. Delegating to ACME client..."}

		err = startNewCertRequest()
		if err != nil {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "ACME Client: Cert Request Failed - " + err.Error()}
			return
		}
		// We should have a cert to load now
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-AS: Just finished with ACME; Configuring Signer..."}
		ourSigner.Configure(signingKey, acmeMetaData.CrtRepoPubUrl)
	} else {
		// We loaded the existing key just fine, but we might immediately need to cycle it
		go CheckAndRefreshAcmeCert()
	}
}

func CheckAndRefreshAcmeCert() {
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Performing Signing Cert Check"}
	signerCrtFilename := filepath.Clean(GlobalConfig.GetStiAsAcmeDir()) + string(filepath.Separator) + AcmeSignerCert
	readBytes, err := os.ReadFile(signerCrtFilename)
	if err != nil {
		return
	}
	block, _ := pem.Decode(readBytes)
	x509Encoded := block.Bytes
	acmeCert, err := x509.ParseCertificate(x509Encoded)
	if err != nil {
		return
	}
	// If we are more than 30 days (expressed as hours) out, return
	if acmeCert.NotAfter.Sub(time.Now()).Hours() > 24*30 {
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Cert will expire later than 30 days. Returning..."}
		return
	}
	if acmeCert.NotAfter.Before(time.Now()) {
		// Cert expired
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Cert is expired. Renewing..."}
		ourSigner.SetReady(false)
	} else {
		// We are within 30 days of expiration. Time to act!
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Cert will expire within 30 days. Renewing..."}
	}
	err = startNewCertRequest()
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "ACME Client: Cert failed to renew - " + err.Error()}
		return
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Sleeping 5 minutes before rolling cert..."}
	time.Sleep(5 * time.Minute) // wait for cert publication before cycling cert
	resp, err := httpClient.Get(acmeMetaData.CrtRepoPubUrl)
	if err != nil {
		return
	}
	readBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
	block, _ = pem.Decode(readBytes)
	x509Encoded = block.Bytes
	_, err = x509.ParseCertificate(x509Encoded)
	if err != nil {
		return
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Renewal complete. Reconfiguring our signer."}
	ourSigner.Configure(filepath.Clean(GlobalConfig.GetStiAsAcmeDir())+string(filepath.Separator)+AcmeSignerKey, acmeMetaData.CrtRepoPubUrl)
}

func readyAcmeApi() error {
	acmeMethods = make(map[string]string)
	acmeDirectory := martiniStaging
	if GlobalConfig.IsProdMode() {
		acmeDirectory = martiniProd
	}
	resp, err := httpClient.Get(acmeDirectory)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(respBytes, &acmeMethods)
	if err != nil {
		return err
	}
	return nil
}

func readyAcmeKey() error {
	readBytes, err := os.ReadFile(GlobalConfig.GetStiAsAcmeAcctKeyFile())
	if err != nil {
		acmeAcctKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		go func() {
			err = os.WriteFile(GlobalConfig.GetStiAsAcmeAcctKeyFile(), dehydratePrivateKey(acmeAcctKey), 0777)
			if err != nil {
				logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "ACME Client: Private key could not be persisted!"}
			}
		}()
	} else {
		acmeAcctKey, err = rehydratePrivateKey(readBytes)
		if err != nil {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "ACME Client: Private key could not be loaded and parsed!"}
			return err
		}
	}
	if !GlobalConfig.IsStiAsAcmeAcctKeyBound() {
		// We need to bind our private key to the acme account
		return registerAcmeKey()
	}
	return nil
}

func registerAcmeKey() error {
	nonce, err := nextNonce.Get()
	if err != nil {
		return errors.New("acme client nonce not available")
	}

	jwk := jose.JSONWebKey{
		Key:   &acmeAcctKey.PublicKey,
		KeyID: "ACME ACCT KEY " + strconv.FormatInt(time.Now().Unix(), 10),
	}
	eabSecret64 := GlobalConfig.GetStiAsAcmeEabKeySecret()
	eabSecretBytes, _ := base64.RawURLEncoding.DecodeString(eabSecret64)
	innerJoseKey := jose.SigningKey{Algorithm: jose.HS256, Key: eabSecretBytes}
	var innerSignerOpts = jose.SignerOptions{}
	innerSignerOpts.WithHeader("alg", "HS256")
	innerSignerOpts.WithHeader("kid", GlobalConfig.GetStiAsAcmeEabKeyId())
	innerSignerOpts.WithHeader("url", acmeMethods["newAccount"])
	hmacSigner, err := jose.NewSigner(innerJoseKey, &innerSignerOpts)
	if err != nil {
		return err
	}
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return err
	}
	innerJws, err := hmacSigner.Sign(jwkBytes)
	if err != nil {
		return err
	}
	innerSerializedJwt := innerJws.FullSerialize()
	rawJson := json.RawMessage(innerSerializedJwt)

	newAcctPayload := NewAccountPayload{
		Contact:                []string{"mailto:user@example.com"},
		TermsOfServiceAgreed:   true,
		ExternalAccountBinding: &rawJson,
	}

	joseKey := jose.SigningKey{Algorithm: jose.ES256, Key: acmeAcctKey}
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithHeader("jwk", jwk)
	signerOpts.WithHeader("alg", "ES256")
	signerOpts.WithHeader("nonce", nonce)
	signerOpts.WithHeader("url", acmeMethods["newAccount"])
	eccSigner, err := jose.NewSigner(joseKey, &signerOpts)
	if err != nil {
		return err
	}
	newAcctPayloadBytes, err := json.Marshal(newAcctPayload)
	if err != nil {
		return err
	}
	jws, err := eccSigner.Sign(newAcctPayloadBytes)
	if err != nil {
		return err
	}
	signedJwt := jws.FullSerialize()

	req, _ := http.NewRequest(http.MethodPost, acmeMethods["newAccount"], bytes.NewBuffer([]byte(signedJwt)))
	req.Header.Add("Content-Type", "application/jose+json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	nextNonce.Set(resp.Header.Get("Replay-Nonce"))
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		GlobalConfig.setStiAsAcmeAcctKeyBound(true)
		GlobalConfig.setStiAsAcmeAcctLocationUrl(resp.Header.Get("Location"))
		GlobalConfig.Save()
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Account Bound"}
		return nil
	} else {
		b, _ := io.ReadAll(resp.Body)
		return errors.New("ACME Client: Acct Binding Failed - " + string(b))
	}
}

func handleOrderChange(orderUrl string, order *OrderResponse) (*OrderResponse, error) {
	switch AcmeStatus(order.Status) {
	case AcmeProcessing: // We are waiting on the ACME server
		return pollOrder(orderUrl, 5)
	case AcmePending: // ACME server is waiting on us
		challengeResponse, err := retrieveChallenge(order.Authorizations[0])
		if err != nil {
			return order, err
		}
		if challengeResponse.Status == string(AcmeInvalid) {
			// This would mean our previous challenge failed. Only option is to request a new SPC token and try again
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "ACME Client: Challenge failed. Requesting new SPC token"}
			err = requestAndStoreSpcToken()
			if err != nil {
				return nil, err
			}
		}
		challengeResponse, err = respondToChallenge(challengeResponse.Challenges[0].Url)
		if err != nil {
			return order, err
		}
		return pollOrder(orderUrl, 5)
	case AcmeReady: // ACME server is ready for a CSR
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Generating CSR..."}
		privateKey, csr, err := generateCsr()
		if err != nil {
			return order, err
		}
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Requesting Cert..."}
		_, err = requestCert(csr, order.Finalize)
		if err != nil {
			return order, err
		}
		// If made it here then we must persist the private key for later use
		signerKeyFilename := filepath.Clean(GlobalConfig.GetStiAsAcmeDir()) + string(filepath.Separator) + AcmeSignerKey
		err = os.WriteFile(signerKeyFilename, dehydratePrivateKey(privateKey), 0777)
		if err != nil {
			return order, err
		}
		return pollOrder(orderUrl, 5)
	case AcmeValid: // Cert is ready to be consumed and installed
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Cert Available"}

		signerCrtFilename := filepath.Clean(GlobalConfig.GetStiAsAcmeDir()) + string(filepath.Separator) + AcmeSignerCert
		req, _ := createAcmePostAsGetRequest(order.Certificate)
		resp, err := httpClient.Do(req)
		if err != nil {
			return order, err
		}
		acmeMetaData.CrtRepoPubUrl = resp.Header.Get("X-Shaken-Certificate-Location")
		if len(order.X5U) > 0 {
			acmeMetaData.CrtRepoPubUrl = order.X5U
		}
		acmeMetaData.CrtUrl = order.Certificate
		err = acmeMetaData.saveMetaData()
		if err != nil {
			return order, err
		}
		respBytes, err := io.ReadAll(resp.Body)
		err = os.WriteFile(signerCrtFilename, respBytes, 0777)
		if err != nil {
			return order, err
		}
		order.Status = string(AcmeComplete)
		return order, nil
	default: // Unknown status
		return pollOrder(orderUrl, 5)
	}

}

func startNewCertRequest() error {
	orderResponse, orderUrl, err := createNewOrder()
	if err != nil {
		return err
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Created a new order at " + orderUrl}
	challengesAttempts := 0
	reqResponseCycles := 0
	const maxCycles = 30
	for reqResponseCycles < maxCycles {
		orderResponse, err = handleOrderChange(orderUrl, orderResponse)
		if err != nil {
			return err
		}
		currentStatus := AcmeStatus(orderResponse.Status)
		if currentStatus == AcmePending {
			// We need to keep track of failed challenges. Our only recourse is to request a new token, but we don't want to anger the STI-PA...
			challengesAttempts++
		}
		if currentStatus == AcmeComplete {
			return nil
		}
		if currentStatus == AcmeInvalid || currentStatus == AcmeRevoked || currentStatus == AcmeDeactivated {
			retrieveChallenge(orderResponse.Authorizations[0])
			return errors.New("order failed. final status was " + orderResponse.Status)
		}
		if challengesAttempts > 2 {
			return errors.New("acme cert request process is failing due to bad atc challenge. Either SPC token or its exchange is problematic")
		}
		reqResponseCycles++
	}
	return errors.New("did not reach final resolution of acme process after " + strconv.Itoa(maxCycles) + " message exchanges")
}

func createNewOrder() (*OrderResponse, string, error) {
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Creating New Order..."}
	if !GlobalConfig.IsStiAsAcmeAcctKeyBound() {
		return nil, "", errors.New("cannot request acme cert. Acme account unbound")
	}
	if GlobalConfig.getStiAsAcmeAcctLocationUrl() == "" {
		return nil, "", errors.New("cannot request acme cert. Acme account url not found")
	}
	nonce, err := nextNonce.Get()
	if err != nil {
		return nil, "", errors.New("acme client nonce unavailable")
	}
	signerOpts := jose.SignerOptions{}
	signerOpts.WithHeader("alg", "ES256")
	signerOpts.WithHeader("nonce", nonce)
	signerOpts.WithHeader("url", acmeMethods["newOrder"])
	signerOpts.WithHeader("kid", GlobalConfig.getStiAsAcmeAcctLocationUrl())
	joseKey := jose.SigningKey{Algorithm: jose.ES256, Key: acmeAcctKey}
	eccSigner, err := jose.NewSigner(joseKey, &signerOpts)
	if err != nil {
		return nil, "", err
	}
	t := time.Now()
	expiry := time.Date(t.Year(), t.Month(), t.Day()+90, 0, 0, 0, 0, t.Location())
	spcTnEntry := TNEntry{ServiceProviderCode: GlobalConfig.GetStiAsCarrierOcn()}
	spcTnEntryBytes, err := asn1.Marshal(spcTnEntry)
	if err != nil {
		return nil, "", err
	}
	spcTnEntry64 := base64.StdEncoding.EncodeToString(spcTnEntryBytes)
	payload := OrderPayload{
		Identifiers: []TypeValueTuple{
			{
				Type:  "TNAuthList",
				Value: spcTnEntry64,
			},
		},
		NotAfter: expiry.UTC(),
	}
	newOrderPayloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	jws, err := eccSigner.Sign(newOrderPayloadBytes)
	if err != nil {
		return nil, "", err
	}
	signedJwt := jws.FullSerialize()
	req, _ := http.NewRequest(http.MethodPost, acmeMethods["newOrder"], bytes.NewBuffer([]byte(signedJwt)))
	req.Header.Add("Content-Type", "application/jose+json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	nextNonce.Set(resp.Header.Get("Replay-Nonce"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, "", errors.New("create order response was " + strconv.Itoa(resp.StatusCode))
	}
	respBytes, err := io.ReadAll(resp.Body)
	//fmt.Println(string(respBytes))
	if err != nil {
		return nil, "", err
	}
	newOrderResponse := OrderResponse{}
	json.Unmarshal(respBytes, &newOrderResponse)
	orderUrl := resp.Header.Get("Location")
	return &newOrderResponse, orderUrl, nil
}

func createAcmePostAsGetRequest(url string) (*http.Request, error) {
	nonce, err := nextNonce.Get()
	if err != nil {
		return nil, err
	}
	signerOpts := jose.SignerOptions{}
	signerOpts.WithHeader("alg", "ES256")
	signerOpts.WithHeader("nonce", nonce)
	signerOpts.WithHeader("url", url)
	signerOpts.WithHeader("kid", GlobalConfig.getStiAsAcmeAcctLocationUrl())
	joseKey := jose.SigningKey{Algorithm: jose.ES256, Key: acmeAcctKey}
	eccSigner, err := jose.NewSigner(joseKey, &signerOpts)
	if err != nil {
		return nil, err
	}
	jws, err := eccSigner.Sign([]byte{})
	if err != nil {
		return nil, err
	}
	signedJwt := jws.FullSerialize()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewBuffer([]byte(signedJwt)))
	req.Header.Add("Content-Type", "application/jose+json")
	req.Header.Set("User-Agent", UserAgent)
	return req, nil
}

func retrieveChallenge(url string) (*ChallengeResponse, error) {
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Retrieving Authorization Challenge Type and URL"}
	req, err := createAcmePostAsGetRequest(url)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	nextNonce.Set(resp.Header.Get("Replay-Nonce"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("post-as-get for acme challenge failed with status " + strconv.Itoa(resp.StatusCode))
	}
	respBytes, err := io.ReadAll(resp.Body)
	fmt.Println(string(respBytes))
	if err != nil {
		return nil, err
	}
	authorizationResponse := ChallengeResponse{}
	json.Unmarshal(respBytes, &authorizationResponse)
	if authorizationResponse.Challenges[0].Type != "tkauth-01" {
		return nil, errors.New("acme challenge type was " + authorizationResponse.Challenges[0].Type)
	}
	if authorizationResponse.Challenges[0].TkauthType != "atc" {
		return nil, errors.New("acme challenge tkAuthType was " + authorizationResponse.Challenges[0].TkauthType)
	}

	return &authorizationResponse, nil
}

func respondToChallenge(url string) (*ChallengeResponse, error) {
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Responding to authorization challenge"}
	nonce, err := nextNonce.Get()
	if err != nil {
		return nil, err
	}
	signerOpts := jose.SignerOptions{}
	signerOpts.WithHeader("alg", "ES256")
	signerOpts.WithHeader("nonce", nonce)
	signerOpts.WithHeader("url", url)
	signerOpts.WithHeader("kid", GlobalConfig.getStiAsAcmeAcctLocationUrl())
	joseKey := jose.SigningKey{Algorithm: jose.ES256, Key: acmeAcctKey}
	eccSigner, err := jose.NewSigner(joseKey, &signerOpts)
	if err != nil {
		return nil, err
	}
	payload := "{\"atc\":\"" + GlobalConfig.getStiAsAcmeStiPaSpcToken() + "\"}"
	jsonPayload := json.RawMessage(payload)
	jws, err := eccSigner.Sign(jsonPayload)
	if err != nil {
		return nil, err
	}
	signedJwt := jws.FullSerialize()
	fmt.Println(signedJwt)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewBuffer([]byte(signedJwt)))
	req.Header.Add("Content-Type", "application/jose+json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	nextNonce.Set(resp.Header.Get("Replay-Nonce"))
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	fmt.Println(string(respBytes))
	if err != nil {
		return nil, err
	}
	challengeResponse := &ChallengeResponse{}
	json.Unmarshal(respBytes, &challengeResponse)

	return challengeResponse, nil
}

func pollOrder(orderUrl string, delay time.Duration) (*OrderResponse, error) {
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "ACME Client: Polling order at " + orderUrl}
	time.Sleep(delay * time.Second)
	req, err := createAcmePostAsGetRequest(orderUrl)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	nextNonce.Set(resp.Header.Get("Replay-Nonce"))
	respBytes, err := io.ReadAll(resp.Body)
	fmt.Println(string(respBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	orderResponse := OrderResponse{}
	err = json.Unmarshal(respBytes, &orderResponse)
	if err != nil {
		return nil, err
	}
	return &orderResponse, nil
}

func generateCsr() (*ecdsa.PrivateKey, []byte, error) {
	tnAuthListOid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 26}
	keyBytes, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spcTnEntry := TNEntry{ServiceProviderCode: GlobalConfig.GetStiAsCarrierOcn()}
	spcTnEntryBytes, err := asn1.Marshal(spcTnEntry)
	if err != nil {
		return nil, nil, err
	}

	subj := pkix.Name{
		CommonName: "SHAKEN " + GlobalConfig.GetStiAsCarrierOcn(),
		Country:    []string{"US"},
	}

	extensions := make([]pkix.Extension, 0)
	// TNAuthList
	extensions = append(extensions, pkix.Extension{
		Id:    tnAuthListOid,
		Value: spcTnEntryBytes,
	})
	crlUri := GlobalConfig.getStiAsAcmeStiPaCrlUri()
	crlIssuer := GlobalConfig.getStiAsAcmeStiPaCrlIssuer()
	if crlUri == "" {
		crlUri = GlobalConfig.getStiAsAcmeCrlUriFallback()
	}
	if crlIssuer == "" {
		crlIssuer = GlobalConfig.getStiAsAcmeCrlIssuerFallback()
	}

	theRdnSequence, err := ParseDN(crlIssuer)
	if err != nil {
		return nil, nil, err
	}

	crlDistPointContainer := DistributionPointContainer{
		DistributionPoint{
			DistributionPointName: DistributionPointName{
				FullNameContainer{
					Fullname: crlUri,
				},
			},
			CRLIssuerContainer: CRLIssuerContainer{
				CRLIssuer: *theRdnSequence,
			},
		},
	}
	octetString, err := asn1.Marshal(crlDistPointContainer)
	if err != nil {
		return nil, nil, err
	}

	// CRL Distribution Points
	extensions = append(extensions, pkix.Extension{
		Id:    oids["crlDistributionPoints"],
		Value: octetString,
	})

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions:    extensions,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	if err != nil {
		return nil, nil, err
	}

	return keyBytes, csrBytes, nil
}

func requestCert(csrBytes []byte, finalizeUrl string) (*OrderResponse, error) {
	csr64 := base64.RawURLEncoding.EncodeToString(csrBytes)
	nonce, err := nextNonce.Get()
	if err != nil {
		return nil, err
	}
	signerOpts := jose.SignerOptions{}
	signerOpts.WithHeader("alg", "ES256")
	signerOpts.WithHeader("nonce", nonce)
	signerOpts.WithHeader("url", finalizeUrl)
	signerOpts.WithHeader("kid", GlobalConfig.getStiAsAcmeAcctLocationUrl())
	joseKey := jose.SigningKey{Algorithm: jose.ES256, Key: acmeAcctKey}
	eccSigner, err := jose.NewSigner(joseKey, &signerOpts)
	if err != nil {
		return nil, err
	}
	payload := "{\"csr\":\"" + csr64 + "\"}"
	jsonPayload := json.RawMessage(payload)
	jws, err := eccSigner.Sign(jsonPayload)
	if err != nil {
		return nil, err
	}
	signedJwt := jws.FullSerialize()
	req, _ := http.NewRequest(http.MethodPost, finalizeUrl, bytes.NewBuffer([]byte(signedJwt)))
	req.Header.Add("Content-Type", "application/jose+json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	nextNonce.Set(resp.Header.Get("Replay-Nonce"))
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	fmt.Println(string(respBytes))
	if err != nil {
		return nil, err
	}
	orderResponse := OrderResponse{}
	json.Unmarshal(respBytes, &orderResponse)
	return &orderResponse, nil
}

func isValidSpcToken() bool {
	spcBytes := GlobalConfig.getStiAsAcmeStiPaSpcToken()
	jws, err := jose.ParseSigned(spcBytes)
	if err != nil {
		return false
	}
	jwtPayload := SpcTokenResponse{}
	json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &jwtPayload)
	expires := time.Unix(jwtPayload.Exp, 0)
	if time.Now().After(expires) {
		return false
	}
	return true
}

func requestAndStoreSpcToken() error {
	accessTokenUrl := GlobalConfig.GetStiPaApiBaseUrl() + "/auth/login"
	accessToken, err := getAuthToken(accessTokenUrl, GlobalConfig.GetStiPaApiUserId(), GlobalConfig.GetStiPaApiPassword())
	if err != nil || len(accessToken) < 1 {
		return errors.New("STI-PA token request failed")
	}
	spcTnEntry := TNEntry{ServiceProviderCode: GlobalConfig.GetStiAsCarrierOcn()}
	spcTnEntryBytes, err := asn1.Marshal(spcTnEntry)
	if err != nil {
		return err
	}
	spcBase64 := base64.StdEncoding.EncodeToString(spcTnEntryBytes)
	ocn := GlobalConfig.GetStiAsCarrierOcn()
	if ocn == "" {
		return errors.New("no carrier ocn number found")
	}
	acmeFingerPrint, err := getAcmePubKeyFingerprint(&acmeAcctKey.PublicKey)
	if err != nil {
		return err
	}
	url := GlobalConfig.GetStiPaApiBaseUrl() + "/account/" + ocn + "/token"
	requestBody := SpcTokenRequest{Atc: Atc{
		Tktype:      "TNAuthList",
		Tkvalue:     spcBase64,
		Ca:          false,
		Fingerprint: acmeFingerPrint,
	}}
	requestBytes, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(requestBytes))
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/jose+json")
	req.Header.Add("Authorization", accessToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("server reject spc request with " + strconv.Itoa(resp.StatusCode))
	}
	defer resp.Body.Close()
	respMap := make(map[string]string)
	respBytes, err := io.ReadAll(resp.Body)
	json.Unmarshal(respBytes, &respMap)
	if respMap["status"] == "success" {
		GlobalConfig.setStiAsAcmeStiPaSpcToken(respMap["token"])
		if respMap["crl"] != "" {
			GlobalConfig.setStiAsAcmeStiPaCrlUri(respMap["crl"])
		}
		if respMap["iss"] != "" {
			GlobalConfig.setStiAsAcmeStiPaCrlIssuer(respMap["iss"])
		}
	}
	GlobalConfig.Save()

	return nil
}

func dehydratePrivateKey(privateKey *ecdsa.PrivateKey) []byte {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return pemEncoded
}

func rehydratePrivateKey(pemEncoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemEncoded)
	x509Encoded := block.Bytes
	return x509.ParseECPrivateKey(x509Encoded)
}

type NewAccountPayload struct {
	Contact                []string         `json:"contact"`
	TermsOfServiceAgreed   bool             `json:"termsOfServiceAgreed"`
	ExternalAccountBinding *json.RawMessage `json:"externalAccountBinding"`
}

type TypeValueTuple struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
type OrderPayload struct {
	Identifiers []TypeValueTuple `json:"identifiers"`
	NotAfter    time.Time        `json:"notAfter"`
}

type OrderResponse struct {
	Status         string           `json:"status"`
	Expires        time.Time        `json:"expires,omitempty"`
	NotBefore      time.Time        `json:"notBefore"`
	NotAfter       time.Time        `json:"notAfter"`
	Identifiers    []TypeValueTuple `json:"identifiers"`
	Authorizations []string         `json:"authorizations"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate,omitempty"`
	X5U            string           `json:"x5u"`
}

type ChallengeResponse struct {
	Status     string `json:"status"`
	Identifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifier"`
	Challenges []struct {
		Type       string `json:"type"`
		TkauthType string `json:"tkauth-type"`
		Url        string `json:"url"`
		Token      string `json:"token"`
	} `json:"challenges"`
}

type TNEntry struct {
	ServiceProviderCode string `asn1:"tag:0,ia5,explicit,optional,omitempty"`
}

type Atc struct {
	Tktype      string `json:"tktype"`
	Tkvalue     string `json:"tkvalue"`
	Ca          bool   `json:"ca"`
	Fingerprint string `json:"fingerprint"`
}
type SpcTokenRequest struct {
	Atc Atc `json:"atc"`
}
type SpcTokenResponse struct {
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
	Atc Atc    `json:"atc"`
}

func debug(data []byte, err error) {
	if err == nil {
		fmt.Printf("%s\n\n", data)
	} else {
		fmt.Printf("%s\n\n", err)
	}
}

type agedNonce struct {
	nonce string
	age   time.Time
}

func (n *agedNonce) Get() (string, error) {
	if n.nonce == "" || time.Since(n.age).Minutes() > 5 {
		url := acmeMethods["newNonce"]
		resp, err := httpClient.Get(url)
		if err != nil {
			return "", err
		}
		n.nonce = resp.Header.Get("Replay-Nonce")
	}
	// All gets should result in this value getting expired out
	n.age = time.Now().Add(5 * time.Minute)
	return n.nonce, nil
}
func (n *agedNonce) Set(nonce string) {
	n.nonce = nonce
	n.age = time.Now()
}

func getAcmePubKeyFingerprint(key *ecdsa.PublicKey) (string, error) {
	keyDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	spkiDigest := sha256.Sum256(keyDER)
	const hextable = "0123456789ABCDEF"
	dst := make([]byte, 2*32+31)
	j := 0
	for _, v := range spkiDigest[0:32] {
		if j > 1 {
			dst[j] = ':'
			j++
		}
		dst[j] = hextable[v>>4]
		dst[j+1] = hextable[v&0x0f]
		j += 2
	}

	return "SHA256 " + string(dst), nil
}

type AcmeMetaData struct {
	CrtUrl        string `yaml:"crt_url"`
	CrtRepoPubUrl string `yaml:"crt_repo_pub_url"`
}

func (metaData *AcmeMetaData) saveMetaData() error {
	metaDataPath := filepath.Clean(GlobalConfig.GetStiAsAcmeDir()) + string(filepath.Separator) + ".metadata"
	data, err := yaml.Marshal(metaData)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "Could not marshal meta data file"}
		return err
	}
	err = os.WriteFile(metaDataPath, data, 0777)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "Could not persist meta data file"}
		return err
	}
	return nil
}
func (metaData *AcmeMetaData) loadMetaData() error {
	metaDataPath := filepath.Clean(GlobalConfig.GetStiAsAcmeDir()) + string(filepath.Separator) + ".metadata"
	tmpMetaData := &AcmeMetaData{}

	file, err := os.Open(metaDataPath)
	if err != nil {
		return err
	}
	defer file.Close()
	d := yaml.NewDecoder(file)
	if err := d.Decode(&tmpMetaData); err != nil {
		return err
	}
	metaData.CrtUrl = tmpMetaData.CrtUrl
	metaData.CrtRepoPubUrl = tmpMetaData.CrtRepoPubUrl

	return nil
}
