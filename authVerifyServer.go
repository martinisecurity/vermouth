package vermouth

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/ipifony/vermouth/logger"
	"github.com/ipifony/vermouth/stivs"
	"gopkg.in/square/go-jose.v2"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ourSigner = &SigningAuth{}

func startAuthVerifyServer(responseChan chan<- Message, crlWorkChan chan string) {
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Auth Verify Server: Starting..."}

	// Start ACME services
	initializeAcme()

	// Ready verification cache to shortcut fetching certs/cert chains
	stivs.InitCertCache()

	//gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	r.Use(gin.CustomRecovery(func(c *gin.Context, err interface{}) {
		str := fmt.Sprintf("%v", err)
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: " Panic Recovered in Gin: " + str}
		if strings.HasPrefix(c.Request.URL.Path, "/ezstir") {
			c.String(http.StatusInternalServerError, "500 Server Error")
			return
		}
		thisError := generateServiceErrorResponse(InternalServerError, nil)
		c.JSON(InternalServerError.toHttpResponseCode(), &thisError)
	}))

	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/ezstir") {
			c.String(http.StatusNotFound, "404 Not Found")
			return
		}
		thisError := generateServiceErrorResponse(NotFound, nil)
		c.JSON(NotFound.toHttpResponseCode(), &thisError)
	})

	r.GET("/status", func(c *gin.Context) {
		getServerStatus(c)
	})

	// Stripped down quick API
	v1Ez := r.Group("/ezstir/v1")
	v1Ez.POST("/signing/:orig/:dest/:attest/*origid", func(c *gin.Context) {
		processEzStirSign(c)
	})
	v1Ez.POST("/signing/:orig/:dest", func(c *gin.Context) {
		processEzStirSign(c)
	})
	v1Ez.POST("/verification/:from/:pai/:to/:ruri/*identity", func(c *gin.Context) {
		processEzStirVerify(c, crlWorkChan)
	})
	v1Ez.GET("/signing/:orig/:dest/:attest/*origid", func(c *gin.Context) {
		processEzStirSign(c)
	})
	v1Ez.GET("/signing/:orig/:dest/:attest", func(c *gin.Context) {
		processEzStirSign(c)
	})
	v1Ez.GET("/signing/:orig/:dest", func(c *gin.Context) {
		processEzStirSign(c)
	})
	v1Ez.GET("/verification/:from/:pai/:to/:ruri/*identity", func(c *gin.Context) {
		processEzStirVerify(c, crlWorkChan)
	})
	// Compliant (mostly) API
	v1Compliant := r.Group("/stir/v1")

	v1Compliant.POST("/signing", func(c *gin.Context) {
		processInSpecSign(c)
	})
	v1Compliant.GET("/signing", func(c *gin.Context) {
		thisError := generateServiceErrorResponse(InvalidHttpMethod, nil)
		c.JSON(InvalidHttpMethod.toHttpResponseCode(), &thisError)
		return
	})

	v1Compliant.POST("/verification", func(c *gin.Context) {
		processInSpecVerify(c, crlWorkChan)
	})
	v1Compliant.GET("/verification", func(c *gin.Context) {
		thisError := generateServiceErrorResponse(InvalidHttpMethod, nil)
		c.JSON(InvalidHttpMethod.toHttpResponseCode(), &thisError)
		return
	})

	authorized := r.Group("/admin", gin.BasicAuth(gin.Accounts{
		GlobalConfig.GetServerAdminApiUsername(): GlobalConfig.GetServerAdminApiPassword(),
	}))
	authorized.GET("/reload_config", func(c *gin.Context) {
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Vermouth: Config Reload Requested..."}
		err := GlobalConfig.ReloadConfig()
		if err != nil {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "Vermouth: Config Reload failed - " + err.Error()}
		}
	})
	err := r.Run(GlobalConfig.getListenPoint())
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "Auth Verify Server: Server Crashed - " + err.Error()}
		status := Message{
			MessageSender: AuthVerifyWorker,
			MessageType:   Failure,
			MsgStr:        "Crashed",
		}
		responseChan <- status
	}
}

// The in-spec sign manually unmarshalls the JSON since we must allow unknown/unexpected fields to appear in the JWT
func processInSpecSign(c *gin.Context) {
	if !ourSigner.IsReady() {
		go SigningData.AddDataPoint(SigningFailureNotReady)
		thisError := generateServiceErrorResponse(InternalServerError, nil)
		c.JSON(InternalServerError.toHttpResponseCode(), &thisError)
		return
	}
	if c.Request.Body == nil || c.Request.ContentLength < 1 {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		thisError := generateServiceErrorResponse(MissingJsonBody, nil)
		c.JSON(MissingJsonBody.toHttpResponseCode(), &thisError)
		return
	}
	if c.Request.Header.Values("Content-Length") == nil {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		thisError := generateServiceErrorResponse(MissingContentLength, nil)
		c.JSON(MissingContentLength.toHttpResponseCode(), &thisError)
		return
	}
	// In theory, we could only accept application/json...let's ignore this for now
	//if c.Request.Header.Get("Accept") != "application/json" {
	//	thisError := generateServiceErrorResponse(UnsupportedBodyTypeInAccept)
	//	c.JSON(UnsupportedBodyTypeInAccept.toHttpResponseCode(), &thisError)
	//	return
	//}

	if c.Request.Header.Get("Content-Type") != "application/json" {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		vars := []string{"content type ('application/json')"}
		thisError := generateServiceErrorResponse(UnsupportedContentType, vars)
		c.JSON(UnsupportedContentType.toHttpResponseCode(), &thisError)
		return
	}

	bytes, err := io.ReadAll(io.LimitReader(c.Request.Body, c.Request.ContentLength))
	if err != nil {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		thisError := generateServiceErrorResponse(InternalServerError, nil)
		c.JSON(InternalServerError.toHttpResponseCode(), &thisError)
		return
	}
	var signingRequestJsonContainer map[string]interface{}
	err = json.Unmarshal(bytes, &signingRequestJsonContainer)
	if err != nil {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		vars := []string{"invalid message body length specified/invalid JSON body"}
		thisError := generateServiceErrorResponse(JsonParseError, vars)
		c.JSON(JsonParseError.toHttpResponseCode(), &thisError)
		return
	}

	signingRequestJsonInterface := signingRequestJsonContainer["signingRequest"]
	if signingRequestJsonInterface == nil {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		vars := []string{"signingRequest"}
		thisError := generateServiceErrorResponse(MissingParam, vars)
		c.JSON(MissingParam.toHttpResponseCode(), &thisError)
		return
	}
	signingRequestJson, ok := signingRequestJsonInterface.(map[string]interface{})
	if !ok {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		vars := []string{"invalid message body length specified/invalid JSON body"}
		thisError := generateServiceErrorResponse(JsonParseError, vars)
		c.JSON(JsonParseError.toHttpResponseCode(), &thisError)
		return
	}
	// Check attest
	if signingRequestJson["attest"] == nil {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		vars := []string{"attest"}
		thisError := generateServiceErrorResponse(MissingParam, vars)
		c.JSON(MissingParam.toHttpResponseCode(), &thisError)
		return
	}
	attestVal, ok := signingRequestJson["attest"].(string)
	if ok && stringInSlice(attestVal, allowedAttestationLevels) {
		signingRequestJson["attest"] = strings.ToUpper(attestVal)
	} else {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		vars := []string{"attest", attestVal}
		thisError := generateServiceErrorResponse(InvalidParamValue, vars)
		c.JSON(InvalidParamValue.toHttpResponseCode(), &thisError)
		return
	}

	// Check iat
	if signingRequestJson["iat"] == nil {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		vars := []string{"iat"}
		thisError := generateServiceErrorResponse(MissingParam, vars)
		c.JSON(MissingParam.toHttpResponseCode(), &thisError)
		return
	}
	if iat, ok := signingRequestJson["iat"].(float64); ok {
		distance := math.Abs(float64(time.Now().Unix()) - iat)
		if distance > 30*1000 {
			// We got a request more than 30 seconds old. Let's quietly replace this iat
			signingRequestJson["iat"] = time.Now().Unix()
		}
	} else {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		vars := []string{"iat", "bad value"}
		thisError := generateServiceErrorResponse(InvalidParamValue, vars)
		c.JSON(InvalidParamValue.toHttpResponseCode(), &thisError)
		return
	}

	// check origid
	// We will generate one if none exists or if it is invalid
	if signingRequestJson["origid"] == nil {
		signingRequestJson["origid"] = uuid.New().String()
	} else {
		if origId, ok := signingRequestJson["origid"].(string); !ok || len(origId) < 1 {
			signingRequestJson["origid"] = uuid.New().String()
		}
	}

	// dest could contain an array of TNs or an array of URIs or both
	if signingRequestJson["dest"] == nil {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		vars := []string{"dest"}
		thisError := generateServiceErrorResponse(MissingParam, vars)
		c.JSON(MissingParam.toHttpResponseCode(), &thisError)
		return
	}
	var dstTn string
	if dest, ok := signingRequestJson["dest"].(map[string]interface{}); ok {
		validDest := false
		if dest["tn"] != nil {
			if tnArray, ok := dest["tn"].([]interface{}); ok {
				if len(tnArray) > 0 {
					validDest = true
					for i, ph := range tnArray {
						cleanPh := cleanTn(ph.(string))
						tnArray[i] = cleanPh
						if i == 0 {
							dstTn = cleanPh
						}
					}
				}
			}
		}
		if dest["uri"] != nil {
			if uriArray, ok := dest["uri"].([]interface{}); ok {
				if len(uriArray) > 0 {
					// Something is in the URI array...Probably ok!
					validDest = true
				}
			}
		}
		if !validDest {
			go SigningData.AddDataPoint(SigningFailureInvalid)
			vars := []string{"dest", "bad value"}
			thisError := generateServiceErrorResponse(InvalidParamValue, vars)
			c.JSON(InvalidParamValue.toHttpResponseCode(), &thisError)
			return
		}
	}

	// Check orig
	if signingRequestJson["orig"] == nil {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		vars := []string{"orig"}
		thisError := generateServiceErrorResponse(MissingParam, vars)
		c.JSON(MissingParam.toHttpResponseCode(), &thisError)
		return
	}
	var origTn string
	if orig, ok := signingRequestJson["orig"].(map[string]interface{}); ok {
		if origTn, ok = orig["tn"].(string); ok {
			orig["tn"] = cleanTn(origTn)
		} else {
			go SigningData.AddDataPoint(SigningFailureInvalid)
			vars := []string{"orig", "bad value"}
			thisError := generateServiceErrorResponse(InvalidParamValue, vars)
			c.JSON(InvalidParamValue.toHttpResponseCode(), &thisError)
			return
		}
	} else {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		vars := []string{"orig", "bad value"}
		thisError := generateServiceErrorResponse(InvalidParamValue, vars)
		c.JSON(InvalidParamValue.toHttpResponseCode(), &thisError)
		return
	}

	jsonStr, _ := json.Marshal(signingRequestJson)

	origId := signingRequestJson["origid"].(string)

	// We either received one and honored it, or we generated one. Either way, we send it back in header form
	c.Header("X-RequestID", origId)

	// Time to build JWS
	signedJwt, err := ourSigner.Sign(jsonStr)
	if signedJwt == "" || err != nil {
		go SigningData.AddDataPoint(SigningFailureNotReady)
		thisError := generateServiceErrorResponse(InternalServerError, nil)
		c.JSON(InternalServerError.toHttpResponseCode(), &thisError)
		return
	}
	go WriteSigningRecord(&origTn, &dstTn, &attestVal, &origId)
	go SigningData.AddDataPoint(SigningSuccess)

	var response SigningResponse
	response.SigningResponseBody.Identity = &signedJwt

	c.PureJSON(http.StatusOK, response)
}

func processEzStirSign(c *gin.Context) {
	if !ourSigner.IsReady() {
		go SigningData.AddDataPoint(SigningFailureNotReady)
		c.String(http.StatusInternalServerError, "error: not ready to sign")
		return
	}
	orig := c.Param("orig")
	if len(orig) < 3 {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		c.String(http.StatusBadRequest, "error: orig")
		return
	}
	orig = cleanTn(orig)
	dest := c.Param("dest")
	if len(dest) < 3 {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		c.String(http.StatusBadRequest, "error: dest")
		return
	}
	dest = cleanTn(dest)
	destArray := []string{dest}
	attest := c.Param("attest")
	if len(attest) < 1 {
		attest = "A"
	} else {
		if stringInSlice(attest, allowedAttestationLevels) {
			attest = strings.ToUpper(attest)
		} else {
			go SigningData.AddDataPoint(SigningFailureInvalid)
			c.String(http.StatusBadRequest, "error: attest")
			return
		}
	}
	origId := c.Param("origid")
	if len(origId) < 2 {
		origId = uuid.New().String()
	} else {
		// Optional URL params contain the leading '/'
		origId = origId[1:]
	}
	iat := time.Now().Unix()

	signingRequest := EzRequest{
		attest,
		Dest{destArray},
		iat,
		Orig{orig},
		origId,
	}

	jsonBytes, err := json.Marshal(signingRequest)
	if err != nil {
		go SigningData.AddDataPoint(SigningFailureInvalid)
		c.String(http.StatusInternalServerError, "error: struct -> json failed")
		return
	}
	serializedPayload, err := ourSigner.Sign(jsonBytes)
	if err != nil {
		go SigningData.AddDataPoint(SigningFailureNotReady)
		c.String(http.StatusInternalServerError, "error: signing failed")
		return
	}
	go WriteSigningRecord(&orig, &dest, &attest, &origId)
	go SigningData.AddDataPoint(SigningSuccess)
	// SIP Header Friendly Version
	retString := "Identity: " + serializedPayload
	c.String(http.StatusOK, retString)
}

func processInSpecVerify(c *gin.Context, crlWorkChan chan string) {
	thisRecord := VerificationRecord{}

	if c.Request.Body == nil || c.Request.ContentLength < 1 {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		thisError := generateServiceErrorResponse(MissingJsonBody, nil)
		c.JSON(MissingJsonBody.toHttpResponseCode(), &thisError)
		return
	}
	if c.Request.Header.Values("Content-Length") == nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		thisError := generateServiceErrorResponse(MissingContentLength, nil)
		c.JSON(MissingContentLength.toHttpResponseCode(), &thisError)
		return
	}
	if c.Request.Header.Get("Content-Type") != "application/json" {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		vars := []string{"content type ('application/json')"}
		thisError := generateServiceErrorResponse(UnsupportedContentType, vars)
		c.JSON(UnsupportedContentType.toHttpResponseCode(), &thisError)
		return
	}

	readBytes, err := io.ReadAll(io.LimitReader(c.Request.Body, c.Request.ContentLength))
	if err != nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		thisError := generateServiceErrorResponse(InternalServerError, nil)
		c.JSON(InternalServerError.toHttpResponseCode(), &thisError)
		return
	}
	defer c.Request.Body.Close()
	jsonPayload := VerificationRequestPayload{}
	err = json.Unmarshal(readBytes, &jsonPayload)
	if err != nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		vars := []string{"invalid JSON body"}
		thisError := generateServiceErrorResponse(JsonParseError, vars)
		c.JSON(JsonParseError.toHttpResponseCode(), &thisError)
		return
	}
	// Error Case E1
	if jsonPayload.VerificationRequest.To == nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		thisError := generateServiceErrorResponse(MissingParam, []string{"to"})
		c.JSON(MissingParam.toHttpResponseCode(), &thisError)
		return
	}
	if jsonPayload.VerificationRequest.From == nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		thisError := generateServiceErrorResponse(MissingParam, []string{"from"})
		c.JSON(MissingParam.toHttpResponseCode(), &thisError)
		return
	}
	if jsonPayload.VerificationRequest.Time == nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		thisError := generateServiceErrorResponse(MissingParam, []string{"time"})
		c.JSON(MissingParam.toHttpResponseCode(), &thisError)
		return
	}
	if jsonPayload.VerificationRequest.Identity == nil {
		thisRecord.StatusNoSignature = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationNoSignature)
		thisError := generateServiceErrorResponse(MissingParam, []string{"identity"})
		c.JSON(MissingParam.toHttpResponseCode(), &thisError)
		return
	}
	// Error Case E2
	fromVal := jsonPayload.VerificationRequest.From.Tn
	thisRecord.From = &fromVal
	if len(fromVal) < 3 {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		thisError := generateServiceErrorResponse(InvalidParamValue, []string{"from", "bad value"})
		c.JSON(InvalidParamValue.toHttpResponseCode(), &thisError)
		return
	}
	toArray := jsonPayload.VerificationRequest.To.Tn
	if len(toArray) < 1 || len(toArray[0]) < 3 {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		thisError := generateServiceErrorResponse(InvalidParamValue, []string{"to", "bad value"})
		c.JSON(InvalidParamValue.toHttpResponseCode(), &thisError)
		return
	}
	thisRecord.To = &toArray[0]
	if *jsonPayload.VerificationRequest.Time < 1 {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		thisError := generateServiceErrorResponse(InvalidParamValue, []string{"time", "bad value"})
		c.JSON(InvalidParamValue.toHttpResponseCode(), &thisError)
		return
	}
	if len(*jsonPayload.VerificationRequest.Identity) < 1 {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		thisError := generateServiceErrorResponse(InvalidParamValue, []string{"identity", "bad value"})
		c.JSON(InvalidParamValue.toHttpResponseCode(), &thisError)
		return
	}
	identityParts := strings.Split(*jsonPayload.VerificationRequest.Identity, ";")
	if len(identityParts) < 2 {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		thisError := generateServiceErrorResponse(InvalidParamValue, []string{"identity", "bad value"})
		c.JSON(InvalidParamValue.toHttpResponseCode(), &thisError)
		return
	}
	thisRecord.Identity = &identityParts[0]
	jws, err := jose.ParseSigned(identityParts[0])
	if err != nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		thisError := generateServiceErrorResponse(InvalidParamValue, []string{"identity", "bad value"})
		c.JSON(InvalidParamValue.toHttpResponseCode(), &thisError)
		return
	}
	// Error Case E3
	timeDiff := time.Now().Unix() - *jsonPayload.VerificationRequest.Time
	if timeDiff > 60 || timeDiff < -60 {
		thisRecord.StatusStale = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationStale)
		resp := generateVerificationResponse("Received 'time' value is not fresh.", http.StatusForbidden, "Stale Date", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	// Error Case E4
	if len(jws.UnsafePayloadWithoutVerification()) == 0 {
		thisRecord.StatusNoSignature = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationNoSignature)
		resp := generateVerificationResponse("Identity header in compact form instead of required by SHAKEN spec full form.", 438, "Invalid Identity Header", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	// Error Case E5
	if jws.Signatures[0].Header.ExtraHeaders["ppt"] != "shaken" {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("Identity header is received with with 'ppt' parameter value that is not 'shaken'.", 438, "Invalid Identity Header", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	// Error Case E6
	if !strings.HasPrefix(identityParts[1], "info") {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("Missing 'info' parameter in the 'identity'.", 436, "Bad identity Info", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	infoUrl := strings.TrimPrefix(identityParts[1], "info=<")
	infoUrl = strings.TrimSuffix(infoUrl, ">")
	// Error Case E7
	if !IsUrl(infoUrl) {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("Invalid 'info' URI.", 436, "Bad identity Info", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	thisRecord.X5U = &infoUrl
	// We should check whether we already have cached info for this url
	cachedEntry, cachedEntryFound := stivs.GetCertCache().GetEntry(infoUrl)
	var leafCert *x509.Certificate
	var intermediates []*x509.Certificate
	cacheHeader := ""

	// We need to check if our cached entry is still valid
	// If the cached entry is invalid for any reason, we remove the entry and let the process continue as though we had no cache hit
	if cachedEntryFound {
		thisRecord.CertBytes = cachedEntry.CertBytes
		_, errVerify := jws.Verify(cachedEntry.Leaf.PublicKey)
		if errVerify != nil {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-VS: JWT was not signed by cached leaf - " + errVerify.Error()}
		}
		errValid := ourTrustAnchors.assertValidLeafCert(cachedEntry.Leaf, cachedEntry.Intermediates, crlWorkChan)
		if errValid != nil {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-VS: Cached leaf cert could not be validated - " + errValid.Error()}
		}
		if errVerify != nil || errValid != nil {
			stivs.GetCertCache().RemoveEntry(infoUrl)
			cachedEntryFound = false
			if cachedEntry.Forced {
				logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-VS: A forced cached entry for " + infoUrl + " was problematic"}
			}
		}
	}
	var certRespBytes []byte
	if cachedEntryFound {
		leafCert = cachedEntry.Leaf
		intermediates = cachedEntry.Intermediates
	} else {
		// Error Case E8
		certResp, err := httpClient.Get(infoUrl)
		if err != nil {
			thisRecord.StatusNotTrusted = true
			go WriteVerificationRecord(&thisRecord)
			go VerificationData.AddDataPoint(VerificationNotTrusted)
			resp := generateVerificationResponse("Failed to dereference 'info' URI.", 436, "Bad identity Info", NoTNValidation)
			c.JSON(http.StatusOK, &resp)
			return
		}
		certRespBytes, err = io.ReadAll(certResp.Body)
		if err != nil {
			thisRecord.StatusNotTrusted = true
			go WriteVerificationRecord(&thisRecord)
			go VerificationData.AddDataPoint(VerificationNotTrusted)
			resp := generateVerificationResponse("Failed to dereference 'info' URI.", 436, "Bad identity Info", NoTNValidation)
			c.JSON(http.StatusOK, &resp)
			return
		}
		defer certResp.Body.Close()
		thisRecord.CertBytes = &certRespBytes
		leafCert, intermediates = getLeafAndIntermediatesFromBytes(certRespBytes)
		cacheHeader = certResp.Header.Get("Cache-Control")
	}

	// Error Case E9
	ppt := jws.Signatures[0].Header.ExtraHeaders["ppt"]
	if ppt == "" {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("Missing ppt claim in the PASSporT header.", 436, "Bad identity Info", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	typ := jws.Signatures[0].Header.ExtraHeaders["typ"]
	if typ == "" {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("Missing typ claim in the PASSporT header.", 436, "Bad identity Info", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	x5u := jws.Signatures[0].Header.ExtraHeaders["x5u"]
	if x5u == "" {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("Missing x5u claim in the PASSporT header.", 436, "Bad identity Info", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	alg := jws.Signatures[0].Header.Algorithm
	if alg == "" {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("Missing alg claim in the PASSporT header.", 436, "Bad identity Info", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	// Error Case E10
	if x5u != infoUrl {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("'x5u' from PASSporT header doesn't match the 'info' parameter of identity header value.", 436, "Bad identity Info", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	// Error Case E11
	if typ != "passport" {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("'typ' from PASSporT header is not 'passport'.", 437, "Unsupported credential", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	// Error Case E12
	if alg != "ES256" {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("'alg' from PASSporT header is not 'ES256'.", 437, "Unsupported credential", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	// Error Case E13
	if ppt != "shaken" {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("'ppt' from PASSporT header is not 'shaken'.", 438, "Invalid Identity Header", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	// Error Case E14
	idJwt := IdentityJwt{}
	err = json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &idJwt)
	if err != nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("Payload is corrupt", 438, "Invalid Identity Header", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	if idJwt.IdDest == nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("Missing 'dest' mandatory claim in PASSporT payload", 438, "Invalid Identity Header", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	if idJwt.IdOrig == nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("Missing 'orig' mandatory claim in PASSporT payload", 438, "Invalid Identity Header", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	if idJwt.Attest == nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("Missing 'attest' mandatory claim in PASSporT payload", 438, "Invalid Identity Header", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	if idJwt.Origid == nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("Missing 'origid' mandatory claim in PASSporT payload", 438, "Invalid Identity Header", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	if idJwt.Iat == nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("Missing 'iat' mandatory claim in PASSporT payload", 438, "Invalid Identity Header", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	// Error Case E16
	if idJwt.IdOrig.Tn != jsonPayload.VerificationRequest.From.Tn {
		thisRecord.StatusTnMismatch = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationTnMismatch)
		resp := generateVerificationResponse("'orig' claim from PASSporT payload doesn't match the received in the verification request claim.", 438, "Invalid Identity Header", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	foundToMismatch := false
	if len(jsonPayload.VerificationRequest.To.Tn) != len(idJwt.IdDest.Tn) {
		foundToMismatch = true
	}
	if !foundToMismatch {
		for index := range idJwt.IdDest.Tn {
			if jsonPayload.VerificationRequest.To.Tn[index] != idJwt.IdDest.Tn[index] {
				foundToMismatch = true
				break
			}
		}
	}
	if foundToMismatch {
		thisRecord.StatusTnMismatch = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationTnMismatch)
		resp := generateVerificationResponse("'dest' claim from PASSporT payload doesn't match the received in the verification request claim.", 438, "Invalid Identity Header", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	// If we made it this far and were already cached, there is no need to recheck since we already performed these tasks
	if !cachedEntryFound {
		// Error Case E17
		err = ourTrustAnchors.assertValidLeafCert(leafCert, intermediates, crlWorkChan)
		if err != nil {
			thisRecord.StatusNotTrusted = true
			go WriteVerificationRecord(&thisRecord)
			go VerificationData.AddDataPoint(VerificationNotTrusted)
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-VS: Leaf cert could not be validated - " + err.Error()}
			resp := generateVerificationResponse("Failed to authenticate CA.", 437, "Unsupported credential", TNValidationFailed)
			c.JSON(http.StatusOK, &resp)
			return
		}
		// Error Case E18
		_, err = jws.Verify(leafCert.PublicKey)
		if err != nil {
			thisRecord.StatusInvalidSignature = true
			go WriteVerificationRecord(&thisRecord)
			go VerificationData.AddDataPoint(VerificationInvalidSignature)
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-VS: JWT was not signed by leaf - " + err.Error()}
			resp := generateVerificationResponse("Signature validation failed.", 438, "Invalid Identity Header", TNValidationFailed)
			c.JSON(http.StatusOK, &resp)
			return
		}
	}
	// Error Case E15 (for stat collection purposes, this was moved lower)
	iatDiff := time.Now().Unix() - *idJwt.Iat
	if iatDiff > 60 || iatDiff < -60 {
		thisRecord.StatusStale = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationStale)
		resp := generateVerificationResponse("'iat' from PASSporT payload is not fresh.", http.StatusForbidden, "Stale Date", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	// Error Case E19
	if !stringInSlice(*idJwt.Attest, allowedAttestationLevels) {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		resp := generateVerificationResponse("'attest' claim in PASSporT is not valid.", 438, "Invalid Identity Header", NoTNValidation)
		c.JSON(http.StatusOK, &resp)
		return
	}
	if !cachedEntryFound {
		// Cache response for future look-ups
		expireTime, forced := getCacheDirective(cacheHeader)
		newEntry := stivs.CertCacheEntry{
			Leaf:          leafCert,
			Intermediates: intermediates,
			Expires:       expireTime,
			Forced:        forced,
			CertBytes:     &certRespBytes,
		}
		stivs.GetCertCache().AddEntry(infoUrl, newEntry)
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Added cache entry for: " + infoUrl}
	}

	thisRecord.StatusValid = true
	thisRecord.Attestation = idJwt.Attest
	go WriteVerificationRecord(&thisRecord)

	go collectValidVerification(*idJwt.Attest)

	// Made it through all error cases. We can issue a 'TN-Validation-Passed'
	resp := VerificationResponsePayload{VerificationResponse{Verstat: string(TNValidationPassed)}}
	c.JSON(http.StatusOK, resp)
}

func collectValidVerification(attestation string) {
	switch attestation {
	case "A":
		VerificationData.AddDataPoint(VerificationValidA)
	case "a":
		VerificationData.AddDataPoint(VerificationValidA)
	case "B":
		VerificationData.AddDataPoint(VerificationValidB)
	case "b":
		VerificationData.AddDataPoint(VerificationValidB)
	case "C":
		VerificationData.AddDataPoint(VerificationValidC)
	case "c":
		VerificationData.AddDataPoint(VerificationValidC)
	}
}

// Out-of-spec verification designed to play friendly with limited call processing engines where certain shortcuts are necessary.
// The call processing engine (or SBC) is free to naively use the to/from info and signed JWT from the SIP headers
//
//	with very little overhead and get, in response, actionable (and quickly parsable) info
func processEzStirVerify(c *gin.Context, crlWorkChan chan string) {
	thisRecord := VerificationRecord{}

	from := c.Param("from")
	pai := c.Param("pai")
	to := c.Param("to")
	ruri := c.Param("ruri")
	identity := (c.Param("identity"))[1:]

	thisRecord.From = &from
	thisRecord.Pai = &pai
	thisRecord.To = &to
	thisRecord.Ruri = &ruri

	if len(identity) == 0 {
		thisRecord.StatusNoSignature = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationNoSignature)
		c.String(http.StatusOK, "NO-SIGNATURE")
		return
	}
	identityParts := strings.Split(identity, ";")
	thisRecord.Identity = &identityParts[0]
	jws, err := jose.ParseSigned(identityParts[0])
	if err != nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		c.String(http.StatusOK, "BAD-SIGNATURE")
		return
	}
	x5uUrl := fmt.Sprintf("%v", jws.Signatures[0].Header.ExtraHeaders["x5u"])
	thisRecord.X5U = &x5uUrl
	if !IsUrl(x5uUrl) {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		c.String(http.StatusOK, "BAD-SIGNATURE")
		return
	}
	// We should check whether we already have cached info for this url
	cachedEntry, cachedEntryFound := stivs.GetCertCache().GetEntry(x5uUrl)
	var leafCert *x509.Certificate
	var intermediates []*x509.Certificate
	cacheHeader := ""

	// If the cached entry is invalid for any reason, we remove the entry and let the process continue as though we had no cache hit
	if cachedEntryFound {
		thisRecord.CertBytes = cachedEntry.CertBytes
		_, errVerify := jws.Verify(cachedEntry.Leaf.PublicKey)
		if errVerify != nil {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-VS: JWT was not signed by cached leaf - " + errVerify.Error()}
		}
		errValid := ourTrustAnchors.assertValidLeafCert(cachedEntry.Leaf, cachedEntry.Intermediates, crlWorkChan)
		if errValid != nil {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-VS: Cached leaf cert could not be validated - " + errValid.Error()}
		}
		if errVerify != nil || errValid != nil {
			stivs.GetCertCache().RemoveEntry(x5uUrl)
			cachedEntryFound = false
			if cachedEntry.Forced {
				logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-VS: A forced cached entry for " + x5uUrl + " was problematic"}
			}
		}
	}

	var certRespBytes []byte

	if cachedEntryFound {
		leafCert = cachedEntry.Leaf
		intermediates = cachedEntry.Intermediates
	} else {
		certResp, err := httpClient.Get(x5uUrl)
		if err != nil {
			thisRecord.StatusNotTrusted = true
			go WriteVerificationRecord(&thisRecord)
			go VerificationData.AddDataPoint(VerificationNotTrusted)
			c.String(http.StatusOK, "BAD-SIGNATURE")
			return
		}
		certRespBytes, err = io.ReadAll(certResp.Body)
		if err != nil {
			thisRecord.StatusNotTrusted = true
			go WriteVerificationRecord(&thisRecord)
			go VerificationData.AddDataPoint(VerificationNotTrusted)
			c.String(http.StatusOK, "BAD-SIGNATURE")
			return
		}
		defer certResp.Body.Close()
		thisRecord.CertBytes = &certRespBytes
		leafCert, intermediates = getLeafAndIntermediatesFromBytes(certRespBytes)
		cacheHeader = certResp.Header.Get("Cache-Control")
	}

	err = ourTrustAnchors.assertValidLeafCert(leafCert, intermediates, crlWorkChan)
	if err != nil {
		thisRecord.StatusNotTrusted = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationNotTrusted)
		c.String(http.StatusOK, "BAD-SIGNATURE")
		return
	}
	_, err = jws.Verify(leafCert.PublicKey)
	if err != nil {
		thisRecord.StatusInvalidSignature = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationInvalidSignature)
		c.String(http.StatusOK, "BAD-SIGNATURE")
		return
	}

	if !cachedEntryFound {
		// Cache response for future look-ups
		expireTime, forced := getCacheDirective(cacheHeader)
		newEntry := stivs.CertCacheEntry{
			Leaf:          leafCert,
			Intermediates: intermediates,
			Expires:       expireTime,
			Forced:        forced,
			CertBytes:     &certRespBytes,
		}
		stivs.GetCertCache().AddEntry(x5uUrl, newEntry)
		logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Added cache entry for: " + x5uUrl}
	}

	if jws.Signatures[0].Header.ExtraHeaders["ppt"] != "shaken" {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		c.String(http.StatusOK, "BAD-SIGNATURE")
		return
	}
	if jws.Signatures[0].Header.ExtraHeaders["typ"] != "passport" {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		c.String(http.StatusOK, "BAD-SIGNATURE")
		return
	}
	if jws.Signatures[0].Header.Algorithm != "ES256" {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		c.String(http.StatusOK, "BAD-SIGNATURE")
		return
	}

	idJwt := IdentityJwt{}
	err = json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &idJwt)
	if idJwt.Iat == nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		c.String(http.StatusOK, "BAD-SIGNATURE")
		return
	}
	if idJwt.Attest == nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		c.String(http.StatusOK, "BAD-SIGNATURE")
		return
	}
	if !stringInSlice(*idJwt.Attest, allowedAttestationLevels) {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		c.String(http.StatusOK, "BAD-SIGNATURE")
		return
	}
	if idJwt.IdOrig == nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		c.String(http.StatusOK, "BAD-SIGNATURE")
		return
	}
	if idJwt.IdDest == nil {
		thisRecord.StatusBadFormat = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationBadFormat)
		c.String(http.StatusOK, "BAD-SIGNATURE")
		return
	}
	if idJwt.IdOrig.Tn != from && idJwt.IdOrig.Tn != pai {
		thisRecord.StatusTnMismatch = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationTnMismatch)
		c.String(http.StatusOK, "MISMATCH-"+*idJwt.Attest)
		return
	}
	foundToMatch := false
	for _, destTn := range idJwt.IdDest.Tn {
		if destTn == to || destTn == ruri {
			foundToMatch = true
			break
		}
	}
	if !foundToMatch {
		thisRecord.StatusTnMismatch = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationTnMismatch)
		c.String(http.StatusOK, "MISMATCH-"+*idJwt.Attest)
		return
	}
	iatDiff := time.Now().Unix() - *idJwt.Iat
	if iatDiff > 60 || iatDiff < -60 {
		thisRecord.StatusStale = true
		go WriteVerificationRecord(&thisRecord)
		go VerificationData.AddDataPoint(VerificationStale)
		c.String(http.StatusOK, "BAD-SIGNATURE")
		return
	}

	thisRecord.StatusValid = true
	thisRecord.Attestation = idJwt.Attest
	go WriteVerificationRecord(&thisRecord)

	go collectValidVerification(*idJwt.Attest)

	// If we made it here, we have a valid signature over this call
	c.String(http.StatusOK, "VALID-"+*idJwt.Attest)
	return

}

type Dest struct {
	Tn []string `json:"tn"`
}
type Orig struct {
	Tn string `json:"tn"`
}
type EzRequest struct {
	Attest string `json:"attest"`
	Dest   `json:"dest"`
	Iat    int64 `json:"iat"`
	Orig   `json:"orig"`
	Origid string `json:"origid"`
}

type SigningAuth struct {
	sync.RWMutex
	ready       bool
	certRepoUrl *string
	eccSigner   jose.Signer
}

type VerificationRequest struct {
	From     *Orig   `json:"from"`
	To       *Dest   `json:"to"`
	Time     *int64  `json:"time"`
	Identity *string `json:"identity"`
}
type VerificationRequestPayload struct {
	VerificationRequest `json:"verificationRequest"`
}

type VerificationResponse struct {
	ReasonCode int    `json:"reasoncode,omitempty"`
	ReasonText string `json:"reasontext,omitempty"`
	ReasonDesc string `json:"reasondesc,omitempty"`
	Verstat    string `json:"verstat"`
}

type VerificationResponsePayload struct {
	VerificationResponse `json:"verificationResponse"`
}

func (ourSigner *SigningAuth) GetRepoUrl() string {
	ourSigner.Lock()
	defer ourSigner.Unlock()
	repoUrl := ""
	if ourSigner.certRepoUrl != nil {
		repoUrl = *ourSigner.certRepoUrl
	}
	return repoUrl
}

func (ourSigner *SigningAuth) SetReady(ready bool) {
	ourSigner.Lock()
	defer ourSigner.Unlock()
	ourSigner.ready = ready
}

func (ourSigner *SigningAuth) IsReady() bool {
	ourSigner.RLock()
	defer ourSigner.RUnlock()
	return ourSigner.ready
}

func (ourSigner *SigningAuth) Sign(payload []byte) (string, error) {
	ourSigner.RLock()
	defer ourSigner.RUnlock()
	signature, err := ourSigner.eccSigner.Sign(payload)
	if err != nil {
		return "", err
	}
	serializedJwt, err := signature.CompactSerialize()
	if err != nil {
		return "", err
	}
	trailer := ";info=<" + *ourSigner.certRepoUrl + ">;alg=ES256;ppt=shaken"
	serializedJwt += trailer
	return serializedJwt, nil
}

func (ourSigner *SigningAuth) Configure(keyPath string, certRepoUrl string) {
	eccKeyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-AS: Couldn't read private key - " + err.Error()}
		return
	}
	eccKey, err := decodeEccKey(eccKeyBytes)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-AS: Couldn't decode private key - " + err.Error()}
		return
	}
	// Attempt to fetch our cert from the repo URL
	shouldValidatePair := false
	var cert *x509.Certificate
	resp, err := httpClient.Get(certRepoUrl)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-AS: Error fetching cert from repo"}
	} else {
		defer resp.Body.Close()
		readBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-AS: Error reading cert response from repo"}
		} else {
			block, _ := pem.Decode(readBytes)
			if block != nil {
				cert, err = x509.ParseCertificate(block.Bytes)
				shouldValidatePair = true
			} else {
				logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-AS: Could not parse cert response from repo"}
			}
		}
	}
	ourSigner.Lock()
	defer ourSigner.Unlock()
	if shouldValidatePair {
		if !eccKey.PublicKey.Equal(cert.PublicKey) {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-AS: Private key does not pair with our cert"}
			ourSigner.ready = false
			return
		}
		if cert.NotAfter.Before(time.Now()) {
			logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "STI-AS: Our cert is expired"}
			ourSigner.ready = false
			return
		}
	}
	// So far so good. Let's build our goJose signer and replace the current one
	joseKey := jose.SigningKey{Algorithm: jose.ES256, Key: eccKey}
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("passport")
	signerOpts.WithHeader("alg", "ES256")
	signerOpts.WithHeader("ppt", "shaken")
	signerOpts.WithHeader("x5u", certRepoUrl)
	eccSigner, _ := jose.NewSigner(joseKey, &signerOpts)
	ourSigner.ready = true
	ourSigner.certRepoUrl = &certRepoUrl
	ourSigner.eccSigner = eccSigner
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "STI-AS: Signer Ready"}
}
func decodeEccKey(pemEncoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemEncoded)
	x509Encoded := block.Bytes
	return x509.ParseECPrivateKey(x509Encoded)
}
func cleanTn(tn string) string {
	regex, _ := regexp.Compile("[^0-9*#]+")
	return regex.ReplaceAllString(tn, "")
}

type Verstat string

const (
	TNValidationPassed Verstat = "TN-Validation-Passed"
	NoTNValidation     Verstat = "No-TN-Validation"
	TNValidationFailed Verstat = "TN-Validation-Failed"
)

func generateVerificationResponse(reasonDesc string, reasonCode int, reasonText string, status Verstat) VerificationResponsePayload {
	payload := VerificationResponsePayload{VerificationResponse{
		ReasonCode: reasonCode,
		ReasonText: reasonText,
		ReasonDesc: reasonDesc,
		Verstat:    string(status),
	}}
	return payload
}

type SigningResponseErrorENUM int

const (
	MissingJsonBody SigningResponseErrorENUM = iota
	MissingParam
	UnsupportedBodyTypeInAccept // Let's not
	NotFound
	UnsupportedContentType
	InvalidParamValue
	JsonParseError
	MissingContentLength
	InvalidHttpMethod // Kind of silly to listen for other methods we don't want. GET is disallowed (woo)
	InternalServerError
)

func (resp SigningResponseErrorENUM) toHttpResponseCode() int {
	return [...]int{400, 400, 406, 404, 415, 400, 400, 411, 405, 500}[resp]
}
func (resp SigningResponseErrorENUM) toExceptionCode() string {
	return [...]string{"SVC4000", "SVC40001", "SVC40002", "SVC4003", "SVC40004",
		"SVC40005", "SVC40006", "SVC40007", "POL4050", "POL5000"}[resp]
}
func (resp SigningResponseErrorENUM) toString() string {
	return [...]string{"Error: Missing JSON body in the request.", "Error: Missing mandatory parameter '%1'.",
		"Error: Requested response body type '%1' is not supported.", "Error: Requested resource was not found.",
		"Error: Unsupported request body type, expected '%1'.", "Error: Invalid '%1' parameter value: %2.",
		"Error: Failed to parse received message body: '%1'.", "Error: Missing mandatory Content-Length header.",
		"Error: Method Not Allowed: Invalid HTTP method used", "Error: Internal Server Issue"}[resp]
}
func generateServiceErrorResponse(response SigningResponseErrorENUM, vars []string) RequestErrorResponse {
	var thisError RequestErrorResponse
	thisError.RequestError.ServiceException.Text = response.toString()
	thisError.RequestError.ServiceException.MessageId = response.toExceptionCode()
	if vars == nil {
		vars = []string{}
	}
	thisError.RequestError.ServiceException.Variables = vars
	return thisError
}

var allowedAttestationLevels = []string{"A", "B", "C", "a", "b", "c"}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

type SigningResponse struct {
	SigningResponseBody struct {
		// The signed JWT
		Identity *string `json:"identity"`
	} `json:"signingResponse"`
}

type RequestErrorResponse struct {
	RequestError struct {
		ServiceException struct {
			MessageId string   `json:"messageId"`
			Text      string   `json:"text"`
			Variables []string `json:"variables"`
		} `json:"serviceException"`
	} `json:"requestError"`
}

type IdentityJwt struct {
	Attest *string `json:"attest"`
	IdOrig *Orig   `json:"orig"`
	IdDest *Dest   `json:"dest"`
	Iat    *int64  `json:"iat"`
	Origid *string `json:"origid"`
}

func getLeafAndIntermediatesFromBytes(PEMBytes []byte) (*x509.Certificate, []*x509.Certificate) {
	getLeaf := true
	intermediates := make([]*x509.Certificate, 0)
	var leaf = &x509.Certificate{}
	for {
		block, rest := pem.Decode(PEMBytes)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			// The first cert is supposed to be the leaf. Everything will fall apart if this is violated
			if getLeaf {
				leaf, _ = x509.ParseCertificate(block.Bytes)
				getLeaf = false
			}
			// All remaining certs become intermediates
			intermediate, _ := x509.ParseCertificate(block.Bytes)
			intermediates = append(intermediates, intermediate)
		}
		PEMBytes = rest
	}
	return leaf, intermediates
}

func IsUrl(str string) bool {
	thisUrl, err := url.ParseRequestURI(str)
	if err != nil {
		return false
	}
	address := net.ParseIP(thisUrl.Host)
	if address == nil {
		return strings.Contains(thisUrl.Host, ".")
	}
	return true
}

func getCacheDirective(header string) (*time.Time, bool) {
	// Allow for max of 30 days and min of 7 days
	const maxAgeSeconds = 86400 * 30
	const minAgeSeconds = 86400 * 7
	if header != "" {
		cacheControlParts := regexp.MustCompile(`,`).Split(header, -1)
		for _, part := range cacheControlParts {
			trimmed := strings.Trim(part, " ")
			if strings.HasPrefix(trimmed, "max-age") {
				ageParts := regexp.MustCompile("=").Split(trimmed, -1)
				if len(ageParts) > 1 {
					expires, err := strconv.Atoi(ageParts[1])
					if err != nil {
						expireTime := time.Now().Add(time.Second * minAgeSeconds)
						return &expireTime, true
					} else {
						if expires < minAgeSeconds {
							expires = minAgeSeconds
						} else if expires > maxAgeSeconds {
							expires = maxAgeSeconds
						}
						expireTime := time.Now().Add(time.Second * minAgeSeconds)
						return &expireTime, false
					}
				}
			} else if trimmed == "immutable" {
				expireTime := time.Now().Add(time.Second * maxAgeSeconds)
				return &expireTime, false
			}
		}
	}
	// We will cache for 7 days without any other directive, but we will note that it was forced
	expireTime := time.Now().Add(time.Second * minAgeSeconds)
	return &expireTime, true
}

type ServerStatus struct {
	Name                   string `json:"name"`
	Version                string `json:"version"`
	StartTime              string `json:"startTime"`
	Uptime                 string `json:"uptime"`
	SignerReady            bool   `json:"signerReady"`
	CertRepoUrl            string `json:"certRepoUrl"`
	CaTrustListLastFetched string `json:"caTrustListLastFetched"`
	CrlLastFetched         string `json:"crlLastFetched"`
}

func getServerStatus(c *gin.Context) {
	uptime := time.Now().Sub(startTime).Round(time.Second)

	var caRefresh = "never"
	if !lastCaRefresh.IsZero() {
		caRefresh = lastCaRefresh.Format(time.RFC3339)
	}
	var crlRefresh = "never"
	if !lastCrlRefresh.IsZero() {
		crlRefresh = lastCrlRefresh.Format(time.RFC3339)
	}

	status := &ServerStatus{
		Name:                   AppName,
		Version:                AppVersion,
		StartTime:              startTime.Format(time.RFC3339),
		Uptime:                 uptime.String(),
		SignerReady:            ourSigner.IsReady(),
		CertRepoUrl:            ourSigner.GetRepoUrl(),
		CaTrustListLastFetched: caRefresh,
		CrlLastFetched:         crlRefresh,
	}

	c.JSON(http.StatusOK, status)
}

type VerificationRecord struct {
	From                   *string
	Pai                    *string
	To                     *string
	Ruri                   *string
	Identity               *string
	X5U                    *string
	CertBytes              *[]byte
	StatusNoSignature      bool
	StatusBadFormat        bool
	StatusNotTrusted       bool
	StatusInvalidSignature bool
	StatusTnMismatch       bool
	StatusStale            bool
	StatusValid            bool
	Attestation            *string
	OrigOcn                *string
}
