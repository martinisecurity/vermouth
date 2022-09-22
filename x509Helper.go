package vermouth

// This file (slightly adapted) comes from https://github.com/tsaarni/x500dn/blob/master/dn.go

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	enchex "encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"strings"
)

var oids = map[string]asn1.ObjectIdentifier{
	"authorityInformationAccess": {1, 3, 6, 1, 5, 5, 7, 1, 1},
	"businesscategory":           {2, 5, 4, 15},
	"c":                          {2, 5, 4, 6},
	"caIssuers":                  {1, 3, 6, 1, 5, 5, 7, 48, 2},
	"cn":                         {2, 5, 4, 3},
	"crlDistributionPoints":      {2, 5, 29, 31},
	"dc":                         {0, 9, 2342, 19200300, 100, 1, 25},
	"description":                {2, 5, 4, 13},
	"destinationindicator":       {2, 5, 4, 27},
	"distinguishedName":          {2, 5, 4, 49},
	"dnqualifier":                {2, 5, 4, 46},
	"enhancedsearchguide":        {2, 5, 4, 47},
	"facsimiletelephonenumber":   {2, 5, 4, 23},
	"generationqualifier":        {2, 5, 4, 44},
	"givenname":                  {2, 5, 4, 42},
	"houseidentifier":            {2, 5, 4, 51},
	"initials":                   {2, 5, 4, 43},
	"internationalisdnnumber":    {2, 5, 4, 25},
	"l":                          {2, 5, 4, 7},
	"member":                     {2, 5, 4, 31},
	"name":                       {2, 5, 4, 41},
	"o":                          {2, 5, 4, 10},
	"oscp":                       {1, 3, 6, 1, 5, 5, 7, 48, 1},
	"ou":                         {2, 5, 4, 11},
	"owner":                      {2, 5, 4, 32},
	"physicaldeliveryofficename": {2, 5, 4, 19},
	"postaladdress":              {2, 5, 4, 16},
	"postalcode":                 {2, 5, 4, 17},
	"postOfficebox":              {2, 5, 4, 18},
	"preferreddeliverymethod":    {2, 5, 4, 28},
	"registeredaddress":          {2, 5, 4, 26},
	"roleoccupant":               {2, 5, 4, 33},
	"searchguide":                {2, 5, 4, 14},
	"seealso":                    {2, 5, 4, 34},
	"serialnumber":               {2, 5, 4, 5},
	"sn":                         {2, 5, 4, 4},
	"st":                         {2, 5, 4, 8},
	"street":                     {2, 5, 4, 9},
	"telephonenumber":            {2, 5, 4, 20},
	"teletexterminalidentifier":  {2, 5, 4, 22},
	"telexnumber":                {2, 5, 4, 21},
	"title":                      {2, 5, 4, 12},
	"uid":                        {0, 9, 2342, 19200300, 100, 1, 1},
	"uniquemember":               {2, 5, 4, 50},
	"userpassword":               {2, 5, 4, 35},
	"x121address":                {2, 5, 4, 24},
}

// ParseDN returns a distinguishedName or an error.
// The function respects https://tools.ietf.org/html/rfc4514
func ParseDN(str string) (*pkix.RDNSequence, error) {
	dn := make(pkix.RelativeDistinguishedNameSET, 0)
	buffer := bytes.Buffer{}
	rdn := new(pkix.AttributeTypeAndValue)
	escaping := false

	unescapedTrailingSpaces := 0
	stringFromBuffer := func() string {
		s := buffer.String()
		s = s[0 : len(s)-unescapedTrailingSpaces]
		buffer.Reset()
		unescapedTrailingSpaces = 0
		return s
	}

	for i := 0; i < len(str); i++ {
		char := str[i]
		switch {
		case escaping:
			unescapedTrailingSpaces = 0
			escaping = false
			switch char {
			case ' ', '"', '#', '+', ',', ';', '<', '=', '>', '\\':
				buffer.WriteByte(char)
				continue
			}
			// Not a special character, assume hex encoded octet
			if len(str) == i+1 {
				return nil, errors.New("got corrupted escaped character")
			}

			dst := []byte{0}
			n, err := enchex.Decode([]byte(dst), []byte(str[i:i+2]))
			if err != nil {
				return nil, fmt.Errorf("failed to decode escaped character: %s", err)
			} else if n != 1 {
				return nil, fmt.Errorf("expected 1 byte when un-escaping, got %d", n)
			}
			buffer.WriteByte(dst[0])
			i++
		case char == '\\':
			unescapedTrailingSpaces = 0
			escaping = true
		case char == '=':
			rdn.Type = oids[strings.ToLower(stringFromBuffer())]
		case char == ',' || char == '+':
			// We're done with this RDN or value, push it
			if len(rdn.Type) == 0 {
				return nil, errors.New("incomplete type, value pair")
			}
			rdn.Value = stringFromBuffer()
			dn = append(dn, *rdn)
			rdn = new(pkix.AttributeTypeAndValue)
			if char == ',' {
				dn = append(dn, *rdn)
				rdn = new(pkix.AttributeTypeAndValue)
			}
		case char == ' ' && buffer.Len() == 0:
			// ignore unescaped leading spaces
			continue
		default:
			if char == ' ' {
				// Track unescaped spaces in case they are trailing and we need to remove them
				unescapedTrailingSpaces++
			} else {
				// Reset if we see a non-space char
				unescapedTrailingSpaces = 0
			}
			buffer.WriteByte(char)
		}
	}
	if buffer.Len() > 0 {
		if len(rdn.Type) == 0 {
			return nil, errors.New("DN ended with incomplete type, value pair")
		}
		rdn.Value = stringFromBuffer()
		dn = append(dn, *rdn)
	}

	var sequence = pkix.RDNSequence{dn}
	var orderedSequence = pkix.RDNSequence{}
	for _, val := range sequence[0] {
		if val.Value != nil {
			orderedSequence = append(orderedSequence, []pkix.AttributeTypeAndValue{val})
		}
	}

	return &orderedSequence, nil
}

type CRLDistributionPoint struct {
	OID         asn1.ObjectIdentifier
	OctetString []byte
}

type DistributionPointContainer struct {
	DistributionPoint
}

type DistributionPointName struct {
	FullNameContainer `asn1:"tag:0,5"`
}

type FullNameContainer struct {
	Fullname string `asn1:"tag:6,5,omitempty"`
}

type CRLIssuerContainer struct {
	CRLIssuer pkix.RDNSequence `asn1:"tag:4,16,explicit,omitempty"`
}

type DistributionPoint struct {
	DistributionPointName `asn1:"tag:0,5"`
	CRLIssuerContainer    `asn1:"tag:2,5"`
}

func getAIAFromAsn1Extension(e pkix.Extension) (string, error) {
	val := cryptobyte.String(e.Value)
	if !val.ReadASN1(&val, cryptobyte_asn1.SEQUENCE) {
		return "", errors.New("x509: invalid authority info access")
	}
	for !val.Empty() {
		var aiaDER cryptobyte.String
		if !val.ReadASN1(&aiaDER, cryptobyte_asn1.SEQUENCE) {
			return "", errors.New("x509: invalid authority info access")
		}
		var method asn1.ObjectIdentifier
		if !aiaDER.ReadASN1ObjectIdentifier(&method) {
			return "", errors.New("x509: invalid authority info access")
		}
		if !aiaDER.PeekASN1Tag(cryptobyte_asn1.Tag(6).ContextSpecific()) {
			continue
		}
		if !aiaDER.ReadASN1(&aiaDER, cryptobyte_asn1.Tag(6).ContextSpecific()) {
			return "", errors.New("x509: invalid authority info access")
		}
		switch {
		case method.Equal(oids["caIssuers"]):
			return string(aiaDER), nil
		}
	}
	return "", errors.New("x509: no AIA URI found")
}
