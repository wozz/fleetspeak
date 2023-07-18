package https

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// GetClientCert returns the client certificate from either the request header or TLS connection state.
func GetClientCert(req *http.Request, hn string) (*x509.Certificate, error) {
	if hn != "" {
		return getCertFromHeader(hn, req.Header)
	} else {
		return getCertFromTLS(req)
	}
}

const (
	key int = iota
	value
	quotedValue
)

type xfccParser struct {
	header string
}

func (x *xfccParser) Next() (string, string) {
	var keyStr, valueStr strings.Builder
	state := key
	var i int
L:
	for i = 0; i < len(x.header); i++ {
		switch state {
		case key:
			if string(x.header[i]) == "=" {
				state = value
			} else {
				keyStr.Write([]byte{x.header[i]})
			}
		case value:
			if string(x.header[i]) == `"` {
				state = quotedValue
				continue L
			} else if string(x.header[i]) == ";" {
				break L
			} else if string(x.header[i]) == "," {
				break L
			}
			valueStr.Write([]byte{x.header[i]})
		case quotedValue:
			if string(x.header[i]) == `"` {
				state = value
				continue L
			}
			if string(x.header[i]) == `\` {
				if len(x.header) == i+1 {
					return "", ""
				}
				i++
			}
			valueStr.Write([]byte{x.header[i]})
		}
	}
	if len(x.header) > i {
		x.header = x.header[i+1:]
	} else {
		x.header = ""
	}
	return keyStr.String(), valueStr.String()
}

// parses the X-Forwarded-Client-Cert header as defined by envoy
// see: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
// if multiple client certs are found, takes the first one
func extractField(fieldName, headerCert string) string {
	headerReader := &xfccParser{
		header: headerCert,
	}
	for {
		keyStr, valueStr := headerReader.Next()
		if keyStr == "" {
			return ""
		}
		if keyStr == fieldName {
			return valueStr
		}
	}
}

func getCertFromHeader(hn string, rh http.Header) (*x509.Certificate, error) {
	headerCert := rh.Get(hn)
	if headerCert == "" {
		return nil, errors.New("no certificate found in header")
	}
	// support for envoy encoded xfcc header:
	if certField := extractField("Cert", headerCert); certField != "" {
		headerCert = certField
	}
	// Most certificates are URL PEM encoded
	if decodedCert, err := url.PathUnescape(headerCert); err != nil {
		return nil, err
	} else {
		headerCert = decodedCert
	}
	block, rest := pem.Decode([]byte(headerCert))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}
	if len(rest) != 0 {
		return nil, errors.New("received more than 1 client cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	return cert, err
}

func getCertFromTLS(req *http.Request) (*x509.Certificate, error) {
	if req.TLS == nil {
		return nil, errors.New("TLS information not found")
	}
	if len(req.TLS.PeerCertificates) != 1 {
		return nil, fmt.Errorf("expected 1 client cert, received %v", len(req.TLS.PeerCertificates))
	}
	cert := req.TLS.PeerCertificates[0]
	return cert, nil
}
