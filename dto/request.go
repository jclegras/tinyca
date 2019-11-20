package dto

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
)

type validator interface {
	validate() error
}

// Decode populates a validator from the given request
func Decode(r *http.Request, v validator) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return err
	}
	return v.validate()
}

// A Request for signing the hostnames and IPs
type Request struct {
	Hostnames []string `json:"dnsNames"`
	AddressIP []net.IP `json:"IPs"`
}

// A RequestCsr obtained from a CSR
type RequestCsr struct {
	Data []byte
}

func (r *RequestCsr) validate() error {
	return nil
}

func (r *Request) validate() error {
	const domainRegexFormat = "^[A-Za-z0-9.*-]+$"
	domainRegex := regexp.MustCompile(domainRegexFormat)

	for _, hostname := range r.Hostnames {
		if !domainRegex.MatchString(hostname) {
			return fmt.Errorf("bad format for hostname: [%s] (expected: '%s')", hostname, domainRegexFormat)
		}
	}

	return nil
}
