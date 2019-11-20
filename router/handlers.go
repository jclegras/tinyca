package router

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/jclegras/tinyca/cert"
	"github.com/jclegras/tinyca/dto"
)

// SignHandler is called for signing a given dto.Request
// Hostnames and/or IPs will be authentified by the root CA (cert.Issuer)
// The response to the client hold the couple key/crt
func SignHandler(w http.ResponseWriter, r *http.Request) {
	var req dto.Request
	err := dto.Decode(r, &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	issuer := cert.GetIssuer()

	crt, err := cert.LeafCertificate(issuer.CRT(), issuer.Key(), req.Hostnames, req.AddressIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s", crt)
}

// SignCsrHandler is called for signing a given dto.RequestCsr
// The CSR must be POSTed with the base64 format
// Hostnames and IPs from the base64-encoded CSR will be authentified by the root CA (cert.Issuer)
// The response to the client hold the generated certificate from the CSR
func SignCsrHandler(w http.ResponseWriter, r *http.Request) {
	buf := bytes.NewBuffer([]byte{})
	buf.ReadFrom(r.Body)

	csrRaw, err := base64.StdEncoding.DecodeString(buf.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	csrPEM, _ := pem.Decode(csrRaw)
	if csrPEM == nil || csrPEM.Type != "CERTIFICATE REQUEST" {
		http.Error(w, "failed to read the certificate request: unexpected content", http.StatusBadRequest)
		return
	}

	csr, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	issuer := cert.GetIssuer()

	crt, err := cert.LeafCertificateFromCSR(issuer.CRT(), issuer.Key(), csr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s", crt)
}
