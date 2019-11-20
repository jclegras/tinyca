package cert

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"time"

	"github.com/jclegras/tinyca/common"
)

// LeafCert is a PEM encoded X509 certificate with its private key
type LeafCert struct {
	Key, CRT *pem.Block
}

func (crt *LeafCert) String() string {
	out := bytes.NewBufferString("")

	if crt.CRT != nil {
		pem.Encode(out, crt.CRT)	
	}
	if crt.Key != nil {
		pem.Encode(out, crt.Key)
	}

	return out.String()
}

// LeafCertificateFromCSR returns a leaf certificate from the given CSR.
// The issuer is the CA ROOT given in parameter.
// The leaf certificate is signed by the CA key.
// The subject is given by the CSR.
func LeafCertificateFromCSR(caRoot *x509.Certificate,
	caKey crypto.PrivateKey, csr *x509.CertificateRequest) (*LeafCert, error) {
	err := csr.CheckSignature()
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:    randomSerialNumber(),
		Subject:         csr.Subject,
		ExtraExtensions: csr.Extensions, // includes requested SANs

		NotAfter:  time.Now().AddDate(10, 0, 0),
		NotBefore: time.Now(),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: false,

		// If the CSR does not request a SAN extension, fix it up for them as
		// the Common Name field does not work in modern browsers. Otherwise,
		// this will get overridden.
		DNSNames: []string{csr.Subject.CommonName},
	}
	cert, err := x509.CreateCertificate(rand.Reader, tpl, caRoot, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}

	return &LeafCert{
		CRT: certPEM,
	}, nil
}

// LeafCertificate returns a leaf certificate for the given hostnames and IP addresses.
// The issuer is the CA ROOT given in parameter.
// The leaf certificate is signed by the CA key.
// The subject is set arbitrarily.
func LeafCertificate(caRoot *x509.Certificate,
	caKey crypto.PrivateKey, hostnames []string, addressIP []net.IP) (*LeafCert, error) {
	leafKey, err := generatePrivateKey(4096)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization: []string{"Tiny CA development certificate"},
		},

		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		DNSNames:    hostnames,
		IPAddresses: addressIP,

		BasicConstraintsValid: true,
		IsCA:        false,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	cert, err := x509.CreateCertificate(rand.Reader, tpl, caRoot,
		leafKey.(crypto.Signer).Public(), caKey)
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	keyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	}

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}

	return &LeafCert{
		Key: keyPEM,
		CRT: certPEM,
	}, nil
}

func generatePrivateKey(bits int) (crypto.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func writePrivateKeyToFilename(path string, key *crypto.PrivateKey) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(*key)
	if err != nil {
		return err
	}
	keyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	}
	return ioutil.WriteFile(path, pem.EncodeToMemory(keyPEM), 0644)
}

func readPrivateKeyFromFilename(path string) (crypto.PrivateKey, error) {
	keyRaw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keyPEM, _ := pem.Decode(keyRaw)
	return x509.ParsePKCS8PrivateKey(keyPEM.Bytes)
}

func readCertificateFromFilename(path string) (*x509.Certificate, error) {
	certRaw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certPEM, _ := pem.Decode(certRaw)
	if certPEM == nil || certPEM.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ERROR: failed to read the CA certificate: unexpected content")
	}
	return x509.ParseCertificate(certPEM.Bytes)
}

func readCertificateRequestFromFilename(path string) (*x509.CertificateRequest, error) {
	csrRaw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	csrPEM, _ := pem.Decode(csrRaw)
	if csrPEM == nil || csrPEM.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("ERROR: failed to read the certificate request: unexpected content")
	}
	return x509.ParseCertificateRequest(csrPEM.Bytes)
}

func writeCertificateToFilename(path string, cert []byte) error {
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	return ioutil.WriteFile(path, pem.EncodeToMemory(certPEM), 0644)
}

func createRootCertificate(privateKey crypto.PrivateKey) ([]byte, error) {
	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			CommonName: "Tiny CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		BasicConstraintsValid: true,
		IsCA:           true,
		MaxPathLenZero: true,
		KeyUsage:       x509.KeyUsageCertSign,
	}
	return x509.CreateCertificate(rand.Reader, tpl, tpl, privateKey.(crypto.Signer).Public(), privateKey)
}

func createLeafCertificateFromCertificateRequest(path string, csr *x509.CertificateRequest,
	caRoot *x509.Certificate, caKey, privateKey crypto.PrivateKey) error {
	err := csr.CheckSignature()
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber:    randomSerialNumber(),
		Subject:         csr.Subject,
		ExtraExtensions: csr.Extensions, // includes requested SANs

		NotAfter:  time.Now().AddDate(10, 0, 0),
		NotBefore: time.Now(),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: false,

		// If the CSR does not request a SAN extension, fix it up for them as
		// the Common Name field does not work in modern browsers. Otherwise,
		// this will get overridden.
		DNSNames: []string{csr.Subject.CommonName},
	}
	cert, err := x509.CreateCertificate(rand.Reader, tpl, caRoot, csr.PublicKey, caKey)
	if err != nil {
		return err
	}
	return writeCertificateToFilename(path, cert)
}

func createLeafCertificate(path string, caRoot *x509.Certificate,
	caKey, privateKey crypto.PrivateKey, dnsNames []string) error {
	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization: []string{"Tiny CA development certificate"},
		},

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		DNSNames:  dnsNames,

		BasicConstraintsValid: true,
		IsCA:        false,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	cert, err := x509.CreateCertificate(rand.Reader, tpl, caRoot,
		privateKey.(crypto.Signer).Public(), caKey)
	if err != nil {
		return err
	}
	return writeCertificateToFilename(path, cert)
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	common.FatalIfErr(err, "failed to generate serial number")
	return serialNumber
}
