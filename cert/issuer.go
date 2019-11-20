package cert

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/jclegras/tinyca/common"
)

var issuer *Issuer

// Issuer represents the CA root with its key and certificate
type Issuer struct {
	key crypto.Signer
	crt *x509.Certificate
}

// Key returns the CA key for signing
func (iss *Issuer) Key() crypto.Signer {
	return iss.key
}

// CRT return the certificate of the CA root
func (iss *Issuer) CRT() *x509.Certificate {
	return iss.crt
}

// GetIssuer returns the data for the CA root
func GetIssuer() *Issuer {
	if issuer != nil {
		return issuer
	}

	logger := common.GetLogger()
	logger.Println("check the CA key and certificate...")

	// CA store
	caRootStoreName, carootOverriden := os.LookupEnv("CAROOT")
	if !carootOverriden {
		homeDir, err := os.UserHomeDir()
		common.FatalIfErr(err, "failed to get the user home directory")
		caRootStoreName = fmt.Sprintf("%s/.local/share/tinyca", homeDir)
		if _, err = os.Stat(caRootStoreName); os.IsNotExist(err) {
			err = os.Mkdir(caRootStoreName, 0755)
			common.FatalIfErr(err, "failed to create the CA root directory")
		}
	}
	caRootStoreStat, caRootStoreErr := os.Stat(caRootStoreName)
	if caRootStoreErr != nil {
		common.FatalIfErr(caRootStoreErr, "failed to load the CA root store")
	}
	if !caRootStoreStat.IsDir() {
		common.FatalIfErr(errors.New("the root store must be a directory"), fmt.Sprintf("%s", caRootStoreName))
	}
	logger.Printf("CA store: %s\n", caRootStoreName)

	// CA key and crt creation
	caKeyName, caKeyNameOverriden := os.LookupEnv("KEYNAME")
	if !caKeyNameOverriden {
		caKeyName = "CAKey.pem"
	}
	caCrtName, caCrtNameOverriden := os.LookupEnv("CRTNAME")
	if !caCrtNameOverriden {
		caCrtName = "CACrt.pem"
	}
	cakeyPath := fmt.Sprintf("%s/%s", caRootStoreName, caKeyName)
	caCrtPath := fmt.Sprintf("%s/%s", caRootStoreName, caCrtName)
	_, errKey := os.Stat(cakeyPath)
	_, errCA := os.Stat(caCrtPath)
	if os.IsNotExist(errKey) || os.IsNotExist(errCA) {
		logger.Println("creating the CA key and the CA certificate...")
		caKey, err := generatePrivateKey(4096)
		common.FatalIfErr(err, "failed to generate the CA private key")
		caCrt, err := createRootCertificate(caKey)
		common.FatalIfErr(err, "failed to create the CA root")
		err = writePrivateKeyToFilename(cakeyPath, &caKey)
		common.FatalIfErr(err, "failed to write the CA private key")
		err = writeCertificateToFilename(caCrtPath, caCrt)
		common.FatalIfErr(err, "failed to write the CA root")
	}
	if errKey != nil && !os.IsNotExist(errKey) {
		common.FatalIfErr(errKey, "")
	}
	if errCA != nil && !os.IsNotExist(errCA) {
		common.FatalIfErr(errCA, "")
	}

	// Load the CA key and certificate
	caKey, err := readPrivateKeyFromFilename(cakeyPath)
	common.FatalIfErr(err, "failed to read the CA private key")
	caCrt, err := readCertificateFromFilename(caCrtPath)
	common.FatalIfErr(err, "failed to read the CA ROOT")
	issuer = &Issuer{
		key: caKey.(crypto.Signer),
		crt: caCrt,
	}

	logger.Println("the CA key and certificate are loaded properly!")
	logger.Printf("CA key: %s\n", cakeyPath)
	logger.Printf("CA crt: %s\n", caCrtPath)
	return issuer
}
