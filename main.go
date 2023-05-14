package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"golang.org/x/term"
)

func main() {
	err := mainE()
	if err != nil {
		fmt.Printf("ERROR: %s\n", err)
		os.Exit(1)
	}
}

func mainE() error {
	var (
		commonName         string
		organizationalUnit string
		organization       string
		locality           string
		state              string
		country            string
		durationYears      int
	)

	flag.StringVar(&commonName, "cn", "", "Common Name")
	flag.StringVar(&organizationalUnit, "ou", "", "Organizational Unit")
	flag.StringVar(&organization, "o", "", "Organization")
	flag.StringVar(&locality, "l", "", "Locality")
	flag.StringVar(&state, "s", "", "State or Province")
	flag.StringVar(&country, "c", "", "Country Name")
	flag.IntVar(&durationYears, "duration", 10, "Duration in years")

	flag.Parse()

	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if commonName == "" {
		return fmt.Errorf("must provide a common name")
	}

	name := pkix.Name{
		CommonName: commonName,
	}

	if organizationalUnit != "" {
		name.OrganizationalUnit = []string{organizationalUnit}
	}

	if organization != "" {
		name.Organization = []string{organization}
	}

	if locality != "" {
		name.Locality = []string{locality}
	}

	if state != "" {
		name.Province = []string{state}
	}

	if country != "" {
		name.Country = []string{country}
	}

	password, err := readPasswordFromTerminal("Enter password: ")
	if err != nil {
		return fmt.Errorf("error reading password: %w", err)
	}
	confirmPassword, err := readPasswordFromTerminal("Confirm password: ")
	if err != nil {
		return fmt.Errorf("error reading password: %w", err)
	}
	if string(password) != string(confirmPassword) {
		return fmt.Errorf("passwords did not match")
	}

	cerPath := commonName + ".cer"
	pemPath := commonName + ".pem"

	err = createRootCA(name, time.Duration(durationYears)*365*24*time.Hour, pemPath, cerPath, password)
	if err != nil {
		return fmt.Errorf("error creating root CA: %w", err)
	}

	fmt.Println("Root CA created successfully.")
	return nil
}

func readPasswordFromTerminal(msg string) ([]byte, error) {
	fmt.Print(msg)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println()
	return password, nil
}

func createRootCA(subject pkix.Name, expiration time.Duration, pemFilename, cerFilename string, password []byte) error {
	// Generate a private key for the CA
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create a self-signed certificate for the CA
	caCertTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(expiration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageContentCommitment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Create a PEM file containing the password-protected private key and public key
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	}

	encryptedPEMBlock, err := x509.EncryptPEMBlock(rand.Reader, privateKeyPEM.Type, privateKeyPEM.Bytes, password, x509.PEMCipherAES256)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	pemData := pem.EncodeToMemory(encryptedPEMBlock)

	err = ioutil.WriteFile(pemFilename, pemData, 0600)
	if err != nil {
		return fmt.Errorf("failed to save PEM file: %w", err)
	}

	fmt.Printf("Wrote public/private key pair to %q\n", pemFilename)

	// Write the public key to a .cer file
	caCertPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	}

	caCertData := pem.EncodeToMemory(caCertPEM)

	err = ioutil.WriteFile(cerFilename, caCertData, 0644)
	if err != nil {
		return fmt.Errorf("failed to save .cer file: %w", err)
	}

	fmt.Printf("Wrote public key to %q\n", cerFilename)

	return nil
}

// issueSSLCertificate generates a new SSL certificate signed by the root CA.
/*func issueSSLCertificate(rootCACertFile, rootCAKeyFile, sslCertFile, sslKeyFile string, certificateValid time.Duration) error {
	rootCertPEM, err := ioutil.ReadFile(rootCACertFile)
	if err != nil {
		return fmt.Errorf("failed to read root CA certificate file: %w", err)
	}

	rootKeyPEM, err := ioutil.ReadFile(rootCAKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read root CA private key file: %w", err)
	}

	// Prompt for the password to decrypt the root CA private key
	password := getPassword()

	// Decrypt the root CA private key
	block, _ := pem.Decode(rootKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("failed to decode root CA private key")
	}

	decryptedKeyBytes, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		return fmt.Errorf("failed to decrypt root CA private key: %w", err)
	}

	rootKey, err := x509.ParsePKCS1PrivateKey(decryptedKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse root CA private key: %w", err)
	}

	// Generate a new RSA key pair for the SSL certificate
	sslKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate SSL key: %w", err)
	}

	// Create a certificate signing request (CSR) for the SSL certificate
	sslCSR := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	sslCSRBytes, err := x509.CreateCertificateRequest(rand.Reader, sslCSR, sslKey)
	if err != nil {
		return fmt.Errorf("failed to create SSL certificate signing request: %w", err)
	}

	// Sign the SSL certificate using the root CA
	sslCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certificateValid),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"example.com"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	sslCertBytes, err := x509.CreateCertificate(rand.Reader, sslCertTemplate, rootCertPEM, &sslKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("failed to create SSL certificate: %w", err)
	}

	// Save the SSL certificate and private key
	sslCertFileOutput, err := os.Create(sslCertFile)
	if err != nil {
		return fmt.Errorf("failed to create SSL certificate file: %w", err)
	}
	pem.Encode(sslCertFileOutput, &pem.Block{Type: "CERTIFICATE", Bytes: sslCertBytes})
	sslCertFileOutput.Close()

	sslKeyFileOutput, err := os.Create(sslKeyFile)
	if err != nil {
		return fmt.Errorf("failed to create SSL private key file: %w", err)
	}
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(sslKey),
	}
	encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, privBlock.Type, privBlock.Bytes, []byte(password), x509.PEMCipherAES256)
	if err != nil || pem.Encode(rootKeyFile, encryptedBlock) != nil {
		return fmt.Errorf("failed to encrypt root CA private key: %w", err)
	}

	if err := pem.Encode(sslKeyFileOutput, encryptedBlock); err != nil {
		return fmt.Errorf("failed to write SSL private key file: %w", err)
	}
	sslKeyFileOutput.Close()

	fmt.Println("SSL certificate and key files created.")
	return nil
}*/
