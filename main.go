package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
		panic(err)
	}
}

func mainE() error {
	subject := pkix.Name{CommonName: "My CA"}
	expiration := time.Hour * 24 * 365 * 10 // 10 years
	pemFilename := "ca_certificate.pem"
	cerFilename := "ca_certificate.cer"

	password, err := readPasswordFromTerminal("Enter password: ")
	if err != nil {
		return fmt.Errorf("error reading password: %w", err)
	}

	confirmPassword, err := readPasswordFromTerminal("Confirm password: ")
	if err != nil {
		return fmt.Errorf("error reading password: %w", err)
	}

	if !bytes.Equal(password, confirmPassword) {
		return fmt.Errorf("passwords do not match")
	}

	err = createRootCA(subject, expiration, pemFilename, cerFilename, password)
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
