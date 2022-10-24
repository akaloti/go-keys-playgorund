package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

// Opens public key file and prints out contents.
func printPubKey(path string) {
	var keyFileContents []byte
	keyFileContents, _ = ioutil.ReadFile(path)
	// fmt.Println("Key file contents")
	// fmt.Println(keyFileContents)

	// Extract PEM block.
	// Second return value is file data corresponding to remaining
	// PEM blocks (if any).
	var pemBlock *pem.Block
	pemBlock, _ = pem.Decode(keyFileContents)
	if pemBlock == nil {
		fmt.Fprintf(os.Stderr, "Failed to decode PEM block\n")
		os.Exit(1)
	}
	fmt.Printf("Key type: %s\n", pemBlock.Type)

	// Print PEM block in base 64. This produces ALMOST the same output
	// as doing `cat` on the key file.
	fmt.Println("In base64:")
	var base64Encoding string
	var pemBlockBytes []byte
	pemBlockBytes = pemBlock.Bytes
	base64Encoding = base64.StdEncoding.EncodeToString(pemBlockBytes)
	fmt.Println(base64Encoding)

	// Print PEM block in base 64 another way. This produces EXACTLY the same output
	// as doing `cat` on the key file.
	fmt.Println("In base64 (another way):")
	pem.Encode(os.Stdout, pemBlock)

	// Parse into object.
	var pubkey *rsa.PublicKey
	var err error
	var tmp any
	tmp, err = x509.ParsePKIXPublicKey(pemBlockBytes)
	pubkey = tmp.(*rsa.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse into public key object: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Public key object: %s\n", pubkey)

	// Convert public key object back to bytes.
	pemBlockBytes, err = x509.MarshalPKIXPublicKey(tmp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to convert public key object back to bytes: %s\n", err)
		os.Exit(1)
	}
	base64Encoding = base64.StdEncoding.EncodeToString(pemBlockBytes)
	fmt.Println(base64Encoding)
}

func trySignature() {
	var privkey *rsa.PrivateKey
	var err error
	privkey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate key: %s\n", err)
		os.Exit(1)
	}
	var pubkey *rsa.PublicKey
	var pubkeyTmp any
	pubkeyTmp = privkey.Public()
	pubkey = pubkeyTmp.(*rsa.PublicKey)
	var ciphertext, decrypted, sig, sig2, hashed, msg []byte
	var tmp [32]byte
	msg = []byte("Test message!")
	tmp = sha256.Sum256(msg)
	hashed = tmp[:]

	fmt.Println("=== PKCS1, encrypt with pub ===")
	ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, pubkey, msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encrypt: %s\n", err)
		os.Exit(1)
	}
	decrypted, err = rsa.DecryptPKCS1v15(rand.Reader, privkey, ciphertext)
	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Printf("msg == decrypted: %t\n", bytes.Equal(msg, decrypted))

	fmt.Println("=== PKCS1, encrypt (sign) with priv ===")
	sig, err = rsa.SignPKCS1v15(rand.Reader, privkey, crypto.SHA256, hashed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sign: %s\n", err)
		os.Exit(1)
	}
	// fmt.Printf("PKCS1 signature (deterministic): %s\n", sig)
	sig2, err = rsa.SignPKCS1v15(rand.Reader, privkey, crypto.SHA256, hashed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sign the second time: %s\n", err)
		os.Exit(1)
	}
	// fmt.Printf("PKCS1 signature, second time (deterministic): %s\n", sig)
	// Since PKCS1-v1_5 is deterministic, the signatures should be equal.
	fmt.Printf("sig == sig2: %t\n", bytes.Equal(sig, sig2))
	if !bytes.Equal(sig, sig2) {
		fmt.Fprintf(os.Stderr, "Didn't get same PKCS1 signature")
		os.Exit(1)
	}
	err = rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, hashed, sig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to verify signature: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully verified signature.\n")

	fmt.Println("=== PSS, encrypt (sign) with priv ===")
	// TODO: Play with opts, in case that's the issue.
	sig, err = rsa.SignPSS(rand.Reader, privkey, crypto.SHA256, hashed, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sign: %s\n", err)
		os.Exit(1)
	}
	sig2, err = rsa.SignPSS(rand.Reader, privkey, crypto.SHA256, hashed, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sign the second time: %s\n", err)
		os.Exit(1)
	}
	// Since PSS is randomized, these should not be equal.
	fmt.Printf("sig == sig2: %t\n", bytes.Equal(sig, sig2))
	if bytes.Equal(sig, sig2) {
		fmt.Fprintf(os.Stderr, "RSA signature was same")
		os.Exit(1)
	}
	err = rsa.VerifyPSS(pubkey, crypto.SHA256, hashed, sig, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to verify signature: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully verified signature.\n")
}

func main() {
	// printPubKey("keys/rsa_prac.pub")
	trySignature()
}
