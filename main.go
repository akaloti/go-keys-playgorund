package main

import (
	"crypto/rsa"
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
		fmt.Fprintf(os.Stderr, "Failed to convert public key objecdt back to bytes: %s\n", err)
		os.Exit(1)
	}
	base64Encoding = base64.StdEncoding.EncodeToString(pemBlockBytes)
	fmt.Println(base64Encoding)
}

func main() {
	printPubKey("keys/rsa_prac.pub")
}