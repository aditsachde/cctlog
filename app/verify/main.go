package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
)

const publicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAY2sshpdKM8cB+iXRGUGnGzmBeORrIBnzbIBVtQrgCYk=
-----END PUBLIC KEY-----`

// verifyAsymmetricSignatureEC will verify that an 'EC_SIGN_P256_SHA256' signature is
// valid for a given message.
func main() {

	message := []byte("2024-11-13T20:04:04-08:00")
	base64Signature := "72UMQ0yd7Fp7UCZ/KTkxfcVT8c4+L0B8mllFzqiPyy74OwZXiiVUERp2sp9sLCtjAJxxJX4LsCiN2FcH8d1GCQ=="

	signature, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		log.Fatalf("failed to parse public key: %v", err)
	}

	// Parse the public key. Note, this example assumes the public key is in the
	// ECDSA format.
	block, _ := pem.Decode([]byte(publicKey))
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse public key: %v", err)
	}
	ecKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		log.Fatalf("public key is not elliptic curve")
	}

	// Verify Elliptic Curve signature.
	if !ed25519.Verify(ecKey, message, signature) {
		log.Fatalf("failed to verify signature")
	}

	log.Println("Verified signature!")
}
