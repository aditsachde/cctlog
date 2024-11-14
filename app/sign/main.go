package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func main() {
	for {
		// Step 1: Get the current timestamp as a string
		currentTimestamp := time.Now().Format(time.RFC3339)

		// Step 2: Call signAsymmetric function
		var signatureBuffer bytes.Buffer
		err := signAsymmetric(&signatureBuffer, currentTimestamp)
		if err != nil {
			log.Fatalf("Error signing message: %v", err)
		}

		// Step 3: Print a JSON object with `data` and `signature` fields
		result := map[string]string{
			"data":      currentTimestamp,
			"signature": signatureBuffer.String(),
		}

		jsonOutput, err := json.Marshal(result)
		if err != nil {
			log.Fatalf("Error marshaling JSON: %v", err)
		}

		fmt.Println(string(jsonOutput))

		// Wait for 15 seconds before repeating
		time.Sleep(15 * time.Second)
	}
}

// signAsymmetric will sign a plaintext message using a saved asymmetric private
// key stored in Cloud KMS.
func signAsymmetric(w io.Writer, message string) error {
	name := "projects/cctlog-demo-project/locations/us/keyRings/demo-cctlog-keyring/cryptoKeys/demo-cctlog-key/cryptoKeyVersions/1"

	// Create the client.
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create kms client: %w", err)
	}
	defer client.Close()

	// Convert the message into bytes. Cryptographic plaintexts and
	// ciphertexts are always byte arrays.
	plaintext := []byte(message)

	// Optional but recommended: Compute digest's CRC32C.
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)

	}
	dataCRC32C := crc32c(plaintext)

	// Build the signing request.
	//
	// Note: Key algorithms will require a varying hash function. For example,
	// EC_SIGN_P384_SHA384 requires SHA-384.
	req := &kmspb.AsymmetricSignRequest{
		Name:       name,
		Data:       plaintext,
		DataCrc32C: wrapperspb.Int64(int64(dataCRC32C)),
	}

	// Call the API.
	result, err := client.AsymmetricSign(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to sign digest: %w", err)
	}

	// Optional, but recommended: perform integrity verification on result.
	// For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if result.VerifiedDataCrc32C == false {
		return fmt.Errorf("AsymmetricSign: request corrupted in-transit 1")
	}
	if result.Name != req.Name {
		return fmt.Errorf("AsymmetricSign: request corrupted in-transit 2")
	}
	if int64(crc32c(result.Signature)) != result.SignatureCrc32C.Value {
		return fmt.Errorf("AsymmetricSign: response corrupted in-transit 3")
	}

	fmt.Fprint(w, base64.StdEncoding.EncodeToString(result.Signature))
	return nil
}
