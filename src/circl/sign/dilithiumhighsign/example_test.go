package dilithiumhighsign_test

import (
	"circl/sign/dilithiumhighsign"
	"fmt"
)

func Example() {
	// Generates a keypair.
	pk, sk, err := dilithiumhighsign.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	// (Alternatively one can derive a keypair from a seed,
	// see NewKeyFromSeed().)

	// Packs public and private key
	var packedSk [dilithiumhighsign.PrivateKeySize]byte
	var packedPk [dilithiumhighsign.PublicKeySize]byte
	sk.Pack(&packedSk)
	pk.Pack(&packedPk)

	// Load it again
	var sk2 dilithiumhighsign.PrivateKey
	var pk2 dilithiumhighsign.PublicKey
	sk2.Unpack(&packedSk)
	pk2.Unpack(&packedPk)

	// Creates a signature on our message with the generated private key.
	msg := []byte("Some message")
	var signature [dilithiumhighsign.SignatureSize]byte
	dilithiumhighsign.SignTo(&sk2, msg, signature[:])

	// Checks whether a signature is correct
	if !dilithiumhighsign.Verify(&pk2, msg, signature[:]) {
		panic("incorrect signature")
	}

	fmt.Printf("O.K.")

	// Output:
	// O.K.
}
