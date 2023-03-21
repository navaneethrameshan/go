//package implements the signature scheme for Dilithium mode5
package dilithiumhighsign

import (
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"crypto"
	cryptoRand "crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/sign"
)

const (
	// SeedSize is the length of the seed for NewKeyFromSeed
	SeedSize = mode5.SeedSize

	// PublicKeySize is the length in bytes of the packed public key.
	PublicKeySize = mode5.PublicKeySize

	// PrivateKeySize is the length in bytes of the packed public key.
	PrivateKeySize = mode5.PrivateKeySize

	// SignatureSize is the length in bytes of the signatures.
	SignatureSize = mode5.SignatureSize
)

// PublicKey is the type of Dilithium mode 5 public key.
type PublicKey struct {
	d mode5.PublicKey
}

// PrivateKey is the type of Dilithium mode 5 private key.
type PrivateKey struct {
	d mode5.PrivateKey
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	var seed [SeedSize]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, nil, err
	}

	pk, sk := NewKeyFromSeed(&seed)
	return pk, sk, nil
}

// NewKeyFromSeed derives a public/private key pair using the given seed.
func NewKeyFromSeed(seed *[SeedSize]byte) (*PublicKey, *PrivateKey) {
	var seed1 [32]byte

	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	_, _ = h.Read(seed1[:])
	dpk, dsk := mode5.NewKeyFromSeed(&seed1)

	return &PublicKey{*dpk}, &PrivateKey{*dsk}
}

// SignTo signs the given message and writes the signature into signature.
// It will panic if signature is not of length at least SignatureSize.
func SignTo(sk *PrivateKey, msg []byte, signature []byte) {
	mode5.SignTo(
		&sk.d,
		msg,
		signature[:mode5.SignatureSize],
	)
}

// Verify checks whether the given signature by pk on msg is valid.
func Verify(pk *PublicKey, msg []byte, signature []byte) bool {
	if !mode5.Verify(
		&pk.d,
		msg,
		signature[:mode5.SignatureSize],
	) {
		return false
	}

	return true
}

// Unpack unpacks pk to the public key encoded in buf.
func (pk *PublicKey) Unpack(buf *[PublicKeySize]byte) {
	var tmp [mode5.PublicKeySize]byte
	copy(tmp[:], buf[:mode5.PublicKeySize])
	pk.d.Unpack(&tmp)
}

// Unpack sets sk to the private key encoded in buf.
func (sk *PrivateKey) Unpack(buf *[PrivateKeySize]byte) {
	var tmp [mode5.PrivateKeySize]byte
	copy(tmp[:], buf[:mode5.PrivateKeySize])
	sk.d.Unpack(&tmp)
}

// Pack packs the public key into buf.
func (pk *PublicKey) Pack(buf *[PublicKeySize]byte) {
	var tmp [mode5.PublicKeySize]byte
	pk.d.Pack(&tmp)
	copy(buf[:mode5.PublicKeySize], tmp[:])
}

// Pack packs the private key into buf.
func (sk *PrivateKey) Pack(buf *[PrivateKeySize]byte) {
	var tmp [mode5.PrivateKeySize]byte
	sk.d.Pack(&tmp)
	copy(buf[:mode5.PrivateKeySize], tmp[:])
}

// Bytes packs the public key.
func (pk *PublicKey) Bytes() []byte {
	return pk.d.Bytes()
}

// Bytes packs the private key.
func (sk *PrivateKey) Bytes() []byte {
	return sk.d.Bytes()
}

// MarshalBinary packs the public key.
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	return pk.Bytes(), nil
}

// MarshalBinary packs the private key.
func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	return sk.Bytes(), nil
}

// UnmarshalBinary the public key from data.
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return errors.New("packed public key must be of mode5.PublicKeySize bytes")
	}
	var buf [PublicKeySize]byte
	copy(buf[:], data)
	pk.Unpack(&buf)
	return nil
}

// UnmarshalBinary unpacks the private key from data.
func (sk *PrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != PrivateKeySize {
		return errors.New("packed private key must be of mode5.PrivateKeySize bytes")
	}
	var buf [PrivateKeySize]byte
	copy(buf[:], data)
	sk.Unpack(&buf)
	return nil
}

func (sk *PrivateKey) Scheme() sign.Scheme { return sch }
func (pk *PublicKey) Scheme() sign.Scheme  { return sch }

func (sk *PrivateKey) Equal(other crypto.PrivateKey) bool {
	castOther, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return castOther.d.Equal(&sk.d)
}

func (pk *PublicKey) Equal(other crypto.PublicKey) bool {
	castOther, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return castOther.d.Equal(&pk.d)
}

// Sign signs the given message.
//
// opts.HashFunc() must return zero, which can be achieved by passing
// crypto.Hash(0) for opts.  rand is ignored.  Will only return an error
// if opts.HashFunc() is non-zero.
//
// This function is used to make PrivateKey implement the crypto.Signer
// interface.  The package-level SignTo function might be more convenient
// to use.
func (sk *PrivateKey) Sign(
	rand io.Reader, msg []byte, opts crypto.SignerOpts,
) (signature []byte, err error) {
	var sig [SignatureSize]byte

	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("dilithium5: cannot sign hashed message")
	}

	SignTo(sk, msg, sig[:])
	return sig[:], nil
}

// Public computes the public key corresponding to this private key.
//
// Returns a *PublicKey.  The type crypto.PublicKey is used to make
// PrivateKey implement the crypto.Signer interface.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return &PublicKey{
		*sk.d.Public().(*mode5.PublicKey),
	}
}
