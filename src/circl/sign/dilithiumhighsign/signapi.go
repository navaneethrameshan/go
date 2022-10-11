package dilithiumhighsign

import (
	"crypto/rand"
	"encoding/asn1"

	"circl/sign"
)

var sch sign.Scheme = &scheme{}

// Scheme returns a signature interface.
func Scheme() sign.Scheme { return sch }

//Following OID and codepoint specs from here - https://github.com/open-quantum-safe/openssl/blob/78b591d8b247d9d863bbfa98ebc8ae7d90992803/oqs-template/generate.yml#L369-L370
//OID - 1.3.6.1.4.1.2.267.6.6.5
//NOTE- HPCS uses a different OID 1.3.6.1.4.1.2.267.1.6.5
//Codepoint - 0xfe09

type scheme struct{}

func (*scheme) Name() string          { return "Dilithium4" }
func (*scheme) PublicKeySize() int    { return PublicKeySize }
func (*scheme) PrivateKeySize() int   { return PrivateKeySize }
func (*scheme) SignatureSize() int    { return SignatureSize }
func (*scheme) SeedSize() int         { return SeedSize }
func (*scheme) TLSIdentifier() uint   { return 0xfe09 /* temp */ }
func (*scheme) SupportsContext() bool { return false }
func (*scheme) Oid() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 6, 6, 5}
}

func (*scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	return GenerateKey(rand.Reader)
}

func (*scheme) Sign(
	sk sign.PrivateKey,
	message []byte,
	opts *sign.SignatureOpts,
) []byte {
	priv, ok := sk.(*PrivateKey)
	if !ok {
		panic(sign.ErrTypeMismatch)
	}
	if opts != nil && opts.Context != "" {
		panic(sign.ErrContextNotSupported)
	}
	var sig [SignatureSize]byte
	SignTo(priv, message, sig[:])
	return sig[:]
}

func (*scheme) Verify(
	pk sign.PublicKey,
	message, signature []byte,
	opts *sign.SignatureOpts,
) bool {
	pub, ok := pk.(*PublicKey)
	if !ok {
		panic(sign.ErrTypeMismatch)
	}
	if opts != nil && opts.Context != "" {
		panic(sign.ErrContextNotSupported)
	}
	return Verify(pub, message, signature)
}

func (*scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	if len(seed) != SeedSize {
		panic(sign.ErrSeedSize)
	}
	var tmp [SeedSize]byte
	copy(tmp[:], seed)
	return NewKeyFromSeed(&tmp)
}

func (*scheme) UnmarshalBinaryPublicKey(buf []byte) (sign.PublicKey, error) {
	if len(buf) != PublicKeySize {
		return nil, sign.ErrPubKeySize
	}
	var tmp [PublicKeySize]byte
	copy(tmp[:], buf)
	var ret PublicKey
	ret.Unpack(&tmp)
	return &ret, nil
}

func (*scheme) UnmarshalBinaryPrivateKey(buf []byte) (sign.PrivateKey, error) {
	if len(buf) != PrivateKeySize {
		return nil, sign.ErrPrivKeySize
	}
	var tmp [PrivateKeySize]byte
	copy(tmp[:], buf)
	var ret PrivateKey
	ret.Unpack(&tmp)
	return &ret, nil
}
