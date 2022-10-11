package dilithiumhighsign_test

import (
	"circl/sign/dilithiumhighsign"
	"encoding/binary"
	"testing"
)

func BenchmarkVerify(b *testing.B) {
	// Note that Dilithium precomputes quite a bit during Unpacking/Keygen
	// instead of at the moment of verification (as compared to the reference
	// implementation.  A fair comparison thus should sum verification
	// times with unpacking times.)
	var seed [32]byte
	var msg [8]byte
	var sig [dilithiumhighsign.SignatureSize]byte
	pk, sk := dilithiumhighsign.NewKeyFromSeed(&seed)
	dilithiumhighsign.SignTo(sk, msg[:], sig[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// We should generate a new signature for every verify attempt,
		// as this influences the time a little bit.  This difference, however,
		// is small and generating a new signature in between creates a lot
		// pressure on the allocator which makes an accurate measurement hard.
		dilithiumhighsign.Verify(pk, msg[:], sig[:])
	}
}

func BenchmarkSign(b *testing.B) {
	// Note that Dilithium precomputes quite a bit during Unpacking/Keygen
	// instead of at the moment of signing (as compared to the reference
	// implementation.  A fair comparison thus should sum sign times with
	// unpacking times.)
	var seed [32]byte
	var msg [8]byte
	var sig [dilithiumhighsign.SignatureSize]byte
	_, sk := dilithiumhighsign.NewKeyFromSeed(&seed)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(msg[:], uint64(i))
		dilithiumhighsign.SignTo(sk, msg[:], sig[:])
	}
}

func BenchmarkGenerateKey(b *testing.B) {
	var seed [32]byte
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		dilithiumhighsign.NewKeyFromSeed(&seed)
	}
}

func BenchmarkPublicFromPrivate(b *testing.B) {
	var seed [32]byte
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		_, sk := dilithiumhighsign.NewKeyFromSeed(&seed)
		b.StartTimer()
		sk.Public()
	}
}

func TestSignThenVerifyAndPkSkPacking(t *testing.T) {
	var seed [dilithiumhighsign.SeedSize]byte
	var sig [dilithiumhighsign.SignatureSize]byte
	var msg [8]byte
	var pkb1, pkb2 [dilithiumhighsign.PublicKeySize]byte
	var skb1, skb2 [dilithiumhighsign.PrivateKeySize]byte
	var pk2 dilithiumhighsign.PublicKey
	var sk2 dilithiumhighsign.PrivateKey
	for i := uint64(0); i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], i)
		pk, sk := dilithiumhighsign.NewKeyFromSeed(&seed)
		for j := uint64(0); j < 10; j++ {
			binary.LittleEndian.PutUint64(msg[:], j)
			dilithiumhighsign.SignTo(sk, msg[:], sig[:])
			if !dilithiumhighsign.Verify(pk, msg[:], sig[:]) {
				t.Fatal()
			}
		}
		pk.Pack(&pkb1)
		pk2.Unpack(&pkb1)
		pk2.Pack(&pkb2)
		if pkb1 != pkb2 {
			t.Fatal()
		}
		sk.Pack(&skb1)
		sk2.Unpack(&skb1)
		sk2.Pack(&skb2)
		if skb1 != skb2 {
			t.Fatal()
		}
	}
}

func TestPublicFromPrivate(t *testing.T) {
	var seed [dilithiumhighsign.SeedSize]byte
	for i := uint64(0); i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], i)
		pk, sk := dilithiumhighsign.NewKeyFromSeed(&seed)
		pk2 := sk.Public().(*dilithiumhighsign.PublicKey)
		var pkb1, pkb2 [dilithiumhighsign.PublicKeySize]byte
		pk.Pack(&pkb1)
		pk2.Pack(&pkb2)
		if pkb1 != pkb2 {
			t.Fatal()
		}
	}
}
