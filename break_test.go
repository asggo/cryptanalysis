package cryptanalysis

import (
	"bytes"
	"testing"
)

func TestBreakSingleByteXor(t *testing.T) {
	enc_key := byte(133)
	data := []byte("Testing single byte xor breakage.")
	cipher := []byte{209, 224, 246, 241, 236, 235, 226, 165, 246, 236, 235,
		226, 233, 224, 165, 231, 252, 241, 224, 165, 253, 234, 247, 165,
		231, 247, 224, 228, 238, 228, 226, 224, 171}

	_, dec_key, plain := BreakSingleByteXor(cipher, ChiAlphaSpace)

	if dec_key != enc_key {
		t.Error("Expected", enc_key, "got", dec_key)
	}

	if bytes.Compare(data, []byte(plain)) != 0 {
		t.Error("Expected", data, "got", plain)
	}
}
