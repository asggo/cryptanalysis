package cryptanalysis

import (
    "bytes"
    "testing"
)

func TestEncryptXor(t *testing.T) {
    key := []byte("ABC")
    data := []byte("TESTDATA")
    cipher := EncryptXor(data, key)
    res := []byte{21, 7, 16, 21, 6, 2, 21, 3}

    if bytes.Compare(cipher, res) != 0 {
        t.Error("Expected", res, "got", cipher)
    }
}
