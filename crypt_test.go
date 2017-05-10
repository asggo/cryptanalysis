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


func TestEncryptEcb(t *testing.T) {
    key := []byte("YELLOW SUBMARINE")
    plain := []byte("This is a test of ECB.")
    expected := []byte{0xf6, 0xd6, 0xbb, 0xa9, 0xf4, 0x88, 0xc9, 0xe2, 0xbd,
        0xa5, 0x04, 0x27, 0x38, 0x28, 0x11, 0x2f, 0x8e, 0x81, 0x4d, 0xd8, 0xee,
        0xe7, 0xf3, 0x2c, 0x74, 0x9c, 0x7b, 0x62, 0xad, 0xfb, 0x19, 0xe4}

    cipher, err := EncryptEcb(plain, key)

    if err != nil {
        t.Error(err)
    }

    if bytes.Compare(cipher, expected) != 0 {
        t.Error("Expected", expected, "got", cipher)
    }
}


func TestDecryptEcb(t *testing.T) {
    key := []byte("YELLOW SUBMARINE")
    cipher := []byte{0xf6, 0xd6, 0xbb, 0xa9, 0xf4, 0x88, 0xc9, 0xe2, 0xbd,
        0xa5, 0x04, 0x27, 0x38, 0x28, 0x11, 0x2f, 0x8e, 0x81, 0x4d, 0xd8, 0xee,
        0xe7, 0xf3, 0x2c, 0x74, 0x9c, 0x7b, 0x62, 0xad, 0xfb, 0x19, 0xe4}
    expected := []byte("This is a test of ECB.\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a")

    plain, err := DecryptEcb(cipher, key)

    if err != nil {
        t.Error(err)
    }

    if bytes.Compare(plain, expected) != 0 {
        t.Error("Expected", expected, "got", plain)
    }
}


// func TestEncryptCbc(t *testing.T) {
//     key := []byte("YELLOW SUBMARINE")
//     plain := []byte("This is a test of CBC.")
//     expected := []byte{0xf6, 0xd6, 0xbb, 0xa9, 0xf4, 0x88, 0xc9, 0xe2, 0xbd,
//         0xa5, 0x04, 0x27, 0x38, 0x28, 0x11, 0x2f, 0x8e, 0x81, 0x4d, 0xd8, 0xee,
//         0xe7, 0xf3, 0x2c, 0x74, 0x9c, 0x7b, 0x62, 0xad, 0xfb, 0x19, 0xe4}
//
//     cipher, err := EncryptCbc(plain, key)
//
//     if err != nil {
//         t.Error(err)
//     }
//
//     if bytes.Compare(cipher, expected) != 0 {
//         t.Error("Expected", expected, "got", cipher)
//     }
// }
//
//
// func TestDecryptCbc(t *testing.T) {
//     key := []byte("YELLOW SUBMARINE")
//     cipher := []byte{0xf6, 0xd6, 0xbb, 0xa9, 0xf4, 0x88, 0xc9, 0xe2, 0xbd,
//         0xa5, 0x04, 0x27, 0x38, 0x28, 0x11, 0x2f, 0x8e, 0x81, 0x4d, 0xd8, 0xee,
//         0xe7, 0xf3, 0x2c, 0x74, 0x9c, 0x7b, 0x62, 0xad, 0xfb, 0x19, 0xe4}
//     expected := []byte("This is a test of CBC.\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a")
//
//     plain, err := DecryptCbc(cipher, key)
//
//     if err != nil {
//         t.Error(err)
//     }
//
//     if bytes.Compare(plain, expected) != 0 {
//         t.Error("Expected", expected, "got", plain)
//     }
// }
