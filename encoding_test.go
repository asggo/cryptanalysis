package cryptanalysis

import (
	"bytes"
	"testing"
)

type encoding struct {
	encoded string
	decoded []byte
}

var b64tests = []encoding{
	{"YWRtaW4=", []byte("admin")},
	{"cGFzc3dvcmQ=", []byte("password")},
	{"AAECAwQF", []byte{0, 1, 2, 3, 4, 5}},
}

var hextests = []encoding{
	{"61646d696e", []byte("admin")},
	{"70617373776f7264", []byte("password")},
	{"000102030405", []byte{0, 1, 2, 3, 4, 5}},
}

func TestDecodeB64Str(t *testing.T) {
	for _, test := range b64tests {
		decoded := DecodeB64Str(test.encoded)
		if bytes.Compare(decoded, test.decoded) != 0 {
			t.Error("Expected", test.decoded, "got", decoded)
		}
	}
}

func TestEncodeB64Str(t *testing.T) {
	for _, test := range b64tests {
		encoded := EncodeB64Str(test.decoded)
		if encoded != test.encoded {
			t.Error("Expected", test.encoded, "got", encoded)
		}
	}
}

func TestDecodeHexStr(t *testing.T) {
	for _, test := range hextests {
		decoded := DecodeHexStr(test.encoded)
		if bytes.Compare(decoded, test.decoded) != 0 {
			t.Error("Expected", test.decoded, "got", decoded)
		}
	}
}

func TestEncodeHexStr(t *testing.T) {
	for _, test := range hextests {
		encoded := EncodeHexStr(test.decoded)
		if encoded != test.encoded {
			t.Error("Expected", test.encoded, "got", encoded)
		}
	}
}
