package cryptanalysis

import (
	"bytes"
	"testing"
)

type xorbyte struct {
	b1     byte
	b2     byte
	result byte
}

type xorarray struct {
	a1     []byte
	a2     []byte
	result []byte
}

type xorarraybyte struct {
	a1     []byte
	b1     byte
	result []byte
}

func TestXorBytes(t *testing.T) {
	var tests = []xorbyte{
		{0, 0, 0},
		{0, 255, 255},
		{128, 128, 0},
	}

	for _, test := range tests {
		xor := XorBytes(test.b1, test.b2)
		if xor != test.result {
			t.Error("Expected", test.result, "got", xor)
		}
	}
}

func TestXorArrayByte(t *testing.T) {
	var tests = []xorarraybyte{
		{[]byte{0, 0, 0}, 0, []byte{0, 0, 0}},
		{[]byte{0, 0, 0}, 255, []byte{255, 255, 255}},
		{[]byte{128, 128, 128}, 128, []byte{0, 0, 0}},
	}

	for _, test := range tests {
		xor := XorArrayByte(test.a1, test.b1)
		if bytes.Compare(xor, test.result) != 0 {
			t.Error("Expected", test.result, "got", xor)
		}
	}
}

func TestXorArrays(t *testing.T) {
	var tests = []xorarray{
		{[]byte{0, 0, 0}, []byte{0, 0, 0}, []byte{0, 0, 0}},
		{[]byte{0, 0, 0}, []byte{255, 255, 255}, []byte{255, 255, 255}},
		{[]byte{128, 128, 128}, []byte{128, 128, 128}, []byte{0, 0, 0}},
		{[]byte{128, 128}, []byte{128}, []byte("Byte arrays have different lengths: 2, 1")},
	}

	for _, test := range tests {
		xor, err := XorArrays(test.a1, test.a2)

		if err != nil {
			result := []byte(err.Error())
			if bytes.Compare(result, test.result) != 0 {
				t.Error("Expected", test.result, "got", result)
			}
		} else {
			if bytes.Compare(xor, test.result) != 0 {
				t.Error("Expected", test.result, "got", xor)
			}
		}
	}
}
