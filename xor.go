package cryptanalysis

import (
    "fmt"
    "errors"
)

func XorBytes(b1, b2 byte) byte {
	return b1 ^ b2
}

func XorArrayByte(b1 []byte, b2 byte) []byte {
	result := make([]byte, len(b1))

	for i, _ := range b1 {
		result[i] = b1[i] ^ b2
	}

	return result
}

func XorArrays(b1, b2 []byte) ([]byte, error) {
	result := make([]byte, len(b1))

	if len(b1) != len(b2) {
		e := fmt.Sprintf("Byte arrays have different lengths: %d, %d", len(b1), len(b2))
        return result, errors.New(e)
	}

	for i, _ := range b1 {
		result[i] = b1[i] ^ b2[i]
	}

	return result, nil
}
