package cryptanalysis

import (
)


func XOR(b1, b2 []byte) []byte {
    result := make([]byte, len(b1))

    if len(b2) == 1 {
        // b2 is a single byte. XOR each byte of b1 with the byte in b2.
        for i, _ := range b1 {
            result[i] = b1[i] ^ b2[0]
        }
    } else {
        // b2 is not a single byte. XOR each byte of b1 with each byte of b2.
        if len(b1) != len(b2) {
            panic("Cannot join byte arrays of two different lengths.")
        }

        for i, _ := range b1 {
            result[i] = b1[i] ^ b2[i]
        }
    }

    return result
}
