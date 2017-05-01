package cryptanalysis

import (
    "errors"
)


func ByteArrays(b1, b2 []byte) ([]byte, error) {
    var e error
    var result []byte

    if len(b1) != len(b2) {
        e = errors.New("Cannot join byte arrays of two different lengths.")
        return nil, e
    }

    result = make([]byte, len(b1))

    for i, _ := range b1 {
        result[i] = b1[i] ^ b2[i]
    }

    return result, nil
}


func SingleByte(b1 []byte, b2 byte) []byte {
    result := make([]byte, len(b1))

    for i, _ := range b1 {
        result[i] = b1[i] ^ b2
    }

    return result
}
