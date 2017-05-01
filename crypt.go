package cryptanalysis

import (
)

func EncryptXor(plain, key []byte) []byte {
    var cipher []byte

    for i:=0; i<len(plain); i++ {
        e := plain[i] ^ key[i%len(key)]
        cipher = append(cipher, e)
    }

    return cipher
}
