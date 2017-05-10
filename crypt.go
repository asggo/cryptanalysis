package cryptanalysis

import (
    "errors"
    "crypto/aes"
)


const block_size = 16


func EncryptXor(plain, key []byte) []byte {
	var cipher []byte

	for i := 0; i < len(plain); i++ {
		e := plain[i] ^ key[i%len(key)]
		cipher = append(cipher, e)
	}

	return cipher
}


func EncryptEcb(plaintext, key []byte) ([]byte, error) {
    ciphertext := make([]byte, 0)
    plaintext = PadPkcs7(plaintext, block_size)
    chunks := Chunk(plaintext, block_size)

    ecb, err := aes.NewCipher(key)
    if err != nil {
        return ciphertext, err
    }

    for _, chunk := range chunks {
        temp := make([]byte, block_size)

        ecb.Encrypt(temp, chunk)

        ciphertext = append(ciphertext, temp...)
    }

    return ciphertext, nil
}


func DecryptEcb(ciphertext, key []byte) ([]byte, error) {
    plaintext := make([]byte, 0)

    if len(ciphertext) % block_size != 0 {
        return plaintext, errors.New("Ciphertext is not padded properly.")
    }

    chunks := Chunk(ciphertext, block_size)
    ecb, err := aes.NewCipher(key)
    if err != nil {
        return plaintext, err
    }

    for _, chunk := range chunks {
        temp := make([]byte, block_size)

        ecb.Decrypt(temp, chunk)

        plaintext = append(plaintext, temp...)
    }

    return plaintext, nil
}


func EncryptCbc(plaintext, key, iv []byte) ([]byte, error) {
    ciphertext := make([]byte, 0)
    chunks := Chunk(plaintext, block_size)

    if len(iv) != block_size {
        return ciphertext, errors.New("IV must be 16 bytes long.")
    }

    cbc, err := aes.NewCipher(key)
    if err != nil {
        return ciphertext, err
    }

    for _, chunk := range chunks {
        chunk = PadPkcs7(chunk, block_size)
        temp := make([]byte, block_size)

        chunk = XorArrays(chunk, iv)
        iv = chunk
        cbc.Encrypt(temp, chunk)

        ciphertext = append(ciphertext, temp...)
    }

    return ciphertext, nil
}


func DecryptCbc(ciphertext, key, iv []byte) ([]byte, error) {
    plaintext := make([]byte, 0)

    if len(iv) != block_size {
        return plaintext, errors.New("IV must be 16 bytes long.")
    }

    cbc, err := aes.NewCipher(key)
    if err != nil {
        return plaintext, err
    }

    chunks := Chunk(ciphertext, block_size)
    for _, chunk := range chunks {
        temp := make([]byte, block_size)

        cbc.Decrypt(temp, chunk)
        temp = XorArrays(temp, iv)
        iv = chunk

        plaintext = append(plaintext, temp...)
    }

    return plaintext, nil
}
