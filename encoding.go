package cryptanalysis


import (
	"encoding/base64"
	"encoding/hex"
)


func DecodeB64Str(data string) []byte {
    b64, err := base64.StdEncoding.DecodeString(data)

    if err != nil {
        panic("Could not decode base64 string.")
    }

    return b64
}


func EncodeB64Str(data []byte) string {
    return base64.StdEncoding.EncodeToString(data)
}


func DecodeHexStr(data string) []byte {
    h, err := hex.DecodeString(data)

    if err != nil {
        panic("Could not decode hex string.")
    }

    return h
}


func EncodeHexStr(data []byte) string {
    return hex.EncodeToString(data)
}
