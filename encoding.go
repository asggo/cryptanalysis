package cryptanalysis


import (
	"encoding/base64"
	"encoding/hex"
)


func DecodeB64Str(data string) ([]byte, error) {
    return base64.StdEncoding.DecodeString(data)
}


func EncodeB64Str(data []byte) string {
    return base64.StdEncoding.EncodeToString(data)
}


func DecodeHexStr(data string) ([]byte, error) {
    return hex.DecodeString(data)
}


func EncodeHexStr(data []byte) string {
    return hex.EncodeToString(data)
}
