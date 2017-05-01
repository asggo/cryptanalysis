package cryptanalysis

import(
    "strings"
)


func BreakSingleByteXor(data []byte) (float64, byte, string) {
    low := 1000.0
    msg := ""
    key := byte(0)

    // Bruteforce the key by XORing each possible key, analyzing the decrypted
    // message, and scoring it. Lowest score wins.
    for i:=0; i<256; i++ {
        k := []byte{byte(i)}
        dec := XOR(data, k)
        str := strings.ToLower(string(dec))
        score := ScoreEnglish(str)

        if score < low {
            low = score
            msg = string(dec)
            key = k[0]
        }
    }

    return low, key, msg
}
