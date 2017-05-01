package cryptanalysis

import(
)


func SingleByteXor(e string) (byte, string) {
    low := 1000.0
    msg := ""
    key := byte(0)

    // Bruteforce the key by XORing each possible key, analyzing the decrypted
    // message, and scoring it. Lowest score wins.
    for i:=0; i<256; i++ {
        k := byte(i)
        dec := SingleByte(encoding.DecodeHexStr(e), k)
        total := analysis.Score(strings.ToLower(dec))

        if total < low {
            low = total
            msg = string(dec)
            key = k
        }
    }

    return key, msg
}
