package cryptanalysis

import ()

func BreakSingleByteXor(data []byte, chi AlphabetFrequency) (float64, byte, string) {
	low := 1000.0
	msg := ""
	key := byte(0)

	// Bruteforce the key by XORing each possible key, analyzing the decrypted
	// message, and scoring it. Lowest score wins.
	for i := 0; i < 256; i++ {
		k := byte(i)
		dec := XorArrayByte(data, k)
		score := ScoreAlphabet(string(dec), chi)

		if score < low {
			low = score
			msg = string(dec)
			key = k
		}
	}

	return low, key, msg
}
