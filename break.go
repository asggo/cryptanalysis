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

func BreakCaesarShift(cipher string, chi AlphabetFrequency) (float64, int, string) {
	score := 1000.0
	plain := ""
	shift := 0

	// Bruteforce the shift by rotating the string by each possible value,
	// analyzing the rotated string, and scoring it. Lowest score wins.
	for i := 1; i < 26; i++ {
		p := CaesarShift(cipher, i)
		s := ScoreAlphabet(p, chi)

		if s < score {
			score = s
			plain = p
			shift = i
		}
	}

	return score, shift, plain
}
