package cryptanalysis

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

type AlphabetFrequency struct {
	Alphabet  string
	Frequency map[rune]float64
}

var ChiAlpha = AlphabetFrequency{
	Alphabet: "abcdefghijklmnopqrstuvwxyz",
	Frequency: map[rune]float64{
		'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
		'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
		'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
		'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
		'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
		'z': 0.00074},
}

var ChiAlphaSpace = AlphabetFrequency{
	Alphabet: "abcdefghijklmnopqrstuvwxyz ",
	Frequency: map[rune]float64{
		'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
		'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
		'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
		'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
		'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
		'z': 0.00074, ' ': 0.23200},
}

func ScoreAlphabet(data string, chi AlphabetFrequency) float64 {
	data = strings.ToLower(data)
	counts := make(map[rune]int)
	chi2 := 0.0
	total := 0

	// Get a count of all the letters and the total number of letters.
	for _, c := range data {
		if strings.Contains(chi.Alphabet, string(c)) {
			total = total + 1
			_, ok := counts[c]
			if ok {
				counts[c] = counts[c] + 1
			} else {
				counts[c] = 1
			}
		}
	}

	// Do not calculate the chi-squared value unless the string is at least 70%
	// ASCII alphabet.
	if total < int(float64(0.7)*float64(len(data))) {
		return 1000.0
	}

	// Calculate chi-squared for each letter
	for _, k := range chi.Alphabet {
		expected := float64(total) * chi.Frequency[k]
		actual := float64(counts[k])
		val := math.Pow(actual-expected, 2) / expected
		chi2 = chi2 + val
	}

	return chi2
}

func Hamming(s1, s2 []byte) (int, error) {
	total := 0

	if len(s1) != len(s2) {
		e := errors.New("Byte arrays are unequal. Cannot calculate Hamming distance.")
		return 0, e
	}

	for i, _ := range s1 {
		record := fmt.Sprintf("%08b", s1[i]^s2[i])
		for _, b := range record {
			if b == '1' {
				total = total + 1
			}
		}
	}

	return total, nil
}

func KeyLength(data []byte) (int, error) {
	normal := 1000
	size := 0

	for s := 2; s <= 40; s++ {
		padded := PadPkcs7(data, s)
		chunks := Chunk(padded, s)
		ham := 0

		if len(data)/s < 10 {
			break
		}

		for i := 0; i < 10; i++ {
			val, err := Hamming(chunks[i], chunks[i+1])

			if err != nil {
				return 0, err
			}

			ham = ham + val
		}

		ham = ham / s

		if ham < normal {
			normal = ham
			size = s
		}
	}

	return size, nil
}

func ScoreEcb(data []byte, block_size int) float64 {
	chunks := Chunk(data, block_size)
	temp := make(map[string]int)

	// Find all the unique strings.
	for _, c := range chunks {
		temp[string(c)] = 0
	}

	// Return the ratio of unique blocks to total blocks. The smaller the ratio
	// the more likely it is ECB.
	return float64(len(temp)) / float64(len(chunks))
}
