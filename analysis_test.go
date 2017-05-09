package cryptanalysis

import (
	//"bytes"
	"testing"
)

type ecbscore struct {
	data  []byte
	size  int
	score float64
}

func round(val float64) int {
	if val < 0 {
		return int(val - 0.5)
	}
	return int(val + 0.5)
}

func TestScoreEnglish(t *testing.T) {
	score := 33
	s := "THECAESARCIPHERISONEOFTHEEARLIESTKNOWNANDSIMPLESTCIPHERSITISATYPEOFSUBSTITUTIONCIPHERINWHICHEACHLETTERINTHEPLAINTEXTISSHIFTEDACERTAINNUMBEROFPLACESDOWNTHEALPHABET"

	eng_score := ScoreEnglish(s)

	if round(eng_score) != score {
		t.Error("Expected", score, "got", eng_score)
	}
}

func TestHamming(t *testing.T) {
	distance := 37
	s1 := []byte("this is a test")
	s2 := []byte("wokka wokka!!!")

	ham_dist, err := Hamming(s1, s2)

	if err != nil {
		t.Error(err)
	}

	if distance != ham_dist {
		t.Error("Expected", distance, "got", ham_dist)
	}

}

func TestKeyLength(t *testing.T) {
	encrypted := []byte{0x27, 0x0d, 0x10, 0x13, 0x42, 0x16, 0x02, 0x0d, 0x17,
		0x04, 0x42, 0x04, 0x0f, 0x06, 0x45, 0x12, 0x07, 0x13, 0x04, 0x0c, 0x45,
		0x18, 0x07, 0x04, 0x13, 0x11, 0x45, 0x00, 0x05, 0x0a, 0x41, 0x0d, 0x10,
		0x13, 0x42, 0x03, 0x0e, 0x10, 0x00, 0x07, 0x03, 0x11, 0x09, 0x07, 0x17,
		0x12, 0x42, 0x07, 0x13, 0x0d, 0x10, 0x06, 0x0a, 0x11, 0x41, 0x04, 0x0a,
		0x13, 0x16, 0x0d, 0x41, 0x16, 0x0a, 0x41, 0x16, 0x0d, 0x08, 0x11, 0x45,
		0x0d, 0x03, 0x0b, 0x05, 0x42, 0x04, 0x41, 0x0c, 0x00, 0x16, 0x42, 0x0b,
		0x00, 0x16, 0x0c, 0x0e, 0x0c, 0x4b}
	length := 3

	key_length, err := KeyLength(encrypted)

	if err != nil {
		t.Error(err)
	}

	if key_length != length {
		t.Error("Expected", length, "got", key_length)
	}

}

func TestScoreEcb(t *testing.T) {
	ecbscores := []ecbscore{
		{[]byte("abcdefghijklmnopqrst"), 5, 1.0},
		{[]byte("abcdabcdabcdabcdabcd"), 4, 0.2},
		{[]byte("abcdabcdabcdabcddcba"), 4, 0.8},
	}

	for _, test := range ecbscores {
		score := ScoreEcb(test.data, test.size)
		if score != test.score {
			t.Error("Expected", test.score, "got", score)
		}
	}
}
